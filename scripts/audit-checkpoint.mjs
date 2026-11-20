#!/usr/bin/env node
/**
 * scripts/audit-checkpoint.mjs — external, signed checkpoint of the audit ledger head.
 *
 * The hash chain in cs3.audit_logs is tamper-*evident* only against someone who cannot also
 * recompute it: a superuser can delete the newest rows (truncation) or rebuild the whole chain,
 * and cs3.verify_audit_chain() will still report it intact because the first retained row's
 * prev_hash is trusted. Anchoring the head outside the database, signed with a key the database
 * never sees, is what turns that into a detectable event.
 *
 * Run from a location the database cannot write to (CI job, backup host, operator workstation):
 *
 *   node scripts/audit-checkpoint.mjs --keygen                       # once per environment
 *   node scripts/audit-checkpoint.mjs                                # append a checkpoint
 *   node scripts/audit-checkpoint.mjs --verify                       # check chain of custody
 *
 * The private key lives beside the checkpoints (secrets/audit/ by default); commit or ship the
 * .pub file and the JSONL file off-host so both survive a host rebuild.
 *
 * Usage:
 *   node scripts/audit-checkpoint.mjs --append [--key GENKEY] [--out FILE] [--dsn DSN] [--head N:HASH]
 *   node scripts/audit-checkpoint.mjs --verify [--out FILE] [--dsn DSN] [--head N:HASH]
 *   node scripts/audit-checkpoint.mjs --keygen [--key GENKEY]
 *
 *   --append     Append a checkpoint for the current ledger head (the default when no mode is given).
 *   --keygen     Create the Ed25519 key pair (private key is never overwritten).
 *   --verify     Verify every signature, the monotonic chain_no sequence, and (when a live head
 *                is available) that no checkpointed row has since been altered or truncated.
 *   --head       Anchor against an explicitly supplied head "<chain_no>:<chain_hash>" instead of
 *                querying PostgreSQL. Required when psql or DSN is unavailable.
 *   --dsn        PostgreSQL connection string; defaults to $CS3_AUDIT_DSN or $DATABASE_URL.
 *   --json       Machine-readable output on stdout. Exit 0 = intact, 1 = broken/tampered.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const DEFAULT_KEY = path.join(ROOT, 'secrets', 'audit', 'checkpoint-ed25519.pem');
const DEFAULT_OUT = path.join(ROOT, 'secrets', 'audit', 'checkpoints.jsonl');

export const CHECKPOINT_VERSION = 1;

function parseArgs(argv) {
  const args = { key: DEFAULT_KEY, out: DEFAULT_OUT, dsn: null, head: null, keygen: false, append: false, verify: false, json: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--key') args.key = argv[++i];
    else if (arg === '--out') args.out = argv[++i];
    else if (arg === '--dsn') args.dsn = argv[++i];
    else if (arg === '--head') args.head = argv[++i];
    else if (arg === '--keygen') args.keygen = true;
    else if (arg === '--append') args.append = true; // default mode; accepted for readability
    else if (arg === '--verify') args.verify = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--help' || arg === '-h') args.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

export function usage() {
  const header = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n');
  const end = header.findIndex((line) => line.trim() === '*/');
  return header
    .slice(2, end)
    .map((line) => line.replace(/^ ?\*\/? ?/, ''))
    .join('\n')
    .trim();
}

/** Stable key order, so a signature is reproducible from the parsed object. */
export function canonical(payload) {
  const ordered = {};
  for (const key of Object.keys(payload).sort()) ordered[key] = payload[key];
  return JSON.stringify(ordered);
}

export function signPayload(privateKeyPem, payload) {
  return cryptoSign(null, Buffer.from(canonical(payload)), createPrivateKey(privateKeyPem)).toString('base64');
}

export function verifyPayload(publicKeyPem, payload, signature) {
  try {
    return cryptoVerify(null, Buffer.from(canonical(payload)), createPublicKey(publicKeyPem), Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

/** Parses "<chain_no>:<chain_hash>"; the hash must look like a chain digest. */
export function parseHead(spec) {
  const match = /^(\d+):(sha256-[a-z0-9]+|genesis-root-000000000000)$/.exec(String(spec || '').trim());
  if (!match) throw new Error(`--head must be "<chain_no>:<chain_hash>", got '${spec}'`);
  return { chainNo: Number(match[1]), chainHash: match[2] };
}

/**
 * Reads the live ledger head through psql. Deliberately read-only and role-agnostic: cs3_app and
 * cs3_archiver both hold SELECT on cs3.audit_logs.
 */
export function readLiveHead(dsn) {
  if (!dsn) throw new Error('No DSN: pass --dsn, --head, or set CS3_AUDIT_DSN / DATABASE_URL');
  const out = execFileSync(
    'psql',
    [dsn, '-At', '-F', ':', '-c', 'select chain_no, chain_hash from cs3.audit_logs order by chain_no desc limit 1'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
  ).trim();
  if (!out) return { chainNo: 0, chainHash: 'genesis-root-000000000000' };
  const [chainNo, chainHash] = out.split(':');
  return { chainNo: Number(chainNo), chainHash };
}

/** Signature payload of a checkpoint: everything except sig and the embedded public key. */
export function payloadOf(checkpoint) {
  const { sig, pubkey, ...payload } = checkpoint;
  return payload;
}

export function readCheckpoints(file) {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`${file}: line ${index + 1} is not valid JSON`);
      }
    });
}

export function appendCheckpoint(file, record) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.appendFileSync(file, `${JSON.stringify(record)}\n`, { mode: 0o600 });
}

/**
 * Verifies the whole checkpoint file against the pinned public key, the monotonic chain_no order,
 * and — when a live head row is supplied — that the anchored rows still exist unmodified and that
 * the ledger has not been truncated below the newest checkpoint.
 */
export function verifyCheckpoints(checkpoints, publicKeyPem, { liveRow = null, liveHead = null } = {}) {
  const problems = [];
  let previousNo = -1;

  for (const [index, checkpoint] of checkpoints.entries()) {
    const where = `checkpoint ${index + 1}`;
    if (checkpoint.v !== CHECKPOINT_VERSION) problems.push(`${where}: unknown version ${checkpoint.v}`);
    if (!verifyPayload(checkpoint.pubkey, payloadOf(checkpoint), checkpoint.sig)) {
      problems.push(`${where}: signature does not verify against its embedded key`);
    }
    if (publicKeyPem && !verifyPayload(publicKeyPem, payloadOf(checkpoint), checkpoint.sig)) {
      problems.push(`${where}: signature does not verify against the pinned public key`);
    }
    if (!(checkpoint.chainNo > previousNo)) {
      problems.push(`${where}: chain_no ${checkpoint.chainNo} does not advance past ${previousNo} (rollback)`);
    }
    previousNo = checkpoint.chainNo;
  }

  if (checkpoints.length > 0) {
    const newest = checkpoints[checkpoints.length - 1];
    if (liveHead && newest.chainNo > liveHead.chainNo) {
      problems.push(`ledger truncated: newest checkpoint is chain_no ${newest.chainNo} but the live head is ${liveHead.chainNo}`);
    }
    if (liveRow && newest.chainNo === liveRow.chainNo && newest.chainHash !== liveRow.chainHash) {
      problems.push(`anchored row rewritten: chain_no ${liveRow.chainNo} is now ${liveRow.chainHash}, checkpoint says ${newest.chainHash}`);
    }
  }

  return { ok: problems.length === 0, problems, checkpoints: checkpoints.length, head: checkpoints.at(-1)?.chainNo ?? null };
}

function ensureKeyPair(keyPath) {
  const pubPath = `${keyPath}.pub`;
  if (fs.existsSync(keyPath)) return pubPath;
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  return pubPath;
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return 0;
  }

  const say = (obj, text) => (args.json ? console.log(JSON.stringify(obj, null, 2)) : console.log(text));

  if (args.keygen) {
    const existed = fs.existsSync(args.key);
    const pubPath = ensureKeyPair(args.key);
    say({ key: args.key, publicKey: pubPath, created: !existed }, existed ? `Key pair already present: ${args.key}` : `Created ${args.key} (0600) and ${pubPath}`);
    return 0;
  }

  const pubPath = `${args.key}.pub`;
  const pinnedPub = fs.existsSync(pubPath) ? fs.readFileSync(pubPath, 'utf8') : null;

  if (args.verify) {
    const checkpoints = readCheckpoints(args.out);
    let liveHead = null;
    let liveRow = null;
    try {
      liveHead = args.head ? parseHead(args.head) : readLiveHead(args.dsn || process.env.CS3_AUDIT_DSN || process.env.DATABASE_URL);
      // Only the newest anchored row matters: it is the one a rewrite would have to fake.
      const newest = checkpoints.at(-1);
      if (newest && liveHead && liveHead.chainNo === newest.chainNo) liveRow = liveHead;
    } catch (err) {
      if (!args.head) console.error(`[audit-checkpoint] head unavailable: ${err.message}`);
    }
    const result = verifyCheckpoints(checkpoints, pinnedPub, { liveHead, liveRow });
    say(result, result.ok ? `OK: ${result.checkpoints} checkpoint(s), head chain_no=${result.head}` : `FAILED\n  ${result.problems.join('\n  ')}`);
    return result.ok ? 0 : 1;
  }

  if (!fs.existsSync(args.key)) {
    throw new Error(`Missing private key ${args.key}; run with --keygen first`);
  }
  const head = args.head ? parseHead(args.head) : readLiveHead(args.dsn || process.env.CS3_AUDIT_DSN || process.env.DATABASE_URL);
  const existing = readCheckpoints(args.out);
  const previous = existing.at(-1);
  if (previous && head.chainNo < previous.chainNo) {
    throw new Error(`Refusing to anchor behind the newest checkpoint (${head.chainNo} < ${previous.chainNo}); the ledger was truncated`);
  }

  const payload = {
    v: CHECKPOINT_VERSION,
    chainNo: head.chainNo,
    chainHash: head.chainHash,
    takenAt: new Date().toISOString(),
    host: process.env.HOSTNAME || 'unknown',
    ledger: 'cs3.audit_logs',
  };
  const privateKeyPem = fs.readFileSync(args.key, 'utf8');
  const record = { ...payload, pubkey: createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'pem' }) };
  appendCheckpoint(args.out, { ...record, sig: signPayload(privateKeyPem, payload) });
  say({ ...payload, out: args.out }, `Anchored chain_no=${head.chainNo} ${head.chainHash.slice(0, 23)}… to ${args.out}`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    console.error(`[audit-checkpoint] ${err.message}`);
    process.exitCode = 1;
  }
}
