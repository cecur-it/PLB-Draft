#!/usr/bin/env node
/**
 * scripts/audit-checkpoint.test.mjs — unit tests for the signed-checkpoint logic that makes audit
 * ledger truncation and rewrite detectable. Everything here runs offline against a temp key pair;
 * the PostgreSQL read is the only part not exercised.
 *
 * Run with:
 *   node --test scripts/audit-checkpoint.test.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  CHECKPOINT_VERSION,
  appendCheckpoint,
  canonical,
  parseHead,
  payloadOf,
  readCheckpoints,
  signPayload,
  verifyCheckpoints,
  verifyPayload,
} from './audit-checkpoint.mjs';

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    pub: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function publicOf(priv) {
  return createPublicKey(priv).export({ type: 'spki', format: 'pem' });
}

function checkpoint(priv, chainNo, chainHash = `sha256-${String(chainNo).padStart(64, '0')}`) {
  const payload = { v: CHECKPOINT_VERSION, chainNo, chainHash, takenAt: '2026-01-01T00:00:00.000Z', ledger: 'cs3.audit_logs' };
  return { ...payload, pubkey: publicOf(priv), sig: signPayload(priv, payload) };
}

test('canonical() is key-order independent', () => {
  assert.equal(canonical({ b: 1, a: 2 }), canonical({ a: 2, b: 1 }));
});

test('a signature verifies with the right key and fails with another', () => {
  const { priv, pub } = keyPair();
  const other = keyPair();
  const payload = { v: 1, chainNo: 4 };
  const sig = signPayload(priv, payload);
  assert.equal(verifyPayload(pub, payload, sig), true);
  assert.equal(verifyPayload(other.pub, payload, sig), false);
  assert.equal(verifyPayload(pub, { v: 1, chainNo: 5 }, sig), false);
});

test('tampered payload and malformed signature are rejected, not thrown', () => {
  const { priv, pub } = keyPair();
  const record = checkpoint(priv, 3);
  assert.equal(verifyPayload(pub, payloadOf({ ...record, chainNo: 4 }), record.sig), false);
  assert.equal(verifyPayload(pub, payloadOf(record), 'not-base64!!'), false);
});

test('an intact ascending file verifies', () => {
  const { priv, pub } = keyPair();
  const result = verifyCheckpoints([checkpoint(priv, 1), checkpoint(priv, 2)], pub);
  assert.deepEqual(result.problems, []);
  assert.equal(result.ok, true);
});

test('rollback (chain_no not advancing) is reported', () => {
  const { priv, pub } = keyPair();
  const result = verifyCheckpoints([checkpoint(priv, 9), checkpoint(priv, 4)], pub);
  assert.equal(result.ok, false);
  assert.match(result.problems.join('\n'), /does not advance/);
});

test('truncation below the newest checkpoint is reported', () => {
  const { priv, pub } = keyPair();
  const newest = checkpoint(priv, 10);
  const result = verifyCheckpoints([newest], pub, { liveHead: { chainNo: 7, chainHash: 'sha256-x' } });
  assert.match(result.problems.join('\n'), /truncated/);
});

test('a rewritten anchored row is reported', () => {
  const { priv, pub } = keyPair();
  const record = checkpoint(priv, 5);
  const result = verifyCheckpoints([record], pub, {
    liveHead: { chainNo: 5, chainHash: `sha256-${'f'.repeat(64)}` },
    liveRow: { chainNo: 5, chainHash: `sha256-${'f'.repeat(64)}` },
  });
  assert.match(result.problems.join('\n'), /rewritten/);
});

test('a rotated key is caught by the pinned public key even though the file self-verifies', () => {
  const pinned = keyPair();
  const attacker = keyPair();
  const forged = checkpoint(attacker.priv, 2);
  assert.equal(verifyCheckpoints([forged], null).ok, true, 'embedded key alone accepts it');
  const result = verifyCheckpoints([forged], pinned.pub);
  assert.match(result.problems.join('\n'), /pinned public key/);
});

test('parseHead() validates the chain_no/hash shape', () => {
  assert.deepEqual(parseHead('12:sha256-abc'), { chainNo: 12, chainHash: 'sha256-abc' });
  assert.equal(parseHead(' 7:genesis-root-000000000000 ').chainNo, 7);
  assert.throws(() => parseHead('nope'), /--head must be/);
  assert.throws(() => parseHead('7'), /--head must be/);
});

test('appendCheckpoint() writes newline-delimited JSON that reads back', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs3-ckpt-'));
  const file = path.join(dir, 'nested', 'checkpoints.jsonl');
  const { priv } = keyPair();
  try {
    appendCheckpoint(file, checkpoint(priv, 1));
    appendCheckpoint(file, checkpoint(priv, 2));
    const parsed = readCheckpoints(file);
    assert.equal(parsed.length, 2);
    assert.equal(parsed[1].chainNo, 2);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(readCheckpoints(path.join(dir, 'missing.jsonl')), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
