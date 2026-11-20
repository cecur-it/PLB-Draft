#!/usr/bin/env node
/**
 * scripts/pin-model-digests.mjs — pins the SHA-256 of every approved model's
 * weight blob into ollama/models.json (replacing the "<pinned-per-release>"
 * sentinel). Adapted from CS3 scripts/pin-model-digests.mjs.
 *
 * Traces: PROMPT §1 Tier 4 (approved models, air-gap integrity),
 *         CONTRACT §0 (sentinel rule) and §10 (models.json format).
 *
 * Digest sources (exactly one; default is the Ollama registry):
 *   --digests <file.json>   JSON object {"<model id>": "<sha256>"}
 *   --from-bundle <dir>     air-gap bundle dir: digests.json ({id: sha256}) and/or
 *                           <id with ":" -> "_">.gguf blobs. Blobs are hashed; when both
 *                           digests.json and a blob exist they must agree.
 *   --registry <url>        resolve model-layer digests from the registry manifests
 *                           (connected staging host only; default https://registry.ollama.ai).
 *                           Hub-qualified ids (hf.co/<owner>/<repo>:<quant>) are always resolved
 *                           from their own host, since they do not live in the Ollama library.
 *
 * Usage:
 *   node scripts/pin-model-digests.mjs [source] [--models-json <path>] [--release-tag vX.Y.Z]
 *                                      [--updated YYYY-MM-DD] [--partial] [--check]
 *
 *   --check     never writes. Fails (exit 1) when any model is still unpinned or, when a
 *               source is given, when models.json drifts from that source.
 *   --partial   allow a source that covers only a subset of the approved models.
 *   --updated   value for the "updated" field; also taken from SOURCE_DATE_EPOCH.
 *               Without either, "updated" is left untouched so output is reproducible.
 *
 * Exit codes: 0 ok, 1 --check failed, 2 usage error, 3 digest source error,
 * 4 models.json unreadable or not valid JSON.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_MODELS_JSON = path.join(__dirname, '..', 'ollama', 'models.json');
const DEFAULT_REGISTRY = 'https://registry.ollama.ai';
const MODEL_LAYER = 'application/vnd.ollama.image.model';
export const SENTINEL = '<pinned-per-release>';

class UsageError extends Error {}
class SourceError extends Error {}
class RegistryFileError extends Error {}

export function isPinned(sha256) {
  return typeof sha256 === 'string' && /^[a-f0-9]{64}$/i.test(sha256);
}

export function normalizeDigest(value) {
  const match = typeof value === 'string' ? value.trim().match(/^(?:sha256:)?([a-f0-9]{64})$/i) : null;
  return match ? match[1].toLowerCase() : null;
}

export function safeId(modelId) {
  return modelId.replace(/[:/]/g, '_');
}

export function modelLayerDigest(manifest) {
  const layer = (manifest.layers || []).find((l) => l.mediaType === MODEL_LAYER);
  return normalizeDigest(layer?.digest);
}

/** Deterministic serializer: 2-space indent, arrays of primitives stay inline, trailing newline. */
export function canonicalStringify(value, depth = 0) {
  const pad = '  '.repeat(depth + 1);
  const end = '  '.repeat(depth);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    if (value.every((v) => v === null || typeof v !== 'object')) {
      return `[${value.map((v) => JSON.stringify(v)).join(', ')}]`;
    }
    return `[\n${value.map((v) => pad + canonicalStringify(v, depth + 1)).join(',\n')}\n${end}]`;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return '{}';
    return `{\n${keys.map((k) => `${pad}${JSON.stringify(k)}: ${canonicalStringify(value[k], depth + 1)}`).join(',\n')}\n${end}}`;
  }
  return JSON.stringify(value);
}

export function serializeRegistry(registry) {
  return `${canonicalStringify(registry)}\n`;
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    fs.createReadStream(filePath)
      .on('error', reject)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')));
  });
}

function parseDigestMap(raw, origin) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new SourceError(`${origin} is not valid JSON: ${err.message}`);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SourceError(`${origin} must be a JSON object of {model id: sha256}`);
  }
  const out = {};
  for (const [id, value] of Object.entries(parsed)) {
    const digest = normalizeDigest(value);
    if (!digest) throw new SourceError(`${origin}: digest for ${id} is not 64 hex characters`);
    out[id] = digest;
  }
  return out;
}

export function readDigestsFile(file) {
  if (!fs.existsSync(file)) throw new SourceError(`digests file not found: ${file}`);
  return parseDigestMap(fs.readFileSync(file, 'utf8'), file);
}

export async function readBundleDigests(dir, modelIds) {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    throw new SourceError(`bundle directory not found: ${dir}`);
  }
  const listed = fs.existsSync(path.join(dir, 'digests.json'))
    ? parseDigestMap(fs.readFileSync(path.join(dir, 'digests.json'), 'utf8'), path.join(dir, 'digests.json'))
    : {};
  const out = { ...listed };
  for (const id of modelIds) {
    const blob = path.join(dir, `${safeId(id)}.gguf`);
    if (!fs.existsSync(blob)) continue;
    const actual = await sha256File(blob);
    if (listed[id] && listed[id] !== actual) {
      throw new SourceError(`${id}: digests.json says ${listed[id]} but ${path.basename(blob)} hashes to ${actual}`);
    }
    out[id] = actual;
  }
  return out;
}

/** Splits an id into { base, repoPath, tag }: Hub ids carry their own registry host. */
export function splitModelId(registryUrl, modelId) {
  const lastColon = modelId.lastIndexOf(':');
  const lastSlash = modelId.lastIndexOf('/');
  const tagged = lastColon > lastSlash;
  const name = tagged ? modelId.slice(0, lastColon) : modelId;
  const tag = tagged ? modelId.slice(lastColon + 1) : 'latest';
  const firstSlash = name.indexOf('/');
  if (firstSlash < 0) return { base: registryUrl, repoPath: `library/${encodeURIComponent(name)}`, tag };
  const repoPath = name.slice(firstSlash + 1).split('/').map(encodeURIComponent).join('/');
  return { base: `https://${name.slice(0, firstSlash)}`, repoPath, tag };
}

export async function fetchRegistryDigest(registryUrl, modelId, fetchImpl = globalThis.fetch) {
  const { base, repoPath, tag } = splitModelId(registryUrl, modelId);
  const url = `${base}/v2/${repoPath}/manifests/${encodeURIComponent(tag)}`;
  const res = await fetchImpl(url, { headers: { Accept: 'application/vnd.docker.distribution.manifest.v2+json' } });
  if (!res.ok) throw new SourceError(`${url} -> HTTP ${res.status}`);
  const digest = modelLayerDigest(await res.json());
  if (!digest) throw new SourceError(`no ${MODEL_LAYER} layer found in the manifest for ${modelId}`);
  return digest;
}

/** Returns a new registry object with digests applied; throws SourceError on unknown ids or gaps. */
export function applyDigests(registry, digests, { partial = false } = {}) {
  const approved = new Set(registry.models.map((m) => m.id));
  const unknown = Object.keys(digests).filter((id) => !approved.has(id));
  if (unknown.length) throw new SourceError(`refusing digests for unapproved models: ${unknown.join(', ')}`);
  const missing = registry.models.map((m) => m.id).filter((id) => !(id in digests));
  if (missing.length && !partial) {
    throw new SourceError(`digest source has no entry for: ${missing.join(', ')} (use --partial to pin a subset)`);
  }
  return {
    ...registry,
    models: registry.models.map((m) => (m.id in digests ? { ...m, sha256: digests[m.id] } : m)),
  };
}

export function checkRegistry(registry, digests = null) {
  const problems = [];
  for (const m of registry.models) {
    if (!isPinned(m.sha256)) problems.push(`${m.id}: sha256 is ${m.sha256 === SENTINEL ? 'still the sentinel' : 'missing or malformed'}`);
    else if (digests && digests[m.id] && digests[m.id] !== m.sha256.toLowerCase()) {
      problems.push(`${m.id}: pinned ${m.sha256} differs from source ${digests[m.id]}`);
    }
  }
  return problems;
}

function parseArgs(argv, env) {
  const args = {
    modelsJson: DEFAULT_MODELS_JSON, digests: null, fromBundle: null, registry: null,
    releaseTag: null, updated: null, partial: false, check: false, help: false,
  };
  const take = (i, flag) => {
    if (i + 1 >= argv.length) throw new UsageError(`${flag} needs a value`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i += 1) {
    switch (argv[i]) {
      case '--models-json': args.modelsJson = take(i, argv[i]); i += 1; break;
      case '--digests': args.digests = take(i, argv[i]); i += 1; break;
      case '--from-bundle': args.fromBundle = take(i, argv[i]); i += 1; break;
      case '--registry': args.registry = take(i, argv[i]).replace(/\/+$/, ''); i += 1; break;
      case '--release-tag': args.releaseTag = take(i, argv[i]); i += 1; break;
      case '--updated': args.updated = take(i, argv[i]); i += 1; break;
      case '--partial': args.partial = true; break;
      case '--check': args.check = true; break;
      case '-h': case '--help': args.help = true; break;
      default: throw new UsageError(`unknown argument: ${argv[i]}`);
    }
  }
  if ([args.digests, args.fromBundle, args.registry].filter(Boolean).length > 1) {
    throw new UsageError('choose only one of --digests, --from-bundle, --registry');
  }
  if (args.releaseTag && !/^v\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(args.releaseTag)) {
    throw new UsageError(`--release-tag must look like v1.0.0, got ${args.releaseTag}`);
  }
  if (!args.updated && env.SOURCE_DATE_EPOCH) {
    if (!/^\d+$/.test(env.SOURCE_DATE_EPOCH)) throw new UsageError('SOURCE_DATE_EPOCH must be an integer');
    args.updated = new Date(Number(env.SOURCE_DATE_EPOCH) * 1000).toISOString().slice(0, 10);
  }
  if (args.updated && !/^\d{4}-\d{2}-\d{2}$/.test(args.updated)) throw new UsageError('--updated must be YYYY-MM-DD');
  return args;
}

const HELP_TEXT = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('*/')[0].replace(/^#!.*\n/, '')
  .replace(/^\/\*\*\n/, '').replace(/^ \* ?/gm, '');

/** Entry point with injectable IO so the node:test suite never touches the network or real files. */
export async function run(argv, io = {}) {
  const stdout = io.stdout || ((s) => process.stdout.write(s));
  const stderr = io.stderr || ((s) => process.stderr.write(s));
  const env = io.env || process.env;
  try {
    const args = parseArgs(argv, env);
    if (args.help) {
      stdout(HELP_TEXT);
      return 0;
    }
    let registry;
    try {
      registry = JSON.parse(fs.readFileSync(args.modelsJson, 'utf8'));
    } catch (err) {
      throw new RegistryFileError(`cannot read ${args.modelsJson}: ${err.message}`);
    }
    if (!Array.isArray(registry.models)) throw new RegistryFileError(`${args.modelsJson} has no models[] array`);
    const ids = registry.models.map((m) => m.id);

    let digests = null;
    let sourceLabel = '';
    if (args.digests) {
      digests = readDigestsFile(args.digests);
      sourceLabel = args.digests;
    } else if (args.fromBundle) {
      digests = await readBundleDigests(args.fromBundle, ids);
      sourceLabel = args.fromBundle;
    } else if (args.registry || !args.check) {
      const base = args.registry || DEFAULT_REGISTRY;
      digests = {};
      for (const id of ids) {
        // an approved id backed by a Hub tag is resolved from that tag's own repo (it is not in the library)
        const upstream = registry.models.find((m) => m.id === id)?.upstream;
        digests[id] = await fetchRegistryDigest(base, upstream || id, io.fetch);
      }
      sourceLabel = base;
    }

    if (args.check) {
      const problems = checkRegistry(registry, digests);
      if (problems.length) {
        problems.forEach((p) => stderr(`[FAIL] ${p}\n`));
        return 1;
      }
      stdout('[PASS] All models have pinned SHA-256 digests.\n');
      return 0;
    }

    const next = applyDigests(registry, digests, { partial: args.partial });
    if (args.releaseTag) next.releaseTag = args.releaseTag;
    if (args.updated) next.updated = args.updated;
    next.models.forEach((m) => stdout(`[pin-model-digests] ${m.id} -> ${m.sha256}\n`));

    const text = serializeRegistry(next);
    JSON.parse(text);
    if (fs.readFileSync(args.modelsJson, 'utf8') === text) {
      stdout(`[pin-model-digests] ${args.modelsJson} already up to date (source: ${sourceLabel}).\n`);
      return 0;
    }
    const staging = `${args.modelsJson}.tmp-${process.pid}`;
    fs.writeFileSync(staging, text);
    fs.renameSync(staging, args.modelsJson);
    stdout(`[pin-model-digests] Updated ${args.modelsJson} from ${sourceLabel}. Review and commit.\n`);
    return 0;
  } catch (err) {
    stderr(`[FAIL] ${err.message}\n`);
    if (err instanceof UsageError) return 2;
    if (err instanceof RegistryFileError) return 4;
    return 3;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
