#!/usr/bin/env node
/**
 * pin-model-digests.test.mjs — node:test suite for scripts/pin-model-digests.mjs.
 * No network, no real registry: digests come from temp files / an injected fetch.
 *
 * Traces: CONTRACT §0 / §10 (sentinel pinning, deterministic models.json rewrite).
 * Run:    node --test ollama/tests/
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyDigests, canonicalStringify, checkRegistry, fetchRegistryDigest, isPinned, modelLayerDigest,
  normalizeDigest, readBundleDigests, run, safeId, serializeRegistry, splitModelId,
} from '../../scripts/pin-model-digests.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHIPPED = path.join(HERE, '..', 'models.json');
const REGISTRY = JSON.parse(fs.readFileSync(SHIPPED, 'utf8'));
const IDS = REGISTRY.models.map((m) => m.id);
const upstreamOf = (id) => REGISTRY.models.find((m) => m.id === id)?.upstream;
const sha = (s) => createHash('sha256').update(s).digest('hex');
const DIGESTS = Object.fromEntries(IDS.map((id) => [id, sha(`blob:${id}`)]));
const SENTINEL = '<pinned-per-release>';

/** The shipped registry with every pin reverted: what a pre-release tree looks like. */
const sentinelRegistry = () => ({ ...structuredClone(REGISTRY), models: REGISTRY.models.map((m) => ({ ...m, sha256: SENTINEL })) });

function workdir({ sentinel = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-digests-'));
  const modelsJson = path.join(dir, 'models.json');
  if (sentinel) fs.writeFileSync(modelsJson, JSON.stringify(sentinelRegistry(), null, 2));
  else fs.copyFileSync(SHIPPED, modelsJson);
  return { dir, modelsJson, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

async function cli(argv, io = {}) {
  let out = '';
  let err = '';
  const code = await run(argv, { stdout: (s) => { out += s; }, stderr: (s) => { err += s; }, env: {}, ...io });
  return { code, out, err };
}

test('canonical serializer reproduces the shipped models.json byte for byte', () => {
  const raw = fs.readFileSync(SHIPPED, 'utf8');
  assert.equal(serializeRegistry(JSON.parse(raw)), raw);
});

test('canonical serializer keeps primitive arrays inline and nests object arrays', () => {
  assert.equal(canonicalStringify({ a: [1, 2], b: [{ c: 1 }], d: [], e: {} }), '{\n  "a": [1, 2],\n  "b": [\n    {\n      "c": 1\n    }\n  ],\n  "d": [],\n  "e": {}\n}');
});

test('digest helpers: isPinned, normalizeDigest, safeId, modelLayerDigest', () => {
  assert.equal(isPinned('<pinned-per-release>'), false);
  assert.equal(isPinned(sha('x')), true);
  assert.equal(isPinned(sha('x').toUpperCase()), true);
  assert.equal(normalizeDigest(`sha256:${sha('x').toUpperCase()}`), sha('x'));
  assert.equal(normalizeDigest('abc'), null);
  assert.equal(safeId('nemotron-3-nano:30b'), 'nemotron-3-nano_30b');
  const manifest = { layers: [{ mediaType: 'x/other', digest: `sha256:${sha('a')}` }, { mediaType: 'application/vnd.ollama.image.model', digest: `sha256:${sha('b')}` }] };
  assert.equal(modelLayerDigest(manifest), sha('b'));
  assert.equal(modelLayerDigest({ layers: [] }), null);
});

test('splitModelId keeps a Hub id on its own host and library ids on the registry', () => {
  assert.deepEqual(splitModelId('https://registry.ollama.ai', 'gemma4:26b'), { base: 'https://registry.ollama.ai', repoPath: 'library/gemma4', tag: '26b' });
  assert.deepEqual(splitModelId('https://registry.ollama.ai', 'hf.co/xtools-at/Qwensploit-V2-9B-CyberSecurity-Qwen3.5-GGUF:Q4_K_M'), { base: 'https://hf.co', repoPath: 'xtools-at/Qwensploit-V2-9B-CyberSecurity-Qwen3.5-GGUF', tag: 'Q4_K_M' });
});

test('applyDigests pins every model, refuses unapproved ids and gaps unless --partial', () => {
  const registry = sentinelRegistry();
  const pinned = applyDigests(registry, DIGESTS);
  assert.deepEqual(pinned.models.map((m) => m.sha256), IDS.map((id) => DIGESTS[id]));
  assert.equal(registry.models[0].sha256, SENTINEL, 'input must not be mutated');
  assert.throws(() => applyDigests(registry, { ...DIGESTS, 'llama3:8b': sha('z') }), /unapproved models: llama3:8b/);
  assert.throws(() => applyDigests(registry, { 'gemma4:26b': DIGESTS['gemma4:26b'] }), /no entry for: .*gemma4:31b.*nemotron-3-nano:30b.*qwensploit-v2:9b/);
  const partial = applyDigests(registry, { 'gemma4:26b': DIGESTS['gemma4:26b'] }, { partial: true });
  assert.equal(partial.models[1].sha256, SENTINEL);
});

test('--digests pins models.json deterministically and a second run is a no-op', async () => {
  const w = workdir();
  try {
    const digestsFile = path.join(w.dir, 'digests.json');
    fs.writeFileSync(digestsFile, JSON.stringify({ ...DIGESTS, 'gemma4:26b': `sha256:${DIGESTS['gemma4:26b'].toUpperCase()}` }));
    const first = await cli(['--models-json', w.modelsJson, '--digests', digestsFile]);
    assert.equal(first.code, 0, first.err);
    const written = fs.readFileSync(w.modelsJson, 'utf8');
    const parsed = JSON.parse(written);
    assert.deepEqual(parsed.models.map((m) => m.sha256), IDS.map((id) => DIGESTS[id]));
    assert.equal(parsed.updated, REGISTRY.updated, 'updated is untouched without --updated / SOURCE_DATE_EPOCH');
    assert.equal(parsed.models[0].minVramGb, 16);
    const second = await cli(['--models-json', w.modelsJson, '--digests', digestsFile]);
    assert.equal(second.code, 0);
    assert.match(second.out, /already up to date/);
    assert.equal(fs.readFileSync(w.modelsJson, 'utf8'), written);
    assert.deepEqual(fs.readdirSync(w.dir).filter((f) => f.includes('.tmp-')), []);
  } finally { w.cleanup(); }
});

test('--release-tag, --updated and SOURCE_DATE_EPOCH are honoured', async () => {
  const w = workdir();
  try {
    const digestsFile = path.join(w.dir, 'd.json');
    fs.writeFileSync(digestsFile, JSON.stringify(DIGESTS));
    const r = await cli(['--models-json', w.modelsJson, '--digests', digestsFile, '--release-tag', 'v1.2.3'], { env: { SOURCE_DATE_EPOCH: '1798761600' } });
    assert.equal(r.code, 0, r.err);
    const parsed = JSON.parse(fs.readFileSync(w.modelsJson, 'utf8'));
    assert.equal(parsed.releaseTag, 'v1.2.3');
    assert.equal(parsed.updated, '2027-01-01');
    const o = await cli(['--models-json', w.modelsJson, '--digests', digestsFile, '--updated', '2026-12-31']);
    assert.equal(JSON.parse(fs.readFileSync(w.modelsJson, 'utf8')).updated, '2026-12-31', o.err);
  } finally { w.cleanup(); }
});

test('--check fails on the sentinel, passes once pinned, and detects drift from a source', async () => {
  const w = workdir({ sentinel: true });
  try {
    const before = await cli(['--models-json', w.modelsJson, '--check']);
    assert.equal(before.code, 1);
    assert.match(before.err, /gemma4:26b: sha256 is still the sentinel/);
    const digestsFile = path.join(w.dir, 'd.json');
    fs.writeFileSync(digestsFile, JSON.stringify(DIGESTS));
    await cli(['--models-json', w.modelsJson, '--digests', digestsFile]);
    const after = await cli(['--models-json', w.modelsJson, '--check']);
    assert.equal(after.code, 0);
    const matching = await cli(['--models-json', w.modelsJson, '--check', '--digests', digestsFile]);
    assert.equal(matching.code, 0);
    fs.writeFileSync(digestsFile, JSON.stringify({ ...DIGESTS, 'gemma4:31b': sha('other') }));
    const drift = await cli(['--models-json', w.modelsJson, '--check', '--digests', digestsFile]);
    assert.equal(drift.code, 1);
    assert.match(drift.err, /gemma4:31b: pinned .* differs from source/);
  } finally { w.cleanup(); }
});

test('--check never writes the file', async () => {
  const w = workdir();
  try {
    const before = fs.readFileSync(w.modelsJson, 'utf8');
    await cli(['--models-json', w.modelsJson, '--check']);
    assert.equal(fs.readFileSync(w.modelsJson, 'utf8'), before);
  } finally { w.cleanup(); }
});

test('--from-bundle hashes GGUF blobs and cross-checks digests.json', async () => {
  const w = workdir();
  try {
    const bundle = path.join(w.dir, 'bundle');
    fs.mkdirSync(bundle);
    for (const id of IDS) fs.writeFileSync(path.join(bundle, `${safeId(id)}.gguf`), `weights for ${id}`);
    const expected = Object.fromEntries(IDS.map((id) => [id, sha(`weights for ${id}`)]));
    assert.deepEqual(await readBundleDigests(bundle, IDS), expected);

    const ok = await cli(['--models-json', w.modelsJson, '--from-bundle', bundle]);
    assert.equal(ok.code, 0, ok.err);
    assert.deepEqual(JSON.parse(fs.readFileSync(w.modelsJson, 'utf8')).models.map((m) => m.sha256), IDS.map((id) => expected[id]));

    fs.writeFileSync(path.join(bundle, 'digests.json'), JSON.stringify({ ...expected, 'gemma4:26b': sha('tampered') }));
    const bad = await cli(['--models-json', w.modelsJson, '--from-bundle', bundle]);
    assert.equal(bad.code, 3);
    assert.match(bad.err, /digests\.json says .* but gemma4_26b\.gguf hashes to/);

    fs.writeFileSync(path.join(bundle, 'digests.json'), JSON.stringify(expected));
    fs.rmSync(path.join(bundle, 'gemma4_31b.gguf'));
    const listedOnly = await cli(['--models-json', w.modelsJson, '--from-bundle', bundle, '--check']);
    assert.equal(listedOnly.code, 0, listedOnly.err);
  } finally { w.cleanup(); }
});

test('--from-bundle reports missing models and missing directories (exit 3)', async () => {
  const w = workdir();
  try {
    const bundle = path.join(w.dir, 'empty');
    fs.mkdirSync(bundle);
    const empty = await cli(['--models-json', w.modelsJson, '--from-bundle', bundle]);
    assert.equal(empty.code, 3);
    assert.match(empty.err, /no entry for/);
    const missing = await cli(['--models-json', w.modelsJson, '--from-bundle', path.join(w.dir, 'nope')]);
    assert.equal(missing.code, 3);
  } finally { w.cleanup(); }
});

test('registry mode resolves the model layer through an injected fetch', async () => {
  const urls = [];
  const fetchStub = async (url) => {
    urls.push(url);
    const id = IDS.find((i) => upstreamOf(i) ? url.includes(`/v2/${upstreamOf(i).split('/').slice(1).join('/').split(':')[0]}/manifests/`) : url.includes(`/library/${i.split(':')[0]}/manifests/${i.split(':')[1]}`));
    return { ok: true, status: 200, json: async () => ({ layers: [{ mediaType: 'application/vnd.ollama.image.model', digest: `sha256:${DIGESTS[id]}` }] }) };
  };
  assert.equal(await fetchRegistryDigest('https://registry.example', 'gemma4:26b', fetchStub), DIGESTS['gemma4:26b']);
  const w = workdir();
  try {
    const r = await cli(['--models-json', w.modelsJson, '--registry', 'https://registry.example/'], { fetch: fetchStub });
    assert.equal(r.code, 0, r.err);
    const secUpstream = upstreamOf('qwensploit-v2:9b');
    assert.ok(urls.every((u) => u.startsWith(`https://${secUpstream.split('/')[0]}/v2/`) || u.startsWith('https://registry.example/v2/library/')));
    const secModel = REGISTRY.models.find((m) => m.id === 'qwensploit-v2:9b');
    const [secHost, secRepo, secTag] = [secModel.upstream.split('/')[0], secModel.upstream.split('/').slice(1).join('/').split(':')[0], secModel.upstream.split(':').pop()];
    assert.ok(urls.includes(`https://${secHost}/v2/${secRepo}/manifests/${secTag}`), 'Hub-backed id must resolve from its own repo, not the library');
    assert.ok(!urls.some((u) => u.includes('/library/qwensploit-v2/')));
    assert.deepEqual(JSON.parse(fs.readFileSync(w.modelsJson, 'utf8')).models.map((m) => m.sha256), IDS.map((id) => DIGESTS[id]));
    const notFound = await cli(['--models-json', w.modelsJson, '--registry', 'https://registry.example'], { fetch: async () => ({ ok: false, status: 404 }) });
    assert.equal(notFound.code, 3);
    assert.match(notFound.err, /HTTP 404/);
  } finally { w.cleanup(); }
});

test('usage and input errors map to documented exit codes', async () => {
  const w = workdir();
  try {
    assert.equal((await cli(['--bogus'])).code, 2);
    assert.equal((await cli(['--digests'])).code, 2);
    assert.equal((await cli(['--digests', 'a', '--from-bundle', 'b'])).code, 2);
    assert.equal((await cli(['--release-tag', 'latest'])).code, 2);
    assert.equal((await cli(['--updated', 'soon'])).code, 2);
    assert.equal((await cli(['--digests', path.join(w.dir, 'missing.json'), '--models-json', w.modelsJson])).code, 3);
    assert.equal((await cli(['--models-json', path.join(w.dir, 'nope.json'), '--check'])).code, 4);
    const bad = path.join(w.dir, 'bad.json');
    fs.writeFileSync(bad, JSON.stringify({ ...DIGESTS, 'gemma4:26b': 'not-a-digest' }));
    const r = await cli(['--digests', bad, '--models-json', w.modelsJson]);
    assert.equal(r.code, 3);
    assert.match(r.err, /not 64 hex/);
    const help = await cli(['--help']);
    assert.equal(help.code, 0);
    assert.match(help.out, /Digest sources/);
  } finally { w.cleanup(); }
});

test('checkRegistry flags malformed digests as well as the sentinel', () => {
  const problems = checkRegistry({ models: [{ id: 'a', sha256: 'zzz' }, { id: 'b', sha256: sha('b') }] });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /a: sha256 is missing or malformed/);
});
