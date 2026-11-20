#!/usr/bin/env node
/**
 * detect-hardware.test.mjs — node:test suite for ollama/detect-hardware.mjs.
 * Uses injected fixtures for nvidia-smi / system_profiler / lspci / PowerShell output
 * and the shipped models.json thresholds; needs no GPU and spawns no probe.
 *
 * Traces: PROMPT §1 Tier 4 (model selection), PROMPT §2.4, CONTRACT §10.
 * Run:    node --test ollama/
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  detectHardware, loadFixture, parseLspci, parseNvidiaSmi, parseSystemProfiler, parseWindowsCim, recommend, renderText,
} from './detect-hardware.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const registry = JSON.parse(fs.readFileSync(path.join(HERE, 'models.json'), 'utf8'));

const sys = (over = {}) => ({ platform: 'linux', arch: 'x64', totalRamGb: 64, freeRamGb: 50, cpuCount: 32, hostname: 'node-a', ...over });
const probes = (over = {}) => Object.fromEntries(Object.entries(over).map(([k, v]) => [k, () => v]));

const NVIDIA_4090 = 'NVIDIA GeForce RTX 4090, 24564\n';
const NVIDIA_A100x2 = 'NVIDIA A100-SXM4-80GB, 81920\nNVIDIA A100-SXM4-80GB, 81920\n';
const NVIDIA_4080 = 'NVIDIA GeForce RTX 4080, 16376\n';
const NVIDIA_3060 = 'NVIDIA GeForce RTX 3060, 12288\n';
const NVIDIA_L4 = 'NVIDIA L4, 23034\n';
const APPLE_JSON = JSON.stringify({ SPDisplaysDataType: [{ sppci_model: 'Apple M3 Max' }] });

const detect = (s, p) => detectHardware({ sys: s, probes: probes(p), registry });

test('parseNvidiaSmi converts MiB to GB per GPU and tolerates commas in names', () => {
  assert.deepEqual(parseNvidiaSmi(NVIDIA_4090), [{ name: 'NVIDIA GeForce RTX 4090', vramGb: 24, backend: 'cuda' }]);
  assert.equal(parseNvidiaSmi(NVIDIA_A100x2).length, 2);
  assert.equal(parseNvidiaSmi('Tesla, Inc. T4, 15360\n')[0].name, 'Tesla, Inc. T4');
  assert.equal(parseNvidiaSmi('bad line\n')[0].vramGb, null);
  assert.deepEqual(parseNvidiaSmi(null), []);
});

test('parseSystemProfiler reports unified memory on arm64 and no VRAM on Intel Macs', () => {
  const arm = parseSystemProfiler(APPLE_JSON, { arch: 'arm64', totalRamGb: 64 });
  assert.deepEqual(arm[0], { name: 'Apple M3 Max', vramGb: 64, backend: 'metal-unified-memory', unifiedMemory: true });
  const intel = parseSystemProfiler('not json', { arch: 'x64', totalRamGb: 16 });
  assert.equal(intel[0].vramGb, null);
  assert.equal(intel[0].backend, 'metal');
});

test('parseLspci and parseWindowsCim yield GPUs with unknown / advisory VRAM', () => {
  const pci = parseLspci('00:02.0 "VGA compatible controller" "Intel" "UHD 630"\n01:00.0 "Ethernet controller" "Intel" "I219"\n');
  assert.equal(pci.length, 1);
  assert.equal(pci[0].vramGb, null);
  const win = parseWindowsCim(JSON.stringify({ Name: 'AMD Radeon', AdapterRAM: 8 * 1024 ** 3 }));
  assert.equal(win[0].vramGb, 8);
  assert.deepEqual(parseWindowsCim('garbage'), []);
});

test('24 GB VRAM / 64 GB RAM: nemotron-3-nano:30b triage with gemma4:31b forensic upgrade', () => {
  const r = detect(sys(), { 'nvidia-smi': NVIDIA_4090 }).recommendation;
  assert.equal(r.backend, 'ollama');
  assert.equal(r.tier, 'agentic');
  assert.equal(r.triageModel, 'nemotron-3-nano:30b');
  assert.equal(r.forensicModel, 'gemma4:31b');
  assert.equal(r.forensicUpgrade, true);
  assert.equal(r.maxLoadedModels, 1);
  assert.ok(r.warnings.some((w) => /swapped/.test(w)));
  assert.equal(r.env.INFERENCE_MODEL_TRIAGE, 'nemotron-3-nano:30b');
  assert.equal(r.env.OLLAMA_FALLBACK_MODEL, 'gemma4:26b');
  assert.equal(r.env.OLLAMA_PRELOAD_MODELS, 'nemotron-3-nano:30b,gemma4:31b,gemma4:26b');
});

test('multi-GPU data-centre node keeps both models resident (OLLAMA_MAX_LOADED_MODELS=2)', () => {
  const report = detect(sys({ totalRamGb: 512 }), { 'nvidia-smi': NVIDIA_A100x2 });
  assert.equal(report.maxVramGb, 80);
  assert.equal(report.totalVramGb, 160);
  assert.equal(report.recommendation.maxLoadedModels, 2);
  assert.equal(report.recommendation.env.OLLAMA_MAX_LOADED_MODELS, '2');
});

test('16 GB VRAM / 32 GB RAM: gemma4:26b serves both roles', () => {
  const r = detect(sys({ totalRamGb: 32 }), { 'nvidia-smi': NVIDIA_4080 }).recommendation;
  assert.equal(r.backend, 'ollama');
  assert.equal(r.tier, 'entry');
  assert.equal(r.triageModel, 'gemma4:26b');
  assert.equal(r.forensicModel, 'gemma4:26b');
  assert.equal(r.forensicUpgrade, false);
  assert.ok(r.warnings.some((w) => /no model diversity/.test(w)));
});

test('24 GB VRAM but only 32 GB RAM falls back to the entry tier (RAM is enforced)', () => {
  const r = detect(sys({ totalRamGb: 32 }), { 'nvidia-smi': NVIDIA_4090 }).recommendation;
  assert.equal(r.tier, 'entry');
  assert.equal(r.triageModel, 'gemma4:26b');
});

test('a "64 GB" server reporting 62.7 GiB still qualifies; 58 GiB does not', () => {
  assert.equal(detect(sys({ totalRamGb: 62.7 }), { 'nvidia-smi': NVIDIA_4090 }).recommendation.tier, 'agentic');
  assert.equal(detect(sys({ totalRamGb: 58 }), { 'nvidia-smi': NVIDIA_4090 }).recommendation.tier, 'entry');
});

test('a 23 GB card (L4) is entry tier, a 12 GB card falls back to llama.cpp', () => {
  assert.equal(detect(sys(), { 'nvidia-smi': NVIDIA_L4 }).recommendation.tier, 'entry');
  const small = detect(sys(), { 'nvidia-smi': NVIDIA_3060 }).recommendation;
  assert.equal(small.backend, 'llama.cpp');
  assert.equal(small.installer, 'ollama/install-llama.cpp.sh');
  assert.equal(small.viable, true);
  assert.match(small.rationale[0], /12 GB VRAM is below the 16 GB/);
});

test('CPU-only host: llama.cpp fallback, viable only with enough RAM', () => {
  const big = detect(sys({ totalRamGb: 64 }), { lspci: '' }).recommendation;
  assert.equal(big.backend, 'llama.cpp');
  assert.equal(big.viable, true);
  assert.deepEqual(big.models, ['gemma4:26b']);
  const small = detect(sys({ totalRamGb: 8 }), {}).recommendation;
  assert.equal(small.backend, 'llama.cpp');
  assert.equal(small.viable, false);
  assert.ok(small.warnings.some((w) => /heuristics/.test(w)));
});

test('non-NVIDIA Linux GPU with unknown VRAM never selects the Ollama GPU tiers', () => {
  const r = detect(sys(), { lspci: '03:00.0 "VGA compatible controller" "AMD" "Navi 31"\n' }).recommendation;
  assert.equal(r.backend, 'llama.cpp');
});

test('Apple Silicon unified memory counts as VRAM; a 16 GB Mac cannot run the entry model', () => {
  const m3max = detect(sys({ platform: 'darwin', arch: 'arm64', totalRamGb: 64 }), { system_profiler: APPLE_JSON });
  assert.equal(m3max.gpus[0].backend, 'metal-unified-memory');
  assert.equal(m3max.recommendation.tier, 'agentic');
  const air = detect(sys({ platform: 'darwin', arch: 'arm64', totalRamGb: 16 }), { system_profiler: APPLE_JSON });
  assert.equal(air.recommendation.backend, 'llama.cpp');
  assert.equal(air.recommendation.viable, false);
});

test('Windows CIM-only GPUs are not treated as CUDA', () => {
  const r = detect(sys({ platform: 'win32' }), { powershell: JSON.stringify({ Name: 'Radeon', AdapterRAM: 24 * 1024 ** 3 }) });
  assert.equal(r.gpus[0].vramGb, 24);
  assert.equal(r.recommendation.backend, 'llama.cpp');
});

test('thresholds come from models.json: raising a minimum changes the decision', () => {
  const stricter = structuredClone(registry);
  stricter.models.find((m) => m.id === 'nemotron-3-nano:30b').minVramGb = 48;
  const hw = { ...sys(), gpus: parseNvidiaSmi(NVIDIA_4090) };
  assert.equal(recommend(registry, hw).tier, 'agentic');
  assert.equal(recommend(stricter, hw).tier, 'entry');
});

test('an empty or tier-less registry fails closed without recommending an unapproved model', () => {
  const r = recommend({ tiers: {}, models: [] }, { ...sys(), gpus: parseNvidiaSmi(NVIDIA_4090) });
  assert.equal(r.backend, 'llama.cpp');
  assert.equal(r.viable, false);
  assert.equal(r.triageModel, null);
  assert.deepEqual(r.models, []);
});

test('renderText summarises backend, models and warnings', () => {
  const text = renderText(detect(sys(), { 'nvidia-smi': NVIDIA_4090 }));
  assert.match(text, /Backend:\s+ollama/);
  assert.match(text, /Forensic:\s+gemma4:31b \(upgrade\)/);
  assert.match(text, /! Only 24 GB/);
});

test('CLI --fixture produces JSON and --text works; bad flags exit 2', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'detect-hw-'));
  try {
    const fixture = path.join(dir, 'fx.json');
    fs.writeFileSync(fixture, JSON.stringify({
      platform: 'linux', arch: 'x64', totalRamBytes: 64 * 1024 ** 3, cpuCount: 16, probes: { 'nvidia-smi': NVIDIA_4090 },
    }));
    const script = path.join(HERE, 'detect-hardware.mjs');
    const out = JSON.parse(execFileSync('node', [script, '--fixture', fixture], { encoding: 'utf8' }));
    assert.equal(out.recommendation.triageModel, 'nemotron-3-nano:30b');
    assert.equal(out.modelsRelease, registry.releaseTag);
    assert.match(execFileSync('node', [script, '--fixture', fixture, '--text'], { encoding: 'utf8' }), /Tier:\s+agentic/);
    assert.equal(loadFixture(fixture).sys.totalRamGb, 64);
    assert.throws(() => execFileSync('node', [script, '--bogus'], { stdio: 'pipe' }), (e) => e.status === 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
