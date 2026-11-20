#!/usr/bin/env node
/**
 * ollama/detect-hardware.mjs — probes GPU, VRAM, OS and RAM, then recommends the
 * LLM backend and model assignment for this node. Output is JSON by default.
 * Adapted from CS3 scripts/detect-hardware.mjs; thresholds come from models.json,
 * nothing is hard-coded here except the role -> tier mapping below.
 *
 * Traces: PROMPT §1 Tier 4 (nemotron triage / gemma4 forensic, llama.cpp fallback),
 *         PROMPT §2.4 (model -> role -> node), CONTRACT §10 (models.json thresholds).
 *
 * Decision (first match wins; VRAM = largest single accelerator, RAM = system RAM, where the
 * RAM minimum is met at 95% of the model.json value to absorb kernel/firmware reservations):
 *   1. CUDA/Metal VRAM >= agentic-tier minimum (24 GB VRAM / 64 GB RAM):
 *        triage = nemotron-3-nano:30b (agentic tier)
 *        forensic = gemma4:31b (frontier tier, the "upgrade") when it also fits, else gemma4:26b
 *   2. CUDA/Metal VRAM >= entry-tier minimum (16 GB VRAM / 32 GB RAM):
 *        triage = forensic = gemma4:26b (entry tier)
 *   3. anything else (CPU only, unknown VRAM, non-CUDA/Metal accelerator):
 *        backend = llama.cpp (ollama/install-llama.cpp.sh) serving the entry-tier GGUF on CPU
 *
 * Usage:
 *   node ollama/detect-hardware.mjs [--text] [--models-json <path>] [--fixture <file.json>]
 *     --text        human-readable report instead of JSON
 *     --fixture     use recorded probe output instead of the live host:
 *                   {"platform","arch","totalRamBytes","freeRamBytes","cpuCount","hostname",
 *                    "probes":{"nvidia-smi","system_profiler","lspci","powershell"}}
 *
 * Exit codes: 0 report produced, 2 usage error or unreadable models.json / fixture.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_MODELS_JSON = path.join(__dirname, 'models.json');
const ACCELERATED_BACKENDS = new Set(['cuda', 'metal-unified-memory', 'metal']);
const GIB = 1024 ** 3;
// Kernel and firmware reserve memory, so a "64 GB" server reports ~62.7 GiB; accept 95% of the RAM minimum.
export const RAM_TOLERANCE = 0.95;

/** Role -> tier mapping (spec §2.4). Model ids are resolved from models.json. */
export const ROLE_TIERS = { triage: 'agentic', forensic: 'entry', forensicUpgrade: 'frontier' };

export function bytesToGb(bytes) {
  return Math.round((bytes / GIB) * 10) / 10;
}

function tryExec(cmd, cmdArgs) {
  try {
    return execFileSync(cmd, cmdArgs, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 });
  } catch {
    return null;
  }
}

export const liveProbes = {
  'nvidia-smi': () => tryExec('nvidia-smi', ['--query-gpu=name,memory.total', '--format=csv,noheader,nounits']),
  system_profiler: () => tryExec('system_profiler', ['SPDisplaysDataType', '-json']),
  lspci: () => tryExec('lspci', ['-mm']),
  powershell: () => {
    const cmd = 'Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion | ConvertTo-Json';
    return tryExec('powershell.exe', ['-NoProfile', '-Command', cmd]) || tryExec('pwsh', ['-NoProfile', '-Command', cmd]);
  },
};

/** `nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits` (memory in MiB). */
export function parseNvidiaSmi(text) {
  if (!text) return [];
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.lastIndexOf(',');
      const name = (idx === -1 ? line : line.slice(0, idx)).trim();
      const vramMb = Number(idx === -1 ? NaN : line.slice(idx + 1));
      return { name, vramGb: Number.isFinite(vramMb) && vramMb > 0 ? Math.round(vramMb / 1024) : null, backend: 'cuda' };
    });
}

/** Apple Silicon reports one unified pool shared between CPU and GPU. */
export function parseSystemProfiler(text, { arch, totalRamGb }) {
  const isAppleSilicon = arch === 'arm64';
  let chipsetModel = isAppleSilicon ? 'Apple Silicon GPU (unified memory)' : 'Unknown';
  try {
    const displays = (text ? JSON.parse(text) : {}).SPDisplaysDataType || [];
    if (displays[0]?.sppci_model) chipsetModel = displays[0].sppci_model;
  } catch {
    // keep the generic label
  }
  return [{
    name: chipsetModel,
    vramGb: isAppleSilicon ? Math.round(totalRamGb) : null,
    backend: isAppleSilicon ? 'metal-unified-memory' : 'metal',
    unifiedMemory: isAppleSilicon,
  }];
}

/** Best-effort listing when no NVIDIA driver is present; VRAM is unknown. */
export function parseLspci(text) {
  if (!text) return [];
  return text
    .split(/\r?\n/)
    .filter((l) => /VGA compatible controller|3D controller/i.test(l))
    .map((l) => ({ name: l.trim(), vramGb: null, backend: 'unknown' }));
}

/** AdapterRAM via WMI under-reports above 4 GB on some drivers, so it is advisory only. */
export function parseWindowsCim(text) {
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    return (Array.isArray(parsed) ? parsed : [parsed]).map((gpu) => ({
      name: gpu.Name,
      vramGb: typeof gpu.AdapterRAM === 'number' && gpu.AdapterRAM > 0 ? bytesToGb(gpu.AdapterRAM) : null,
      backend: 'directml-or-cuda',
      note: 'AdapterRAM via WMI can under-report VRAM above 4GB; cross-check with nvidia-smi.',
    }));
  } catch {
    return [];
  }
}

export function detectGpus(sys, probes) {
  const nvidia = parseNvidiaSmi(probes['nvidia-smi']?.());
  if (nvidia.length > 0) return nvidia;
  if (sys.platform === 'linux') return parseLspci(probes.lspci?.());
  if (sys.platform === 'darwin') return parseSystemProfiler(probes.system_profiler?.(), sys);
  if (sys.platform === 'win32') return parseWindowsCim(probes.powershell?.());
  return [];
}

function modelFor(registry, tierName) {
  const id = registry.tiers?.[tierName]?.models?.[0];
  return (registry.models || []).find((m) => m.id === id) || null;
}

function fits(model, vramGb, ramGb) {
  return Boolean(model) && vramGb !== null && vramGb >= model.minVramGb && ramGb >= (model.minSystemRamGb || 0) * RAM_TOLERANCE;
}

function plan(registry, backend, tier, triage, forensic, extra) {
  const fallback = modelFor(registry, ROLE_TIERS.forensic);
  const deep = tier === 'agentic' ? modelFor(registry, ROLE_TIERS.forensicUpgrade) : null;
  const models = [...new Set([triage?.id, forensic?.id, fallback?.id, deep?.id].filter(Boolean))];
  return {
    backend,
    viable: true,
    tier,
    triageModel: triage?.id ?? null,
    forensicModel: forensic?.id ?? null,
    forensicUpgrade: forensic ? forensic.id === modelFor(registry, ROLE_TIERS.forensicUpgrade)?.id : false,
    models,
    installer: backend === 'ollama' ? 'ollama/install-ollama.sh' : 'ollama/install-llama.cpp.sh',
    env: {
      OLLAMA_PRIMARY_MODEL: triage?.id ?? '',
      OLLAMA_FALLBACK_MODEL: fallback?.id ?? '',
      INFERENCE_MODEL_TRIAGE: triage?.id ?? '',
      INFERENCE_MODEL_FORENSIC: forensic?.id ?? '',
      OLLAMA_PRELOAD_MODELS: models.join(','),
    },
    rationale: [],
    warnings: [],
    ...extra,
  };
}

/** Pure decision function; exported for ollama/detect-hardware.test.mjs. */
export function recommend(registry, hw) {
  const agentic = modelFor(registry, ROLE_TIERS.triage);
  const entry = modelFor(registry, ROLE_TIERS.forensic);
  const frontier = modelFor(registry, ROLE_TIERS.forensicUpgrade);
  const accel = hw.gpus.filter((g) => ACCELERATED_BACKENDS.has(g.backend) && g.vramGb);
  const maxVram = accel.reduce((max, g) => Math.max(max, g.vramGb), 0) || null;
  const totalVram = accel.reduce((sum, g) => sum + g.vramGb, 0) || null;

  if (!agentic || !entry) {
    const out = plan(registry, 'llama.cpp', 'cpu-fallback', null, null, { viable: false });
    out.warnings.push('models.json defines no agentic/entry tier; refusing to recommend an unapproved model.');
    return out;
  }

  if (fits(agentic, maxVram, hw.totalRamGb)) {
    const upgrade = fits(frontier, maxVram, hw.totalRamGb);
    const forensic = upgrade ? frontier : entry;
    const out = plan(registry, 'ollama', 'agentic', agentic, forensic, {});
    out.maxLoadedModels = totalVram >= agentic.minVramGb + forensic.minVramGb ? 2 : 1;
    out.env.OLLAMA_MAX_LOADED_MODELS = String(out.maxLoadedModels);
    out.rationale.push(
      `${maxVram} GB VRAM / ${hw.totalRamGb} GB RAM satisfies ${agentic.id} (needs ${agentic.minVramGb} GB / ${agentic.minSystemRamGb} GB): triage.`,
      upgrade
        ? `${frontier.id} also fits (needs ${frontier.minVramGb} GB / ${frontier.minSystemRamGb} GB): forensic upgrade over ${entry.id}.`
        : `${entry.id} serves the forensic role.`,
    );
    if (out.maxLoadedModels === 1) {
      out.warnings.push(`Only ${totalVram} GB of accelerator memory: triage and forensic models are swapped (OLLAMA_MAX_LOADED_MODELS=1); expect a reload delay on failover.`);
    }
    return out;
  }

  if (fits(entry, maxVram, hw.totalRamGb)) {
    const out = plan(registry, 'ollama', 'entry', entry, entry, { maxLoadedModels: 1 });
    out.env.OLLAMA_MAX_LOADED_MODELS = '1';
    out.rationale.push(`${maxVram} GB VRAM / ${hw.totalRamGb} GB RAM satisfies ${entry.id} (needs ${entry.minVramGb} GB / ${entry.minSystemRamGb} GB) but not ${agentic.id}.`);
    out.warnings.push(`Triage and forensic share ${entry.id}; the failover cascade has no model diversity on this node.`);
    return out;
  }

  const ramOk = hw.totalRamGb >= (entry.minSystemRamGb || 0) * RAM_TOLERANCE;
  const out = plan(registry, 'llama.cpp', 'cpu-fallback', entry, entry, { viable: ramOk, maxLoadedModels: 1 });
  out.rationale.push(
    maxVram === null
      ? 'No CUDA/Metal accelerator with a known VRAM size was detected; using the llama.cpp CPU fallback.'
      : `${maxVram} GB VRAM is below the ${entry.minVramGb} GB needed for ${entry.id}; using the llama.cpp CPU fallback.`,
  );
  if (!ramOk) {
    out.warnings.push(`${hw.totalRamGb} GB RAM is below the ${entry.minSystemRamGb} GB needed for ${entry.id}: not viable, the gateway will serve deterministic heuristics (tier 3).`);
  }
  return out;
}

export function detectHardware({ sys, probes = liveProbes, registry } = {}) {
  const system = sys || {
    platform: os.platform(),
    arch: os.arch(),
    totalRamGb: bytesToGb(os.totalmem()),
    freeRamGb: bytesToGb(os.freemem()),
    cpuCount: os.cpus()?.length || 0,
    hostname: os.hostname(),
  };
  const gpus = detectGpus(system, probes);
  const accel = gpus.filter((g) => ACCELERATED_BACKENDS.has(g.backend) && g.vramGb);
  const hw = { ...system, gpus };
  return {
    platform: system.platform,
    arch: system.arch,
    hostname: system.hostname,
    cpuCount: system.cpuCount,
    totalRamGb: system.totalRamGb,
    freeRamGb: system.freeRamGb,
    gpus,
    maxVramGb: accel.reduce((max, g) => Math.max(max, g.vramGb), 0) || null,
    totalVramGb: accel.reduce((sum, g) => sum + g.vramGb, 0) || null,
    modelsRelease: registry?.releaseTag ?? null,
    recommendation: recommend(registry || { tiers: {}, models: [] }, hw),
  };
}

export function loadFixture(file) {
  const f = JSON.parse(fs.readFileSync(file, 'utf8'));
  const sys = {
    platform: f.platform,
    arch: f.arch || 'x64',
    totalRamGb: bytesToGb(f.totalRamBytes),
    freeRamGb: bytesToGb(f.freeRamBytes ?? f.totalRamBytes),
    cpuCount: f.cpuCount ?? 0,
    hostname: f.hostname || 'fixture',
  };
  const probes = Object.fromEntries(Object.entries(f.probes || {}).map(([k, v]) => [k, () => v]));
  return { sys, probes };
}

export function renderText(report) {
  const r = report.recommendation;
  const lines = [
    '', '=== vendetta-stack LLM hardware detection ===',
    `Platform:      ${report.platform} (${report.arch})`,
    `CPU cores:     ${report.cpuCount}`,
    `System RAM:    ${report.totalRamGb} GB total / ${report.freeRamGb} GB free`,
  ];
  if (report.gpus.length === 0) lines.push('GPU:           none detected');
  for (const g of report.gpus) lines.push(`GPU:           ${g.name}${g.vramGb ? ` — ${g.vramGb} GB VRAM` : ' — VRAM unknown'} (${g.backend})`);
  lines.push('', `Backend:       ${r.backend}${r.viable ? '' : ' (NOT viable on this host)'}`, `Tier:          ${r.tier}`,
    `Triage model:  ${r.triageModel ?? '-'}`, `Forensic:      ${r.forensicModel ?? '-'}${r.forensicUpgrade ? ' (upgrade)' : ''}`,
    `Installer:     ${r.installer}`, `Preload:       ${r.env.OLLAMA_PRELOAD_MODELS || '-'}`);
  r.rationale.forEach((l) => lines.push(`  + ${l}`));
  r.warnings.forEach((l) => lines.push(`  ! ${l}`));
  return `${lines.join('\n')}\n`;
}

function parseArgs(argv) {
  const args = { text: false, modelsJson: DEFAULT_MODELS_JSON, fixture: null, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    switch (argv[i]) {
      case '--text': args.text = true; break;
      case '--json': break;
      case '--models-json':
      case '--fixture':
        if (i + 1 >= argv.length) throw new Error(`${argv[i]} needs a value`);
        args[argv[i] === '--fixture' ? 'fixture' : 'modelsJson'] = argv[i + 1];
        i += 1;
        break;
      case '-h': case '--help': args.help = true; break;
      default: throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  return args;
}

const isMain = (() => {
  try {
    return import.meta.url === new URL(`file://${path.resolve(process.argv[1] || '')}`).href;
  } catch {
    return false;
  }
})();

if (isMain) {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      process.stdout.write(fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('*/')[0].replace(/^#!.*\n/, '').replace(/^\/\*\*\n/, '').replace(/^ \* ?/gm, ''));
    } else {
      const registry = JSON.parse(fs.readFileSync(args.modelsJson, 'utf8'));
      const report = detectHardware({ registry, ...(args.fixture ? loadFixture(args.fixture) : {}) });
      process.stdout.write(args.text ? renderText(report) : `${JSON.stringify(report, null, 2)}\n`);
    }
  } catch (err) {
    process.stderr.write(`[detect-hardware] ${err.message}\n`);
    process.exitCode = 2;
  }
}
