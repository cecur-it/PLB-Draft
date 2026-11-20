#!/usr/bin/env node

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { runWizard } from '../onboarding/wizard.mjs';
import { resolveModelIds } from './build-airgap-bundle.mjs';

const registry = JSON.parse(fs.readFileSync(new URL('../onboarding/models.json', import.meta.url), 'utf8'));

function parseEnv(filePath) {
  return Object.fromEntries(
    fs.readFileSync(filePath, 'utf8')
      .split(/\r?\n/)
      .filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line))
      .map((line) => {
        const index = line.indexOf('=');
        return [line.slice(0, index), line.slice(index + 1)];
      }),
  );
}

test('default air-gap bundle contains every production model and excludes optional evaluation models', () => {
  assert.deepEqual(resolveModelIds(registry), ['gemma4:26b', 'gemma4:31b', 'nemotron-3-nano:30b']);
});

test('an explicitly requested evaluation model remains available for an evaluation-only bundle', () => {
  const requested = ['qwensploit-v2:9b'];
  assert.equal(resolveModelIds(registry, requested), requested);
});

test('Windows installer provisions preload tags and verifies the air-gap archive before extraction', () => {
  const script = fs.readFileSync(new URL('../install.ps1', import.meta.url), 'utf8');
  assert.match(script, /\$preload = \$EnvMap\['OLLAMA_PRELOAD_MODELS'\]/);
  assert.match(script, /\$model -eq 'cs3-errow-security'/);
  assert.match(script, /ArgumentList @\('pull', \$model\)/);
  assert.match(script, /Assert-LocalModels/);
  const airgap = script.slice(script.indexOf('function Install-AirgapOllamaAndModel'));
  assert.ok(airgap.indexOf('Get-FileHash') < airgap.indexOf("ArgumentList @('-xf'"));
  assert.doesNotMatch(airgap, /Write-WarnLog/);
});

test('Windows console replacement waits for health before discarding its rollback container', () => {
  const script = fs.readFileSync(new URL('../install.ps1', import.meta.url), 'utf8');
  const start = script.indexOf('function Start-SocConsole');
  const acquire = script.slice(start, script.indexOf('function Install-OnpremOllamaAndModel', start));

  assert.match(acquire, /\$buildLocal = \(\$Profile -eq 'onprem' -and \$image -notmatch '\/'\)/);
  assert.match(acquire, /-and \$image -notmatch '@sha256:\[0-9a-fA-F\]\{64\}\$'/);
  assert.match(acquire, /@\('build', '--pull=false', '-t', \$image,/);
  assert.ok(acquire.indexOf("ArgumentList @('build'") < acquire.indexOf("ArgumentList @('stop'"));

  const healthFailure = acquire.slice(acquire.indexOf('  if ($failure) {'));
  const removeReplacement = healthFailure.indexOf("rm -f $containerName");
  const restoreName = healthFailure.indexOf("$backupName, $containerName");
  const restartPrevious = healthFailure.indexOf("ArgumentList @('start', $containerName)");
  assert.ok(removeReplacement >= 0 && removeReplacement < restoreName && restoreName < restartPrevious);
  assert.ok(healthFailure.indexOf('Write-FailClosed $failure') > restartPrevious);
});

test('Helm gates every preloaded model into readiness and pins the Ollama runtime', () => {
  const read = (relative) => fs.readFileSync(new URL(`../deployment/helm/cs3/${relative}`, import.meta.url), 'utf8');
  const template = read('templates/ollama.yaml');
  const values = read('values.yaml');
  const airgap = read('values-airgap.yaml');
  const loops = template.match(/range \$model := splitList "," \.Values\.ollama\.preloadModels/g) || [];
  assert.equal(loops.length, 2, 'postStart pulls and readiness checks must iterate the same preload list');
  assert.match(template, /- sh\s+- -ec/);
  assert.doesNotMatch(template, /ollama pull[^\n]*&/);
  const digest = values.match(/ollama\/ollama, tag: 0\.40\.5, digest: "(sha256:[0-9a-f]{64})"/);
  assert.ok(digest, 'default Ollama image must have a verified digest');
  assert.ok(airgap.includes(`digest: "${digest[1]}"`), 'air-gap must use the same pinned Ollama image');
  assert.match(airgap, /pullModelsOnStart: false/);
});

test('wizard propagates model choices to console and Vendetta role variables', async () => {
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cs3-model-wizard-'));
  const overrides = {
    OLLAMA_PRIMARY_MODEL: 'primary-test:1b',
    OLLAMA_FALLBACK_MODEL: 'fallback-test:2b',
    OLLAMA_SECURITY_MODEL: 'security-test:3b',
    INFERENCE_MODEL_REASONING_DEEP: 'deep-test:4b',
  };
  const saved = Object.fromEntries(Object.keys(overrides).map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, overrides);
    const result = await runWizard('onprem', { repoRoot, nonInteractive: true });
    const env = parseEnv(result.envPath);
    assert.equal(env.INFERENCE_MODEL_TRIAGE, overrides.OLLAMA_PRIMARY_MODEL);
    assert.equal(env.CS3_MODEL_TRIAGE, overrides.OLLAMA_PRIMARY_MODEL);
    assert.equal(env.INFERENCE_MODEL_FORENSIC, overrides.OLLAMA_FALLBACK_MODEL);
    assert.equal(env.INFERENCE_MODEL_GUARD, overrides.OLLAMA_FALLBACK_MODEL);
    assert.equal(env.CS3_MODEL_REASONING, overrides.OLLAMA_FALLBACK_MODEL);
    assert.equal(env.INFERENCE_MODEL_SECURITY, overrides.OLLAMA_SECURITY_MODEL);
    assert.equal(env.INFERENCE_MODEL_ERROW_SECURITY, overrides.OLLAMA_SECURITY_MODEL);
    assert.equal(env.CS3_MODEL_SECURITY, overrides.OLLAMA_SECURITY_MODEL);
    assert.equal(env.CS3_MODEL_REASONING_DEEP, overrides.INFERENCE_MODEL_REASONING_DEEP);
    assert.equal(env.CS3_MODEL_ERROW_SECURITY, 'cs3-errow-security');
    assert.equal(env.OLLAMA_REASONING_DEEP_MODEL, overrides.INFERENCE_MODEL_REASONING_DEEP);
    assert.equal(env.OLLAMA_ERROW_SECURITY_MODEL, overrides.OLLAMA_SECURITY_MODEL);
    assert.equal(env.OLLAMA_PRELOAD_MODELS, 'primary-test:1b,fallback-test:2b,deep-test:4b');
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(repoRoot, { recursive: true, force: true });
  }
});
