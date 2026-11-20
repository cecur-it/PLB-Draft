import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { OpenAICompatGateway, backendFor, setGateway } from '../../server/inference/gateway';
import { setBackendFetchForTests } from '../../server/inference/backends/base';
import type { InferenceGateway, InferenceRequest } from '../../server/inference/types';
import { setGuardModel } from '../../server/inference/router';

const req = {
  role: 'triage' as const,
  profile: 'onprem' as const,
  tenantId: 't1',
  incidentId: 'i1',
  dataClassification: 'internal' as const,
  input: { system: 's', user: 'u', schema: { type: 'object', required: ['a'] } },
};

function mockFetch(body: unknown, ok = true) {
  setBackendFetchForTests((async () => ({ ok, status: ok ? 200 : 500, json: async () => body })) as any);
}

test('backend is selected by profile', () => {
  process.env.INFERENCE_GATEWAY_URL = 'https://gw.example/v1/';
  assert.equal(backendFor('cloud').backend, 'vllm');
  assert.equal(backendFor('cloud').baseUrl, 'https://gw.example/v1');
  assert.equal(backendFor('airgap').backend, 'ollama');
  assert.match(backendFor('onprem').baseUrl, /11434/);
  delete process.env.INFERENCE_GATEWAY_URL;
});

test('security role routes to the security model, overridable, never the triage model', () => {
  const saved = { sec: process.env.INFERENCE_MODEL_SECURITY, ollama: process.env.OLLAMA_SECURITY_MODEL, primary: process.env.OLLAMA_PRIMARY_MODEL };
  try {
    delete process.env.INFERENCE_MODEL_SECURITY;
    delete process.env.OLLAMA_SECURITY_MODEL;
    process.env.OLLAMA_PRIMARY_MODEL = 'nemotron-test:1b';
    assert.equal(backendFor('onprem').models.security, 'nemotron-3-nano:30b');
    assert.notEqual(backendFor('onprem').models.security, backendFor('onprem').models.triage);
    process.env.OLLAMA_SECURITY_MODEL = 'own-security:2b';
    assert.equal(backendFor('onprem').models.security, 'own-security:2b');
    process.env.INFERENCE_MODEL_SECURITY = 'explicit:3b';
    assert.equal(backendFor('onprem').models.security, 'explicit:3b');
  } finally {
    for (const [k, v] of [['INFERENCE_MODEL_SECURITY', saved.sec], ['OLLAMA_SECURITY_MODEL', saved.ollama], ['OLLAMA_PRIMARY_MODEL', saved.primary]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test('infer sends the security model for the security role', async () => {
  const bodies: Array<Record<string, unknown>> = [];
  setBackendFetchForTests((async (_url: unknown, init: any) => {
    bodies.push(JSON.parse(init.body));
    return { ok: true, json: async () => ({ choices: [{ message: { content: '{"a":1}' } }] }) };
  }) as any);
  await new OpenAICompatGateway().infer({ ...req, role: 'security' });
  assert.equal(bodies.at(0)?.model, 'nemotron-3-nano:30b');
});

test('infer returns schema-validated output with usage', async () => {
  mockFetch({ model: 'm', choices: [{ message: { content: '{"a":1}' } }], usage: { prompt_tokens: 3, completion_tokens: 4 } });
  const r = await new OpenAICompatGateway().infer(req);
  assert.deepEqual(r.output, { a: 1 });
  assert.equal(r.usage.promptTokens, 3);
  assert.equal(r.fallback, false);
});

test('infer rejects output violating the schema and non-JSON', async () => {
  mockFetch({ choices: [{ message: { content: '{"b":1}' } }] });
  await assert.rejects(new OpenAICompatGateway().infer(req), /violates schema/);
  mockFetch({ choices: [{ message: { content: 'nope' } }] });
  await assert.rejects(new OpenAICompatGateway().infer(req), /not valid JSON/);
  mockFetch({}, false);
  await assert.rejects(new OpenAICompatGateway().infer(req), /HTTP 500/);
});

test('Ollama disables reasoning by default, honors overrides, and leaves vLLM unchanged', async () => {
  const saved = {
    gatewayUrl: process.env.INFERENCE_GATEWAY_URL,
    effort: process.env.INFERENCE_REASONING_EFFORT,
  };
  const bodies: Array<Record<string, unknown>> = [];
  setBackendFetchForTests((async (_url: unknown, init: any) => {
    bodies.push(JSON.parse(init.body));
    return { ok: true, json: async () => ({ choices: [{ message: { content: '{"a":1}' } }] }) };
  }) as any);
  try {
    delete process.env.INFERENCE_REASONING_EFFORT;
    await new OpenAICompatGateway().infer(req);
    assert.equal(bodies[0].reasoning_effort, 'none');

    process.env.INFERENCE_REASONING_EFFORT = 'low';
    await new OpenAICompatGateway().infer(req);
    assert.equal(bodies[1].reasoning_effort, 'low');

    process.env.INFERENCE_GATEWAY_URL = 'http://vllm:8000/v1';
    await new OpenAICompatGateway().infer({ ...req, profile: 'cloud' });
    assert.equal('reasoning_effort' in bodies[2], false);
  } finally {
    setBackendFetchForTests();
    if (saved.gatewayUrl === undefined) delete process.env.INFERENCE_GATEWAY_URL; else process.env.INFERENCE_GATEWAY_URL = saved.gatewayUrl;
    if (saved.effort === undefined) delete process.env.INFERENCE_REASONING_EFFORT; else process.env.INFERENCE_REASONING_EFFORT = saved.effort;
  }
});

test('cecurAI goes through the injected gateway', async () => {
  process.env.CS3_PROFILE = 'onprem';
  const calls: string[] = [];
  const mock: InferenceGateway = {
    describe: () => ({ backend: 'mock', baseUrl: '', models: { triage: 'x', forensic: 'y', security: 'z' } }),
    infer: async (r) => {
      calls.push(r.role);
      return {
        output: { aiSummary: 'S', mitreAnalysis: 'M', recommendedPlaybook: [] },
        model: { name: 'x', digest: '', quantization: '', backend: 'mock' },
        usage: { promptTokens: 0, completionTokens: 0, gpuSeconds: 0 },
        guardrail: { passed: true, violations: [] },
        latencyMs: 1,
        fallback: false,
      };
    },
  };
  setGateway(mock);
  const { generateIncidentAnalysisWithAI } = await import('../../server/ai/cecurAI');
  const out = await generateIncidentAnalysisWithAI({ id: 'i', title: 't', severity: 'HIGH', category: 'c', mitreTactic: 'x', mitreTechnique: 'y', affectedAssets: ['a'], rootCause: 'r', playbookSteps: [] } as any);
  assert.equal(out.aiSummary, 'S');
  assert.deepEqual(calls, ['forensic']);
  setGateway(null);
});

test('remediation propagates its isolated timeout and no-retry policy and preserves AI provenance', async () => {
  process.env.CS3_PROFILE = 'onprem';
  setGuardModel(null);
  let seen: InferenceRequest | undefined;
  const mock: InferenceGateway = {
    describe: () => ({ backend: 'mock', baseUrl: '', models: { triage: 'x', forensic: 'y', security: 'z' } }),
    infer: async (request) => {
      seen = request;
      return {
        output: {
          executiveSummary: 'Upgrade after review.',
          patchSteps: ['Review', 'Upgrade', 'Verify'],
          bashScript: '#!/bin/bash\n# ROLLBACK\napt-get install --only-upgrade example=1.0\napt-get install --only-upgrade example\n',
          powerShellScript: '# ROLLBACK\nWrite-Host "Use the vendor package"\n',
          ansiblePlaybook: '---\n- hosts: all\n  tasks: []\n  rescue: []\n',
          exploitMitigationWorkaround: 'Restrict exposure until patched.',
        },
        model: { name: 'x', digest: '', quantization: '', backend: 'mock' },
        usage: { promptTokens: 0, completionTokens: 0, gpuSeconds: 0 },
        guardrail: { passed: true, violations: [] }, latencyMs: 1, fallback: false,
      };
    },
  };
  setGateway(mock);
  try {
    const { generateVulnerabilityRemediationAI } = await import('../../server/ai/cecurAI');
    const out = await generateVulnerabilityRemediationAI({
      cve: 'CVE-2026-0001', title: 'Finding', package: 'example', installedVersion: '1.0',
      fixedVersion: '1.1', agentOs: 'Ubuntu 22.04', cvss: 7.5,
    }, { timeoutMs: 3_600_000, retries: 0, maxTokens: 4096 });
    assert.equal(out.source, 'ai');
    assert.equal(out.engineUsed.includes('Inference'), true);
    assert.equal(seen?.options?.timeoutMs, 3_600_000);
    assert.equal(seen?.options?.retries, 0);
    assert.equal(seen?.options?.maxTokens, 4096);
  } finally {
    setGateway(null);
    setGuardModel(undefined);
  }
});

test('incomplete AI remediation becomes explicit deterministic fallback without heuristic AI labeling', async () => {
  process.env.CS3_PROFILE = 'onprem';
  setGuardModel(null);
  setGateway({
    describe: () => ({ backend: 'mock', baseUrl: '', models: { triage: 'x', forensic: 'y', security: 'z' } }),
    infer: async () => ({
      output: { executiveSummary: 'Incomplete', patchSteps: ['Upgrade'] },
      model: { name: 'x', digest: '', quantization: '', backend: 'mock' },
      usage: { promptTokens: 0, completionTokens: 0, gpuSeconds: 0 },
      guardrail: { passed: true, violations: [] }, latencyMs: 1, fallback: false,
    }),
  });
  try {
    const { generateVulnerabilityRemediationAI } = await import('../../server/ai/cecurAI');
    const out = await generateVulnerabilityRemediationAI({
      cve: 'CVE-2026-0001', title: 'Finding', package: 'example', installedVersion: '1.0',
      fixedVersion: '1.1', agentOs: 'Ubuntu 22.04', cvss: 7.5,
    });
    assert.equal(out.source, 'deterministic');
    assert.equal(out.engineUsed, 'Cecur Native Security Playbook Generator');
  } finally {
    setGateway(null);
    setGuardModel(undefined);
  }
});

test('no Gemini/DeepSeek SDK or endpoint is referenced in server code', () => {
  const walk = (d: string): string[] =>
    readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : f.endsWith('.ts') ? [join(d, f)] : []));
  for (const f of walk('server')) {
    assert.doesNotMatch(readFileSync(f, 'utf8'), /@google\/genai|api\.deepseek\.com|GEMINI_API_KEY/, f);
  }
});
