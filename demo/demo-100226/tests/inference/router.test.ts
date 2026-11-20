import { test } from 'node:test';
import assert from 'node:assert/strict';
import { routeInference, RoutingPolicyError } from '../../server/inference/router';
import { setGateway } from '../../server/inference/gateway';
import type { InferenceRequest } from '../../server/inference/types';

const base: InferenceRequest = {
  role: 'triage', profile: 'onprem', tenantId: 't', incidentId: 'i', dataClassification: 'internal',
  input: { system: 's', user: 'u' },
};
let calls = 0;
const ok = { infer: async () => { calls++; return { output: { a: 1 }, model: { name: 'm', digest: '', quantization: '', backend: 'b' }, usage: { promptTokens: 0, completionTokens: 0, gpuSeconds: 0 }, guardrail: { passed: true, violations: [] }, latencyMs: 1, fallback: false }; }, describe: () => ({ backend: 'b', baseUrl: '', models: { triage: '', forensic: '' } }) };

test('airgap answers deterministically without calling the gateway', async () => {
  setGateway(ok as any); calls = 0;
  const r = await routeInference({ ...base, profile: 'airgap' });
  assert.equal(r.fallback, true);
  assert.equal(calls, 0);
});

test('airgap forensic reaches the site node only when enabled', async () => {
  setGateway(ok as any); calls = 0;
  process.env.INFERENCE_AIRGAP_FORENSIC = 'on';
  const r = await routeInference({ ...base, profile: 'airgap', role: 'forensic' });
  assert.equal(r.fallback, false);
  delete process.env.INFERENCE_AIRGAP_FORENSIC;
  assert.equal((await routeInference({ ...base, profile: 'airgap', role: 'forensic' })).fallback, true);
});

test('gateway failure yields fallback:true', async () => {
  setGateway({ ...ok, infer: async () => { throw new Error('down'); } } as any);
  const r = await routeInference(base);
  assert.equal(r.fallback, true);
  assert.equal(r.output, null);
});

test('cui/classified are blocked from cloud', async () => {
  setGateway(ok as any); calls = 0;
  for (const dataClassification of ['cui', 'classified'] as const) {
    await assert.rejects(routeInference({ ...base, profile: 'cloud', dataClassification }), RoutingPolicyError);
  }
  assert.equal(calls, 0);
  assert.equal((await routeInference({ ...base, dataClassification: 'cui' })).fallback, false);
});
