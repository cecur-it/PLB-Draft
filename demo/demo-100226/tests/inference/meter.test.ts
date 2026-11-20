import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GasLedger, computeGpuSeconds, creditsFor, setLedger, getLedger } from '../../server/inference/meter';
import { routeInference, setGuardModel } from '../../server/inference/router';
import { setGateway } from '../../server/inference/gateway';
import type { InferenceRequest, InferenceResponse } from '../../server/inference/types';

const req = (tenantId = 't1'): InferenceRequest => ({
  role: 'triage', profile: 'onprem', tenantId, incidentId: 'i', dataClassification: 'internal', input: { system: 's', user: 'u' },
});
const res = (gpuSeconds: number, fallback = false): InferenceResponse => ({
  output: { ok: 1 }, model: { name: 'm', digest: '', quantization: '', backend: 'b' },
  usage: { promptTokens: 999, completionTokens: 999, gpuSeconds }, guardrail: { passed: true, violations: [] }, latencyMs: 1, fallback,
});

test('credits are charged per GPU-second, not per token, and reconcile with the ledger', () => {
  const l = new GasLedger();
  l.grant('t1', 100);
  const fixtures = [1.5, 0.25, 3, 0.0004];
  for (const g of fixtures) l.record(req(), res(g));
  const expected = fixtures.reduce((a, g) => a + creditsFor(g), 0);
  assert.equal(l.usage('t1').gpuSeconds, 4.75);
  assert.equal(l.balance('t1'), Math.round((100 - expected) * 1000) / 1000);
  assert.equal(l.list('t1').at(-1)!.credits, -0.001); // rounded up, never free
  assert.equal(l.list('t1').length, 5);
});

test('rate is configurable; fallback answers cost nothing; tenants are isolated', () => {
  process.env.GAS_CREDITS_PER_GPU_SECOND = '2';
  assert.equal(creditsFor(1.5), 3);
  delete process.env.GAS_CREDITS_PER_GPU_SECOND;
  const l = new GasLedger();
  assert.equal(l.record(req(), res(5, true)), null);
  l.record(req('a'), res(1));
  assert.equal(l.balance('b'), 0);
  assert.ok(l.balance('a') < 0 && l.list('a')[0].overdraft);
});

test('computeGpuSeconds prefers backend-reported value, else scaled wall-clock', () => {
  assert.equal(computeGpuSeconds(2000, 0.8), 0.8);
  assert.equal(computeGpuSeconds(2000), 2);
  process.env.INFERENCE_GPU_SHARE = '0.5';
  assert.equal(computeGpuSeconds(2000), 1);
  delete process.env.INFERENCE_GPU_SHARE;
});

test('router charges the ledger exactly usage.gpuSeconds, even when a guardrail rejects', async () => {
  setLedger(new GasLedger());
  setGuardModel(null);
  setGateway({ infer: async () => res(2), describe: () => ({}) } as any);
  await routeInference(req('t9'));
  assert.equal(getLedger().usage('t9').gpuSeconds, 2);
  assert.equal(getLedger().balance('t9'), -2);
  setGateway({ infer: async () => ({ ...res(1), output: { s: 'rm -rf /' } }) } as any);
  const r = await routeInference(req('t9'));
  assert.equal(r.fallback, true);
  assert.equal(getLedger().usage('t9').gpuSeconds, 3);
  setGuardModel(undefined);
});
