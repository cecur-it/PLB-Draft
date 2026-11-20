import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { FairShareScheduler } from '../../server/inference/scheduler';
import { OllamaBackend } from '../../server/inference/backends/ollama';
import { VllmBackend } from '../../server/inference/backends/vllm';
import { setBackendFetchForTests } from '../../server/inference/backends/base';
import { OpenAICompatGateway } from '../../server/inference/gateway';

const tick = () => new Promise((r) => setTimeout(r, 5));

test('per-tenant concurrency cap is enforced', async () => {
  const s = new FairShareScheduler(2);
  let cur = 0, max = 0;
  const job = async () => { cur++; max = Math.max(max, cur); await tick(); cur--; };
  await Promise.all(Array.from({ length: 8 }, () => s.run('a', job)));
  assert.equal(max, 2);
  assert.deepEqual(s.stats(), { active: 0, queued: 0 });
});

test('a busy tenant does not starve another (global cap 1, round-robin)', async () => {
  const s = new FairShareScheduler(1, 1);
  const order: string[] = [];
  const job = (t: string) => s.run(t, async () => { order.push(t); await tick(); });
  const all = [job('a'), job('a'), job('a'), job('b')];
  await Promise.all(all);
  assert.ok(order.indexOf('b') <= 2, order.join());
});

test('core transport honors the total deadline before headers and prevents retry amplification', async () => {
  setBackendFetchForTests();
  let calls = 0;
  const server = createServer((_req, res) => {
    calls++;
    setTimeout(() => res.end('{"choices":[]}'), 150);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const backend = new OllamaBackend(`http://127.0.0.1:${address.port}/v1`, { timeoutMs: 20, retries: 2, retryDelayMs: 1 });
  const started = Date.now();
  try {
    await assert.rejects(backend.chat({}), /request failed|total deadline/);
    assert.equal(calls, 1);
    assert.ok(Date.now() - started < 150, 'request must abort before the delayed response and not retry');
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('backend retries 5xx, not 4xx; health uses backend-specific URLs', async () => {
  let n = 0;
  const urls: string[] = [];
  setBackendFetchForTests((async (u: string) => {
    urls.push(String(u)); n++;
    if (String(u).endsWith('/chat/completions')) return n < 3 ? { ok: false, status: 503 } : { ok: true, json: async () => ({ ok: 1 }) };
    return { ok: true };
  }) as any);
  const o = new OllamaBackend('http://h:11434/v1', { retryDelayMs: 1 });
  assert.deepEqual(await o.chat({}), { ok: 1 });
  assert.equal(n, 3);
  assert.equal(await o.health(), true);
  assert.ok(urls.at(-1)!.endsWith(':11434/api/tags'));
  const v = new VllmBackend('http://g/v1', { retryDelayMs: 1 });
  await v.health();
  assert.ok(urls.at(-1)!.endsWith('/v1/models'));
  n = 0;
  setBackendFetchForTests((async () => { n++; return { ok: false, status: 400 }; }) as any);
  await assert.rejects(v.chat({}), /HTTP 400/);
  assert.equal(n, 1);
});

test('per-request deadline overrides the synchronous default without retry amplification', async () => {
  setBackendFetchForTests();
  let calls = 0;
  const server = createServer((_req, res) => {
    calls++;
    setTimeout(() => res.end('{"choices":[]}'), 150);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const savedBaseUrl = process.env.OLLAMA_BASE_URL;
  process.env.OLLAMA_BASE_URL = `http://127.0.0.1:${address.port}/v1`;
  const gateway = new OpenAICompatGateway(5000);
  try {
    await assert.rejects(gateway.infer({
      role: 'triage', profile: 'onprem', tenantId: 'test', incidentId: 'per-request-deadline',
      dataClassification: 'internal', input: { system: 'Return JSON', user: 'Return {}' },
      options: { timeoutMs: 20, retries: 0, maxTokens: 8 },
    }), /request failed|total deadline/);
    assert.equal(calls, 1);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    if (savedBaseUrl === undefined) delete process.env.OLLAMA_BASE_URL; else process.env.OLLAMA_BASE_URL = savedBaseUrl;
  }
});
