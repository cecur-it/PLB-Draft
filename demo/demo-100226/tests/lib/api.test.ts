import { afterEach, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, apiRequest } from '../../src/lib/api';

const originalFetch = globalThis.fetch;
const originalLocalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');

beforeEach(() => {
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: { getItem: () => null },
  });
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalLocalStorage) {
    Object.defineProperty(globalThis, 'localStorage', originalLocalStorage);
  } else {
    Reflect.deleteProperty(globalThis, 'localStorage');
  }
});

test('API HTTP errors identify the method and path without exposing query values', async () => {
  globalThis.fetch = async () => new Response('upstream unavailable', { status: 502 });

  await assert.rejects(
    apiRequest('/api/cecur/status?probe=do-not-log'),
    (error: any) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 502);
      assert.equal(error.message, 'GET /api/cecur/status: HTTP Error 502');
      assert.doesNotMatch(error.message, /do-not-log/);
      return true;
    },
  );
});

test('API network failures identify the operation that could not be reached', async () => {
  globalThis.fetch = async () => {
    throw new TypeError('socket closed');
  };

  await assert.rejects(
    apiRequest('/api/cecur/ai/remediate-vuln', { method: 'POST' }),
    /POST \/api\/cecur\/ai\/remediate-vuln: socket closed/,
  );
});
