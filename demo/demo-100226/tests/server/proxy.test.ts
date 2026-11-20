import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveTrustProxyHops } from '../../server/proxy';

test('direct development trusts no forwarded headers by default', () => {
  assert.equal(resolveTrustProxyHops(undefined), 0);
  assert.equal(resolveTrustProxyHops(''), 0);
});

test('Compose can trust exactly one known proxy hop', () => {
  assert.equal(resolveTrustProxyHops('1'), 1);
  assert.equal(resolveTrustProxyHops(' 2 '), 2);
});

test('permissive or invalid proxy settings fail closed', () => {
  for (const value of ['-1', '1.5', '6', 'true', 'loopback']) {
    assert.throws(() => resolveTrustProxyHops(value), /between 0 and 5/);
  }
});
