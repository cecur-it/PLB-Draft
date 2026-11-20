import { test } from 'node:test';
import assert from 'node:assert/strict';
import { calculateHotCacheEpsEstimate, summarizeSensorHealth } from '../../server/cecur/overviewMetrics';

const now = new Date('2026-01-01T00:01:00.000Z');

test('empty hot-cache EPS is explicit no-data, not live fleet throughput', () => {
  const estimate = calculateHotCacheEpsEstimate([], now);
  assert.equal(estimate.name, 'cecur_hot_cache_60s_eps');
  assert.equal(estimate.source, 'db.cecurLogs');
  assert.equal(estimate.cache, 'in_memory_hot_cache');
  assert.equal(estimate.windowSeconds, 60);
  assert.equal(estimate.value, 0);
  assert.equal(estimate.eventCount, 0);
  assert.equal(estimate.latestEventAt, null);
  assert.equal(estimate.status, 'no_data');
  assert.equal(estimate.stale, false);
  assert.equal(estimate.windowStart, '2026-01-01T00:00:00.000Z');
  assert.equal(estimate.windowEnd, now.toISOString());
});

test('stale hot-cache data is distinguishable from an empty cache', () => {
  const estimate = calculateHotCacheEpsEstimate([
    { timestamp: '2025-12-31T23:59:59.000Z' },
  ], now);
  assert.equal(estimate.status, 'stale');
  assert.equal(estimate.stale, true);
  assert.equal(estimate.cacheEventCount, 1);
  assert.equal(estimate.eventCount, 0);
  assert.equal(estimate.value, 0);
  assert.equal(estimate.latestEventAt, '2025-12-31T23:59:59.000Z');
});

test('EPS uses only valid events inside the named trailing 60-second window', () => {
  const estimate = calculateHotCacheEpsEstimate([
    { timestamp: '2026-01-01T00:00:59.000Z' },
    { timestamp: '2026-01-01T00:00:01.000Z' },
    { timestamp: '2025-12-31T23:59:59.000Z' },
    { timestamp: 'not-a-timestamp' },
  ], now);
  assert.equal(estimate.status, 'current');
  assert.equal(estimate.stale, false);
  assert.equal(estimate.eventCount, 2);
  assert.equal(estimate.cacheEventCount, 4);
  assert.equal(estimate.value, 0.03);
  assert.equal(estimate.latestEventAt, '2026-01-01T00:00:59.000Z');
});

test('sensor health has no-data, offline, degraded, and operational semantics', () => {
  assert.deepEqual(summarizeSensorHealth([]), {
    total: 0, online: 0, degraded: 0, offline: 0, status: 'NO_SENSORS',
  });
  assert.equal(summarizeSensorHealth([{ status: 'OFFLINE' }]).status, 'OFFLINE');
  assert.equal(summarizeSensorHealth([
    { status: 'ONLINE' }, { status: 'DEGRADED' }, { status: 'OFFLINE' },
  ]).status, 'DEGRADED');
  assert.deepEqual(summarizeSensorHealth([{ status: 'ONLINE' }, { status: 'ONLINE' }]), {
    total: 2, online: 2, degraded: 0, offline: 0, status: 'OPERATIONAL',
  });
});
