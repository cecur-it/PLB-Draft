import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateSensorEps } from '../../src/lib/telemetry';

test('EPS is zero without sensor telemetry and excludes offline sensors', () => {
  assert.equal(calculateSensorEps(undefined), 0);
  assert.equal(calculateSensorEps([]), 0);
  assert.equal(calculateSensorEps([
    { status: 'ONLINE', packetRate: 12 },
    { status: 'OFFLINE', packetRate: 984200 },
    { status: 'DEGRADED', packetRate: 8 },
  ]), 20);
});
