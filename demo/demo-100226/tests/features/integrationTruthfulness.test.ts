import { after, afterEach, before, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { Server } from 'node:http';
import { once } from 'node:events';
import { db } from '../../server/db';
import { signToken } from '../../server/middleware/auth';
import { activtrakRouter } from '../../server/routes/activtrak';
import { sensorsRouter } from '../../server/routes/sensors';
import { errowRouter } from '../../server/routes/errow';
import { authRouter } from '../../server/routes/auth';
import type { SensorNode, User } from '../../src/types';

const admin: User = {
  id: 'usr-integration-admin',
  username: 'integration-admin',
  email: 'integration-admin@example.invalid',
  passwordHash: 'not-used-by-bearer-authentication',
  role: 'admin',
  displayName: 'Integration Administrator',
  title: 'Administrator',
  department: 'Test',
  avatar: '/avatars/av-2.svg',
  createdAt: '2026-01-01T00:00:00.000Z',
  lastLogin: '2026-01-01T00:00:00.000Z',
};
const analyst: User = { ...admin, id: 'usr-integration-analyst', username: 'integration-analyst', role: 'analyst' };
const sensor: SensorNode = {
  id: 'sensor-integration-test',
  name: 'Integration Test Sensor',
  location: 'Lab',
  ipAddress: '192.0.2.10',
  type: 'dmz_tap',
  status: 'ONLINE',
  packetRate: 0,
  droppedPackets: 0,
  jitterMs: 0,
  anomalyRate: 0,
  cpuUsage: 0,
  memoryUsage: 0,
  lastPing: '2026-01-01T00:00:00.000Z',
  firmwareVersion: 'test',
  alerts24h: 0,
};

let server: Server;
let baseUrl = '';
let adminToken = '';
let analystToken = '';
const originalUsers = [...db.users];
const originalSensors = [...db.sensors];
const originalTargets = [...db.targetAllowlist];
const originalJwtSecret = process.env.JWT_SECRET;

before(async () => {
  process.env.JWT_SECRET = 'integration-test-only-jwt-secret';
  db.users.splice(0, db.users.length, admin, analyst);
  adminToken = signToken(admin);
  analystToken = signToken(analyst);

  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRouter);
  app.use('/api/activtrak', activtrakRouter);
  app.use('/api/sensors', sensorsRouter);
  app.use('/api/errow', errowRouter);
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(() => {
  mock.restoreAll();
  db.users.splice(0, db.users.length, admin, analyst);
  db.sensors.splice(0, db.sensors.length);
  db.targetAllowlist.splice(0, db.targetAllowlist.length);
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.users.splice(0, db.users.length, ...originalUsers);
  db.sensors.splice(0, db.sensors.length, ...originalSensors);
  db.targetAllowlist.splice(0, db.targetAllowlist.length, ...originalTargets);
  if (originalJwtSecret === undefined) delete process.env.JWT_SECRET;
  else process.env.JWT_SECRET = originalJwtSecret;
});

function request(path: string, token: string, init: RequestInit = {}) {
  return fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init.headers || {}) },
  });
}

test('ActivTrak API identifies process-local, nonexternal, nondurable telemetry', async () => {
  const response = await request('/api/activtrak', adminToken);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.total, body.sessions.length);
  assert.deepEqual(body.provenance, {
    source: 'LOCAL_IN_MEMORY',
    persistent: false,
    externalApiConnected: false,
    message: body.provenance.message,
  });
  assert.match(body.provenance.message, /No external ActivTrak API is connected/);
});

test('sensor calibration returns audited 501 and never claims a remote action occurred', async (t) => {
  db.sensors.push(sensor);
  const audits: any[] = [];
  t.mock.method(db, 'logAudit', (entry: any) => {
    audits.push(entry);
    return entry;
  });

  const response = await request(`/api/sensors/${sensor.id}/calibrate`, adminToken, { method: 'POST' });
  assert.equal(response.status, 501);
  const body = await response.json();
  assert.equal(body.code, 'SENSOR_MANAGEMENT_UNAVAILABLE');
  assert.equal(body.performed, false);
  assert.match(body.message, /was not performed/i);
  assert.equal(audits.length, 1);
  assert.equal(audits[0].status, 'ERROR');
  assert.match(audits[0].details, /not performed/i);
});

test('Errow allowlist mutation fails closed when its critical audit is not durable', async (t) => {
  t.mock.method(db, 'logAuditCritical', async () => ({
    durable: true,
    persisted: false,
    timedOut: false,
  }));

  const response = await request('/api/errow/allowlist', adminToken, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostname: 'target.example.invalid', ipRange: '192.0.2.0/24', ownerDepartment: 'Lab' }),
  });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.mutated, false);
  assert.equal(db.targetAllowlist.length, 0);
});

test('operator registration attributes audit to the administrator and returns no credential hash', async (t) => {
  const audits: any[] = [];
  t.mock.method(db, 'logAuditCritical', async (entry: any) => {
    audits.push(entry);
    return { durable: true, persisted: true, timedOut: false };
  });

  const response = await request('/api/auth/register', adminToken, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'created-operator',
      email: 'created-operator@example.invalid',
      password: 'test-only-password',
      role: 'analyst',
      displayName: 'Created Operator',
    }),
  });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal('passwordHash' in body.user, false);
  assert.equal(audits.length, 1);
  assert.equal(audits[0].actorId, admin.id);
  assert.equal(audits[0].actorUsername, admin.username);
  assert.match(audits[0].targetResource, /created-operator/);
});

test('nonadministrators cannot read the account registry', async () => {
  const response = await request('/api/auth/users', analystToken);
  assert.equal(response.status, 403);
  const body = await response.json();
  assert.equal(body.action, 'manage_users');
});
