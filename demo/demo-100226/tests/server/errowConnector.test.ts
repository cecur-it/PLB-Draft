import { after, afterEach, before, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { Server } from 'node:http';
import { once } from 'node:events';
import { db } from '../../server/db';
import {
  ErrowUnavailableError,
  getErrowStatus,
  refreshErrowJob,
  runErrowScan,
} from '../../server/connectors/errowClient';
import type { TargetAllowlistEntry } from '../../src/types';

const target: TargetAllowlistEntry = {
  id: 'tgt-errow-test',
  hostname: 'target.example.invalid',
  ipRange: '192.0.2.0/24',
  ownerDepartment: 'Lab',
  authorizedBy: 'Integration Test',
  authorizationDate: '2026-01-01',
  status: 'AUTHORIZED',
  notes: 'Loopback connector test only; no target traffic is generated.',
  scanCount: 0,
};

let server: Server;
let connectorUrl = '';
let postStatus = 200;
let postDocument: any = {};
let getDocument: any = {};
const originalTargets = [...db.targetAllowlist];
const originalJobs = [...db.errowJobs];
const originalEnv = {
  baseUrl: process.env.ERROW_BASE_URL,
  apiKey: process.env.ERROW_API_KEY,
  mode: process.env.ERROW_MODE,
  runtime: process.env.ERROW_SANDBOX_RUNTIME,
};

before(async () => {
  const remote = express();
  remote.use(express.json());
  remote.post('/api/tasks', (_req, res) => res.status(postStatus).json(postDocument));
  remote.get('/api/tasks/:id', (_req, res) => res.json(getDocument));
  server = remote.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  connectorUrl = `http://127.0.0.1:${address.port}`;
});

beforeEach(() => {
  process.env.ERROW_BASE_URL = connectorUrl;
  delete process.env.ERROW_API_KEY;
  delete process.env.ERROW_MODE;
  delete process.env.ERROW_SANDBOX_RUNTIME;
  postStatus = 200;
  postDocument = {};
  getDocument = {};
  target.scanCount = 0;
  delete target.lastScanned;
  db.targetAllowlist.splice(0, db.targetAllowlist.length, target);
  db.errowJobs.splice(0, db.errowJobs.length);
});

afterEach(() => {
  db.targetAllowlist.splice(0, db.targetAllowlist.length);
  db.errowJobs.splice(0, db.errowJobs.length);
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.targetAllowlist.splice(0, db.targetAllowlist.length, ...originalTargets);
  db.errowJobs.splice(0, db.errowJobs.length, ...originalJobs);
  for (const [key, value] of Object.entries(originalEnv)) {
    const envKey = { baseUrl: 'ERROW_BASE_URL', apiKey: 'ERROW_API_KEY', mode: 'ERROW_MODE', runtime: 'ERROW_SANDBOX_RUNTIME' }[key]!;
    if (value === undefined) delete process.env[envKey];
    else process.env[envKey] = value;
  }
});

test('Errow status distinguishes configuration from verification and does not invent integrations', () => {
  delete process.env.ERROW_BASE_URL;
  const empty = getErrowStatus();
  assert.equal(empty.mode, 'UNCONFIGURED');
  assert.equal(empty.agentMode, 'unconfigured');
  assert.equal(empty.sandboxRuntime, 'unconfigured');
  assert.equal(empty.verified, false);
  assert.equal(empty.reachability, 'UNVERIFIED');
  assert.deepEqual(empty.integrations, { caido: false, projectdiscovery: false });

  process.env.ERROW_BASE_URL = connectorUrl;
  process.env.ERROW_API_KEY = 'test-only-key';
  const configured = getErrowStatus();
  assert.equal(configured.mode, 'CONFIGURED');
  assert.equal(configured.agentMode, 'remote');
  assert.equal(configured.credentialConfigured, true);
  assert.equal(configured.verified, false);
  assert.equal(configured.reachability, 'UNVERIFIED');
  assert.equal(configured.persistence.durable, false);
});

test('unconfigured Errow scans are refused before jobs or scan counters change', async () => {
  delete process.env.ERROW_BASE_URL;
  await assert.rejects(
    runErrowScan(target.hostname, target.id, 'nmap_scan', 'integration-admin'),
    ErrowUnavailableError,
  );
  assert.equal(db.errowJobs.length, 0);
  assert.equal(target.scanCount, 0);
});

test('remote queued and running states advance only when polling returns a terminal result', async () => {
  postDocument = { id: 'remote-task-1', status: 'queued' };
  const job = await runErrowScan(target.hostname, target.id, 'nmap_scan', 'integration-admin');
  assert.equal(job.status, 'QUEUED');
  assert.equal(job.source, 'ERROW_REMOTE');
  assert.equal(job.remoteTaskId, 'remote-task-1');
  assert.equal(job.findingsCount, 0);

  getDocument = { id: 'remote-task-1', status: 'running' };
  await refreshErrowJob(job);
  assert.equal(job.status, 'RUNNING');

  getDocument = {
    id: 'remote-task-1',
    status: 'completed',
    findings: [
      { id: 'finding-1', title: 'Observed service', severity: 'HIGH', port: 443 },
      { id: 'finding-2', name: 'Unclassified observation', risk: 'unexpected' },
    ],
  };
  await refreshErrowJob(job);
  assert.equal(job.status, 'COMPLETED');
  assert.equal(job.findingsCount, 2);
  assert.equal(job.findings[0].severity, 'HIGH');
  assert.equal(job.findings[1].severity, 'INFO');
  assert.ok(job.completedAt);
});

test('missing and unknown remote statuses fail instead of fabricating completion', async () => {
  postDocument = {};
  const missing = await runErrowScan(target.hostname, target.id, 'nmap_scan', 'integration-admin');
  assert.equal(missing.status, 'FAILED');
  assert.match(missing.error || '', /missing or unrecognized task status/i);

  postDocument = { id: 'remote-task-2', status: 'mystery' };
  const unknown = await runErrowScan(target.hostname, target.id, 'nmap_scan', 'integration-admin');
  assert.equal(unknown.status, 'FAILED');
  assert.match(unknown.error || '', /mystery/);
  assert.ok(db.errowJobs.every((job) => job.status !== 'COMPLETED'));
});

test('HTTP and explicit remote failures remain failed jobs with no simulated findings', async () => {
  postStatus = 503;
  postDocument = { message: 'connector unavailable' };
  const unavailable = await runErrowScan(target.hostname, target.id, 'nmap_scan', 'integration-admin');
  assert.equal(unavailable.status, 'FAILED');
  assert.match(unavailable.error || '', /HTTP 503/);
  assert.equal(unavailable.findingsCount, 0);

  postStatus = 200;
  postDocument = { id: 'remote-task-3', status: 'failed', message: 'remote rejected task' };
  const rejected = await runErrowScan(target.hostname, target.id, 'nmap_scan', 'integration-admin');
  assert.equal(rejected.status, 'FAILED');
  assert.equal(rejected.error, 'remote rejected task');
  assert.equal(rejected.findingsCount, 0);
});
