import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  InMemoryRemediationJobStore,
  RemediationJobService,
  remediationTimeoutMs,
  validateRemediationVulnerability,
  vulnerabilityFingerprint,
} from '../../server/cecur/remediationJobs';
import type { CecurRemediationJob, CecurRemediationResult, CecurVulnerability } from '../../src/types';

const owner = { id: 'user-1', username: 'analyst' };
const vulnerability = (id = 'vuln-1'): CecurVulnerability => ({
  id,
  cve: id === 'vuln-1' ? 'CVE-2026-0001' : 'CVE-2026-0002',
  title: 'Test finding',
  package: 'example-package',
  installedVersion: '1.0',
  fixedVersion: '1.1',
  severity: 'HIGH',
  cvss: 7.5,
  status: 'VULNERABLE',
  agentId: 'agent-1',
  agentName: 'endpoint-1',
  agentOs: 'Ubuntu 22.04',
  detectionDate: '2026-11-17T00:00:00Z',
  exploitAvailable: false,
  remediationGuide: 'Upgrade the package.',
  compliance: ['NIST'],
});

const result = (source: 'ai' | 'deterministic'): CecurRemediationResult => ({
  executiveSummary: 'Review and upgrade.',
  patchSteps: ['Review', 'Upgrade', 'Verify'],
  bashScript: '#!/bin/bash\n# ROLLBACK\napt-get install --only-upgrade example-package\n',
  powerShellScript: '# ROLLBACK\nWrite-Host "Review vendor guidance"\n',
  ansiblePlaybook: '---\n- hosts: all\n  tasks: []\n  rescue: []\n',
  exploitMitigationWorkaround: 'Restrict exposure.',
  engineUsed: source === 'ai' ? 'CECUR-IT Inference (test-model)' : 'Cecur Native Security Playbook Generator',
  source,
});

async function waitFor(predicate: () => Promise<boolean> | boolean, message: string): Promise<void> {
  const deadline = Date.now() + 1000;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail(message);
}

test('duplicate submissions share one job and generation is strictly sequential', async () => {
  const store = new InMemoryRemediationJobStore();
  const releases: Array<() => void> = [];
  let calls = 0;
  let active = 0;
  let maxActive = 0;
  const service = new RemediationJobService(store, async () => {
    calls++;
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise<void>((resolve) => releases.push(resolve));
    active--;
    return result('ai');
  }, 60_000);
  await service.start();
  try {
    const [first, duplicate] = await Promise.all([
      service.submit(owner, vulnerability()),
      service.submit(owner, vulnerability()),
    ]);
    const second = await service.submit(owner, vulnerability('vuln-2'));
    await waitFor(() => calls === 1, 'first generation did not start');
    assert.equal(first.deduplicated, false);
    assert.equal(duplicate.deduplicated, true);
    assert.equal(duplicate.job.id, first.job.id);
    assert.notEqual(second.job.id, first.job.id);
    assert.equal((await service.getOwned(second.job.id, owner.id))?.status, 'queued');
    releases.shift()!();
    await waitFor(() => calls === 2, 'second generation did not start after the first completed');
    releases.shift()!();
    await waitFor(async () => (await service.getOwned(second.job.id, owner.id))?.status === 'completed', 'second job did not complete');
    assert.equal(calls, 2);
    assert.equal(maxActive, 1);
  } finally {
    await service.stop();
  }
});

test('restart marks uncertain running work interrupted and never retries it automatically', async () => {
  const store = new InMemoryRemediationJobStore();
  let release!: () => void;
  let restartedCalls = 0;
  const firstWorker = new RemediationJobService(store, async () => {
    await new Promise<void>((resolve) => { release = resolve; });
    return result('ai');
  }, 60_000);
  await firstWorker.start();
  const { job } = await firstWorker.submit(owner, vulnerability());
  await waitFor(async () => (await firstWorker.getOwned(job.id, owner.id))?.status === 'running', 'job did not enter running state');

  const restartedWorker = new RemediationJobService(store, async () => {
    restartedCalls++;
    return result('ai');
  }, 60_000);
  await restartedWorker.start();
  const interrupted = await restartedWorker.getOwned(job.id, owner.id);
  assert.equal(interrupted?.status, 'interrupted');
  assert.match(interrupted?.message ?? '', /not retried automatically/);
  release();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal((await restartedWorker.getOwned(job.id, owner.id))?.status, 'interrupted');
  assert.equal(restartedCalls, 0);
  await firstWorker.stop();
  await restartedWorker.stop();
});

test('a persisted queued job resumes once because it was never dispatched', async () => {
  const store = new InMemoryRemediationJobStore();
  const vuln = vulnerability();
  const now = new Date().toISOString();
  const queued: CecurRemediationJob = {
    id: 'remediation-queued', ownerId: owner.id, ownerUsername: owner.username,
    vulnerability: vuln, fingerprint: vulnerabilityFingerprint(vuln), status: 'queued',
    timeoutMs: 60_000, createdAt: now, updatedAt: now,
  };
  assert.equal(await store.create(queued), null);
  let calls = 0;
  const service = new RemediationJobService(store, async (_vuln, options) => {
    calls++;
    assert.deepEqual(options, { timeoutMs: 60_000, retries: 0, maxTokens: 4096 });
    return result('ai');
  }, 60_000);
  await service.start();
  try {
    await waitFor(async () => (await service.getOwned(queued.id, owner.id))?.status === 'completed', 'queued job did not resume');
    assert.equal(calls, 1);
  } finally {
    await service.stop();
  }
});

test('fallback provenance is terminal and failures do not expose internal errors', async () => {
  const fallbackStore = new InMemoryRemediationJobStore();
  const fallbackService = new RemediationJobService(fallbackStore, async () => result('deterministic'), 60_000);
  await fallbackService.start();
  const fallback = await fallbackService.submit(owner, vulnerability());
  await waitFor(async () => (await fallbackService.getOwned(fallback.job.id, owner.id))?.status === 'fallback', 'fallback state was not stored');
  const fallbackJob = await fallbackService.getOwned(fallback.job.id, owner.id);
  assert.equal(fallbackJob?.remediation?.source, 'deterministic');
  assert.equal(fallbackJob?.remediation?.engineUsed, 'Cecur Native Security Playbook Generator');
  await fallbackService.stop();

  const failedService = new RemediationJobService(new InMemoryRemediationJobStore(), async () => {
    throw new Error('sensitive internal transport detail');
  }, 60_000);
  await failedService.start();
  const failed = await failedService.submit(owner, vulnerability());
  await waitFor(async () => (await failedService.getOwned(failed.job.id, owner.id))?.status === 'failed', 'failure state was not stored');
  const failedJob = await failedService.getOwned(failed.job.id, owner.id);
  assert.doesNotMatch(failedJob?.message ?? '', /sensitive internal/);
  await failedService.stop();
});

test('job reads and active recovery enforce ownership; malformed findings are rejected', async () => {
  const store = new InMemoryRemediationJobStore();
  let release!: () => void;
  const service = new RemediationJobService(store, async () => {
    await new Promise<void>((resolve) => { release = resolve; });
    return result('ai');
  }, 60_000);
  await service.start();
  await assert.rejects(service.submit(owner, { cve: 'CVE-2026-0001' }), /vulnerability object|vulnerability\./);
  const { job } = await service.submit(owner, vulnerability());
  assert.equal(await service.getOwned(job.id, 'another-user'), null);
  assert.equal(await service.getActive('another-user', vulnerability().id), null);
  assert.equal((await service.getActive(owner.id, vulnerability().id))?.id, job.id);
  release();
  await service.stop();
});

test('remediation timeout is bounded and independent of the synchronous default', () => {
  assert.equal(remediationTimeoutMs(undefined), 3_600_000);
  assert.equal(remediationTimeoutMs('7200000'), 7_200_000);
  assert.throws(() => remediationTimeoutMs('0'), /1000 to 7200000/);
  assert.throws(() => remediationTimeoutMs('not-a-number'), /1000 to 7200000/);
  assert.throws(() => validateRemediationVulnerability({}), /vulnerability\./);
});
