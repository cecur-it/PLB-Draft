import { createHash, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type {
  CecurRemediationJob,
  CecurRemediationResult,
  CecurVulnerability,
} from '../../src/types';
import { generateVulnerabilityRemediationAI } from '../ai/cecurAI';
import { getPool, isPostgresEnabled } from '../pg/pool';

export const DEFAULT_REMEDIATION_TIMEOUT_MS = 3_600_000;
const MAX_REMEDIATION_TIMEOUT_MS = 7_200_000;
const ACTIVE_STATUSES = new Set(['queued', 'running']);

export class RemediationJobError extends Error {
  constructor(message: string, readonly statusCode = 503) {
    super(message);
  }
}

export function remediationTimeoutMs(value = process.env.INFERENCE_REMEDIATION_TIMEOUT_MS): number {
  if (value === undefined || value === '') return DEFAULT_REMEDIATION_TIMEOUT_MS;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1000 || parsed > MAX_REMEDIATION_TIMEOUT_MS) {
    throw new RemediationJobError('INFERENCE_REMEDIATION_TIMEOUT_MS must be an integer from 1000 to 7200000.', 500);
  }
  return parsed;
}

function requiredString(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || !value.trim() || value.length > maxLength) {
    throw new RemediationJobError(`vulnerability.${field} must be a non-empty string of at most ${maxLength} characters.`, 400);
  }
  return value;
}

export function validateRemediationVulnerability(input: unknown): CecurVulnerability {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new RemediationJobError('A vulnerability object is required.', 400);
  }
  const value = input as Record<string, unknown>;
  const severity = requiredString(value.severity, 'severity', 16);
  const status = requiredString(value.status, 'status', 16);
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity)) {
    throw new RemediationJobError('vulnerability.severity is invalid.', 400);
  }
  if (!['VULNERABLE', 'PATCHED', 'MITIGATED'].includes(status)) {
    throw new RemediationJobError('vulnerability.status is invalid.', 400);
  }
  if (typeof value.cvss !== 'number' || !Number.isFinite(value.cvss) || value.cvss < 0 || value.cvss > 10) {
    throw new RemediationJobError('vulnerability.cvss must be a number from 0 to 10.', 400);
  }
  if (typeof value.exploitAvailable !== 'boolean') {
    throw new RemediationJobError('vulnerability.exploitAvailable must be a boolean.', 400);
  }
  if (!Array.isArray(value.compliance) || value.compliance.length > 32 ||
      value.compliance.some((entry) => typeof entry !== 'string' || entry.length > 128)) {
    throw new RemediationJobError('vulnerability.compliance must contain at most 32 strings of at most 128 characters.', 400);
  }
  return {
    id: requiredString(value.id, 'id', 256),
    cve: requiredString(value.cve, 'cve', 64),
    title: requiredString(value.title, 'title', 512),
    package: requiredString(value.package, 'package', 256),
    installedVersion: requiredString(value.installedVersion, 'installedVersion', 256),
    fixedVersion: requiredString(value.fixedVersion, 'fixedVersion', 256),
    severity: severity as CecurVulnerability['severity'],
    cvss: value.cvss,
    status: status as CecurVulnerability['status'],
    agentId: requiredString(value.agentId, 'agentId', 256),
    agentName: requiredString(value.agentName, 'agentName', 256),
    agentOs: requiredString(value.agentOs, 'agentOs', 256),
    detectionDate: requiredString(value.detectionDate, 'detectionDate', 64),
    exploitAvailable: value.exploitAvailable,
    remediationGuide: requiredString(value.remediationGuide, 'remediationGuide', 20_000),
    compliance: [...value.compliance] as string[],
  };
}

export function vulnerabilityFingerprint(vuln: CecurVulnerability): string {
  return createHash('sha256').update(JSON.stringify([
    vuln.agentId,
    vuln.cve,
    vuln.package,
    vuln.installedVersion,
    vuln.fixedVersion,
    vuln.agentOs,
  ])).digest('hex');
}

export interface RemediationJobOwner {
  id: string;
  username: string;
}

export interface RemediationJobStore {
  create(job: CecurRemediationJob): Promise<CecurRemediationJob | null>;
  findActive(ownerId: string, fingerprint: string): Promise<CecurRemediationJob | null>;
  findActiveByVulnerability(ownerId: string, vulnerabilityId: string): Promise<CecurRemediationJob | null>;
  getOwned(id: string, ownerId: string): Promise<CecurRemediationJob | null>;
  claimNextQueued(): Promise<CecurRemediationJob | null>;
  finish(id: string, patch: Partial<CecurRemediationJob>): Promise<CecurRemediationJob | null>;
  interruptRunning(): Promise<number>;
}

const INTERRUPTED_MESSAGE = 'The console stopped while generation was running or its dispatch was uncertain. The job was not retried automatically; submit a new job explicitly.';

/** Test/development adapter. Production routes use the PostgreSQL adapter below. */
export class InMemoryRemediationJobStore implements RemediationJobStore {
  readonly jobs = new Map<string, CecurRemediationJob>();

  async create(job: CecurRemediationJob): Promise<CecurRemediationJob | null> {
    const active = [...this.jobs.values()].find((candidate) =>
      candidate.ownerId === job.ownerId && candidate.fingerprint === job.fingerprint && ACTIVE_STATUSES.has(candidate.status)
    );
    if (active) return structuredClone(active);
    this.jobs.set(job.id, structuredClone(job));
    return null;
  }

  async findActive(ownerId: string, fingerprint: string): Promise<CecurRemediationJob | null> {
    return [...this.jobs.values()].find((job) =>
      job.ownerId === ownerId && job.fingerprint === fingerprint && ACTIVE_STATUSES.has(job.status)
    ) ?? null;
  }

  async findActiveByVulnerability(ownerId: string, vulnerabilityId: string): Promise<CecurRemediationJob | null> {
    return [...this.jobs.values()].find((job) =>
      job.ownerId === ownerId && job.vulnerability.id === vulnerabilityId && ACTIVE_STATUSES.has(job.status)
    ) ?? null;
  }

  async getOwned(id: string, ownerId: string): Promise<CecurRemediationJob | null> {
    const job = this.jobs.get(id);
    return job?.ownerId === ownerId ? structuredClone(job) : null;
  }

  async claimNextQueued(): Promise<CecurRemediationJob | null> {
    const job = [...this.jobs.values()]
      .filter((candidate) => candidate.status === 'queued')
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))[0];
    if (!job) return null;
    const now = new Date().toISOString();
    Object.assign(job, { status: 'running', startedAt: now, updatedAt: now });
    return structuredClone(job);
  }

  async finish(id: string, patch: Partial<CecurRemediationJob>): Promise<CecurRemediationJob | null> {
    const job = this.jobs.get(id);
    if (!job || job.status !== 'running') return null;
    Object.assign(job, patch);
    this.jobs.set(id, structuredClone(job));
    return structuredClone(job);
  }

  async interruptRunning(): Promise<number> {
    let count = 0;
    for (const job of this.jobs.values()) {
      if (job.status !== 'running') continue;
      Object.assign(job, {
        status: 'interrupted',
        message: INTERRUPTED_MESSAGE,
        updatedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
      });
      count++;
    }
    return count;
  }
}

export class PostgresRemediationJobStore implements RemediationJobStore {
  constructor(private readonly pool: Pool) {}

  async create(job: CecurRemediationJob): Promise<CecurRemediationJob | null> {
    try {
      await this.pool.query('INSERT INTO cs3.remediation_jobs (id, data) VALUES ($1, $2::jsonb)', [job.id, JSON.stringify(job)]);
      return null;
    } catch (error: any) {
      if (error?.code !== '23505') throw error;
      const active = await this.findActive(job.ownerId, job.fingerprint);
      if (active) return active;
      throw error;
    }
  }

  async findActive(ownerId: string, fingerprint: string): Promise<CecurRemediationJob | null> {
    const result = await this.pool.query(
      `SELECT data FROM cs3.remediation_jobs
       WHERE data->>'ownerId' = $1 AND data->>'fingerprint' = $2
         AND data->>'status' IN ('queued', 'running')
       ORDER BY created_at DESC LIMIT 1`,
      [ownerId, fingerprint],
    );
    return result.rows[0]?.data ?? null;
  }

  async findActiveByVulnerability(ownerId: string, vulnerabilityId: string): Promise<CecurRemediationJob | null> {
    const result = await this.pool.query(
      `SELECT data FROM cs3.remediation_jobs
       WHERE data->>'ownerId' = $1 AND data->'vulnerability'->>'id' = $2
         AND data->>'status' IN ('queued', 'running')
       ORDER BY created_at DESC LIMIT 1`,
      [ownerId, vulnerabilityId],
    );
    return result.rows[0]?.data ?? null;
  }

  async getOwned(id: string, ownerId: string): Promise<CecurRemediationJob | null> {
    const result = await this.pool.query(
      `SELECT data FROM cs3.remediation_jobs WHERE id = $1 AND data->>'ownerId' = $2`,
      [id, ownerId],
    );
    return result.rows[0]?.data ?? null;
  }

  async claimNextQueued(): Promise<CecurRemediationJob | null> {
    const now = new Date().toISOString();
    const result = await this.pool.query(
      `WITH next_job AS (
         SELECT id FROM cs3.remediation_jobs
         WHERE data->>'status' = 'queued'
         ORDER BY created_at, id
         FOR UPDATE SKIP LOCKED
         LIMIT 1
       )
       UPDATE cs3.remediation_jobs AS jobs
       SET data = jobs.data || $1::jsonb
       FROM next_job
       WHERE jobs.id = next_job.id
       RETURNING jobs.data`,
      [JSON.stringify({ status: 'running', startedAt: now, updatedAt: now })],
    );
    return result.rows[0]?.data ?? null;
  }

  async finish(id: string, patch: Partial<CecurRemediationJob>): Promise<CecurRemediationJob | null> {
    const result = await this.pool.query(
      `UPDATE cs3.remediation_jobs SET data = data || $2::jsonb
       WHERE id = $1 AND data->>'status' = 'running'
       RETURNING data`,
      [id, JSON.stringify(patch)],
    );
    return result.rows[0]?.data ?? null;
  }

  async interruptRunning(): Promise<number> {
    const now = new Date().toISOString();
    const result = await this.pool.query(
      `UPDATE cs3.remediation_jobs
       SET data = data || $1::jsonb
       WHERE data->>'status' = 'running'`,
      [JSON.stringify({ status: 'interrupted', message: INTERRUPTED_MESSAGE, updatedAt: now, completedAt: now })],
    );
    return result.rowCount ?? 0;
  }
}

type Generator = (
  vulnerability: CecurVulnerability,
  options: { timeoutMs: number; retries: number; maxTokens: number },
) => Promise<CecurRemediationResult>;

export class RemediationJobService {
  private accepting = false;
  private pumping = false;
  private kickRequested = false;
  private currentJobId: string | null = null;

  constructor(
    private readonly store: RemediationJobStore,
    private readonly generate: Generator = generateVulnerabilityRemediationAI,
    private readonly timeoutMs = remediationTimeoutMs(),
  ) {}

  async start(): Promise<void> {
    if (this.accepting) return;
    const interrupted = await this.store.interruptRunning();
    if (interrupted) console.warn(`[remediation] marked ${interrupted} uncertain running job(s) interrupted; no automatic retry`);
    this.accepting = true;
    this.kick();
  }

  async submit(owner: RemediationJobOwner, input: unknown): Promise<{ job: CecurRemediationJob; deduplicated: boolean }> {
    if (!this.accepting) throw new RemediationJobError('The durable remediation worker is not available.');
    const vulnerability = validateRemediationVulnerability(input);
    const fingerprint = vulnerabilityFingerprint(vulnerability);
    const active = await this.store.findActive(owner.id, fingerprint);
    if (active) return { job: active, deduplicated: true };
    const now = new Date().toISOString();
    const job: CecurRemediationJob = {
      id: `remediation-${randomUUID()}`,
      ownerId: owner.id,
      ownerUsername: owner.username,
      vulnerability,
      fingerprint,
      status: 'queued',
      timeoutMs: this.timeoutMs,
      createdAt: now,
      updatedAt: now,
    };
    const duplicate = await this.store.create(job);
    if (duplicate) return { job: duplicate, deduplicated: true };
    this.kick();
    return { job, deduplicated: false };
  }

  async getOwned(id: string, ownerId: string): Promise<CecurRemediationJob | null> {
    return this.store.getOwned(id, ownerId);
  }

  async getActive(ownerId: string, vulnerabilityId: string): Promise<CecurRemediationJob | null> {
    return this.store.findActiveByVulnerability(ownerId, vulnerabilityId);
  }

  private kick(): void {
    if (!this.accepting) return;
    if (this.pumping) {
      this.kickRequested = true;
      return;
    }
    this.kickRequested = false;
    this.pumping = true;
    void this.pump()
      .catch((error) => console.error('[remediation] worker persistence failure:', error instanceof Error ? error.message : 'unknown error'))
      .finally(() => {
        this.pumping = false;
        if (this.accepting && this.kickRequested) this.kick();
      });
  }

  private async pump(): Promise<void> {
    while (this.accepting) {
      const job = await this.store.claimNextQueued();
      if (!job) return;
      this.currentJobId = job.id;
      if (!this.accepting) {
        await this.store.finish(job.id, {
          status: 'interrupted',
          message: INTERRUPTED_MESSAGE,
          updatedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
        });
        this.currentJobId = null;
        return;
      }
      try {
        const remediation = await this.generate(job.vulnerability, {
          timeoutMs: job.timeoutMs,
          retries: 0,
          maxTokens: 4096,
        });
        const now = new Date().toISOString();
        await this.store.finish(job.id, {
          status: remediation.source === 'ai' ? 'completed' : 'fallback',
          remediation,
          message: remediation.source === 'ai'
            ? 'Validated AI remediation generated. Review and test it before execution; no script was run.'
            : 'AI generation was unavailable or failed validation. Deterministic guidance was stored instead; it is not AI-authored output.',
          updatedAt: now,
          completedAt: now,
        });
      } catch (error) {
        console.error(`[remediation] job ${job.id} failed:`, error instanceof Error ? error.message : 'unknown error');
        const now = new Date().toISOString();
        await this.store.finish(job.id, {
          status: 'failed',
          message: 'Remediation generation failed before a validated result could be stored. No script was run; submit a new job explicitly.',
          updatedAt: now,
          completedAt: now,
        });
      } finally {
        this.currentJobId = null;
      }
    }
  }

  async stop(): Promise<void> {
    this.accepting = false;
    if (!this.currentJobId) return;
    const now = new Date().toISOString();
    await this.store.finish(this.currentJobId, {
      status: 'interrupted',
      message: INTERRUPTED_MESSAGE,
      updatedAt: now,
      completedAt: now,
    });
  }
}

class DeferredPostgresRemediationJobStore implements RemediationJobStore {
  create(job: CecurRemediationJob) { return postgresStore().then((store) => store.create(job)); }
  findActive(ownerId: string, fingerprint: string) { return postgresStore().then((store) => store.findActive(ownerId, fingerprint)); }
  findActiveByVulnerability(ownerId: string, vulnerabilityId: string) {
    return postgresStore().then((store) => store.findActiveByVulnerability(ownerId, vulnerabilityId));
  }
  getOwned(id: string, ownerId: string) { return postgresStore().then((store) => store.getOwned(id, ownerId)); }
  claimNextQueued() { return postgresStore().then((store) => store.claimNextQueued()); }
  finish(id: string, patch: Partial<CecurRemediationJob>) { return postgresStore().then((store) => store.finish(id, patch)); }
  interruptRunning() { return postgresStore().then((store) => store.interruptRunning()); }
}

let singleton: RemediationJobService | null = null;

export function getRemediationJobService(): RemediationJobService {
  if (!isPostgresEnabled()) {
    throw new RemediationJobError('Durable remediation jobs require CS3_PERSISTENCE=postgres and DATABASE_URL.');
  }
  if (!singleton) singleton = new RemediationJobService(new DeferredPostgresRemediationJobStore());
  return singleton;
}

async function postgresStore(): Promise<PostgresRemediationJobStore> {
  const pool = await getPool();
  if (!pool) throw new RemediationJobError('PostgreSQL is not available for durable remediation jobs.');
  return new PostgresRemediationJobStore(pool);
}

export async function startRemediationJobs(): Promise<void> {
  if (!isPostgresEnabled()) return;
  await getRemediationJobService().start();
  console.log('[remediation] durable worker started');
}

export async function stopRemediationJobs(): Promise<void> {
  if (singleton) await singleton.stop();
}

/** Test seam: replace the singleton without changing production persistence requirements. */
export function setRemediationJobServiceForTests(service: RemediationJobService | null): void {
  singleton = service;
}
