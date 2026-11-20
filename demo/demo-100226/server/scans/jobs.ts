import { randomUUID } from 'node:crypto';
import { db } from '../db';
import type {
  CecurAgent,
  CecurAlert,
  CecurFIMEvent,
  CecurSCACheck,
  CecurSCAScan,
  CecurScanJob,
  CecurScanKind,
  CecurVulnerability,
} from '../../src/types';

/**
 * Scan task queue. The console never fabricates scan output: an operator request becomes a queued job for an
 * enrolled agent, the agent claims it, runs the scan on its own host, and posts back what it actually observed.
 */

const QUEUED_TTL_MS = () => (Number(process.env.CS3_SCAN_QUEUED_TTL_MINUTES) || 60) * 60_000;
const RUNNING_TTL_MS = () => (Number(process.env.CS3_SCAN_RUNNING_TTL_MINUTES) || 30) * 60_000;
const MAX_JOBS_KEPT = 500;
const MAX_ITEMS = 5000;

/** Marks jobs the agent never claimed or never finished as timed out so the UI does not show them as pending forever. */
export function expireStaleJobs(now = Date.now()): void {
  for (const job of db.cecurScanJobs) {
    if (job.status === 'queued' && now - Date.parse(job.requestedAt) > QUEUED_TTL_MS()) {
      job.status = 'timeout';
      job.completedAt = new Date(now).toISOString();
      job.error = 'No agent claimed this job before it expired (agent offline or not polling for tasks).';
    } else if (job.status === 'running' && now - Date.parse(job.startedAt ?? job.requestedAt) > RUNNING_TTL_MS()) {
      job.status = 'timeout';
      job.completedAt = new Date(now).toISOString();
      job.error = 'Agent claimed this job but did not report results in time.';
    }
  }
}

export function eligibleAgents(agentId?: string): CecurAgent[] {
  if (agentId) {
    const a = db.cecurAgents.find((x) => x.id === agentId);
    return a ? [a] : [];
  }
  return db.cecurAgents.filter((a) => a.status === 'active');
}

/** Queues one job per target agent; an agent with an in-flight job of the same kind is returned as-is rather than duplicated. */
export function queueScans(kind: CecurScanKind, agents: CecurAgent[], requestedBy: string): CecurScanJob[] {
  expireStaleJobs();
  const out: CecurScanJob[] = [];
  for (const agent of agents) {
    const existing = db.cecurScanJobs.find(
      (j) => j.agentId === agent.id && j.kind === kind && (j.status === 'queued' || j.status === 'running')
    );
    if (existing) {
      out.push(existing);
      continue;
    }
    const job: CecurScanJob = {
      id: `scan-${randomUUID()}`,
      kind,
      agentId: agent.id,
      agentName: agent.name,
      status: 'queued',
      requestedBy,
      requestedAt: new Date().toISOString(),
    };
    db.cecurScanJobs.unshift(job);
    out.push(job);
  }
  if (db.cecurScanJobs.length > MAX_JOBS_KEPT) db.cecurScanJobs.length = MAX_JOBS_KEPT;
  return out;
}

/** Hands the agent its queued jobs and marks them running. */
export function claimJobs(agentId: string): CecurScanJob[] {
  expireStaleJobs();
  const claimed = db.cecurScanJobs.filter((j) => j.agentId === agentId && j.status === 'queued');
  const now = new Date().toISOString();
  for (const j of claimed) {
    j.status = 'running';
    j.startedAt = now;
  }
  return claimed;
}

const str = (v: unknown, max = 512): string => (typeof v === 'string' ? v.slice(0, max) : '');
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const oneOf = <T extends string>(v: unknown, allowed: readonly T[]): T | undefined =>
  typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : undefined;

export class ScanResultError extends Error {
  constructor(message: string, public status = 400) {
    super(message);
  }
}

export interface AgentScanReport {
  jobId: string;
  status: 'completed' | 'failed';
  error?: string;
  // fim
  monitoredFiles?: number;
  events?: unknown[];
  // sca
  benchmark?: string;
  checks?: unknown[];
  // vuln
  installedPackages?: number;
  findings?: unknown[];
}

const FIM_EVENT_TYPES = ['MODIFIED', 'ADDED', 'DELETED', 'PERMISSIONS_CHANGED'] as const;
const FIM_FILE_TYPES = ['binary', 'config', 'system', 'credential', 'web_root'] as const;
const BENCHMARKS = ['CIS_Linux_2.0', 'CIS_Windows_11', 'CIS_Kubernetes_1.8', 'CIS_macOS_14'] as const;
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

function ingestFim(job: CecurScanJob, agent: CecurAgent, report: AgentScanReport) {
  const events = Array.isArray(report.events) ? report.events.slice(0, MAX_ITEMS) : [];
  const now = new Date().toISOString();
  let deviations = 0;
  for (const raw of events as Record<string, unknown>[]) {
    const path = str(raw?.path, 1024);
    const eventType = oneOf(raw?.eventType, FIM_EVENT_TYPES);
    if (!path || !eventType) continue;
    const isTamperAlert = eventType !== 'ADDED';
    const fim: CecurFIMEvent = {
      id: `fim-${randomUUID()}`,
      timestamp: now,
      agentId: agent.id,
      agentName: agent.name,
      path,
      eventType,
      fileType: oneOf(raw?.fileType, FIM_FILE_TYPES) ?? 'system',
      oldHash: str(raw?.oldHash, 128) || undefined,
      newHash: str(raw?.newHash, 128) || undefined,
      oldPerms: str(raw?.oldPerms, 16) || undefined,
      newPerms: str(raw?.newPerms, 16) || undefined,
      isTamperAlert,
      compliance: ['PCI_DSS_11.5', 'NIST_800_53_SI_7'],
    };
    db.cecurFIMEvents.unshift(fim);
    if (isTamperAlert) {
      deviations++;
      const alert: CecurAlert = {
        id: `alert-${randomUUID()}`,
        timestamp: now,
        ruleId: 10030,
        ruleLevel: fim.fileType === 'credential' || fim.fileType === 'binary' ? 12 : 8,
        ruleTitle: 'File integrity deviation against baseline',
        description: `${fim.eventType} detected on ${fim.path} by agent FIM scan ${job.id}.`,
        category: 'fim',
        agentId: agent.id,
        agentName: agent.name,
        agentIp: agent.ip,
        agentOs: agent.os.name,
        complianceTags: fim.compliance,
        decoderMatched: 'cecur-fim-agent',
        filePath: fim.path,
        hash: fim.newHash,
        fullLog: JSON.stringify(fim),
        status: 'new',
      };
      db.cecurAlerts.unshift(alert);
    }
  }
  if (db.cecurFIMEvents.length > 5000) db.cecurFIMEvents.length = 5000;
  const monitored = num(report.monitoredFiles);
  if (monitored !== undefined) agent.fimMonitoredFilesCount = monitored;
  job.summary = { filesChecked: monitored ?? 0, deviations };
}

function ingestSca(job: CecurScanJob, agent: CecurAgent, report: AgentScanReport) {
  const checks: CecurSCACheck[] = (Array.isArray(report.checks) ? report.checks.slice(0, MAX_ITEMS) : [])
    .map((raw: any, i): CecurSCACheck | null => {
      const status = oneOf(raw?.status, ['PASS', 'FAIL', 'MANUAL'] as const);
      const title = str(raw?.title, 256);
      if (!status || !title) return null;
      return {
        id: `${job.id}-c${i + 1}`,
        checkId: str(raw?.checkId, 64) || String(i + 1),
        title,
        status,
        rationale: str(raw?.rationale, 1024),
        remediation: str(raw?.remediation, 1024),
        compliance: Array.isArray(raw?.compliance) ? raw.compliance.map((c: unknown) => str(c, 64)).filter(Boolean).slice(0, 16) : [],
        section: str(raw?.section, 128),
      };
    })
    .filter((c): c is CecurSCACheck => c !== null);
  const passCount = checks.filter((c) => c.status === 'PASS').length;
  const failCount = checks.filter((c) => c.status === 'FAIL').length;
  const scored = passCount + failCount;
  const score = scored === 0 ? 0 : Math.round((passCount / scored) * 100);
  const scan: CecurSCAScan = {
    id: `sca-${job.id}`,
    benchmark: oneOf(report.benchmark, BENCHMARKS) ?? 'CIS_Linux_2.0',
    agentId: agent.id,
    agentName: agent.name,
    agentOs: agent.os.name,
    passCount,
    failCount,
    totalChecks: checks.length,
    score,
    lastScanDate: new Date().toISOString(),
    checks,
  };
  db.cecurSCAScans = [scan, ...db.cecurSCAScans.filter((s) => s.agentId !== agent.id)];
  agent.scaScore = score;
  job.summary = { checks: checks.length, passed: passCount, failed: failCount, score };
}

function ingestVuln(job: CecurScanJob, agent: CecurAgent, report: AgentScanReport) {
  const now = new Date().toISOString();
  const vulns: CecurVulnerability[] = (Array.isArray(report.findings) ? report.findings.slice(0, MAX_ITEMS) : [])
    .map((raw: any): CecurVulnerability | null => {
      const pkg = str(raw?.package, 256);
      const cve = str(raw?.cve, 64);
      if (!pkg || !cve) return null;
      return {
        id: `vuln-${randomUUID()}`,
        cve,
        title: str(raw?.title, 256) || `${cve} affects ${pkg}`,
        package: pkg,
        installedVersion: str(raw?.installedVersion, 128),
        fixedVersion: str(raw?.fixedVersion, 128),
        severity: oneOf(raw?.severity, SEVERITIES) ?? 'MEDIUM',
        cvss: num(raw?.cvss) ?? 0,
        status: 'VULNERABLE',
        agentId: agent.id,
        agentName: agent.name,
        agentOs: agent.os.name,
        detectionDate: now,
        exploitAvailable: raw?.exploitAvailable === true,
        remediationGuide: str(raw?.remediationGuide, 1024),
        compliance: ['PCI_DSS_6.2', 'NIST_800_53_RA_5'],
      };
    })
    .filter((v): v is CecurVulnerability => v !== null);
  db.cecurVulnerabilities = [...vulns, ...db.cecurVulnerabilities.filter((v) => v.agentId !== agent.id)];
  const count = (s: string) => vulns.filter((v) => v.severity === s).length;
  agent.vulnerabilitiesCount = { critical: count('CRITICAL'), high: count('HIGH'), medium: count('MEDIUM'), low: count('LOW') };
  const pkgs = num(report.installedPackages);
  if (pkgs !== undefined) agent.installedPackagesCount = pkgs;
  job.summary = { packagesEvaluated: pkgs ?? 0, findings: vulns.length };
}

/** Applies an agent-reported result. The job must belong to the authenticated agent and be in the running state. */
export function applyAgentReport(agentId: string, report: AgentScanReport): CecurScanJob {
  const job = db.cecurScanJobs.find((j) => j.id === report?.jobId);
  const agent = db.cecurAgents.find((a) => a.id === agentId);
  if (!job || !agent || job.agentId !== agentId) throw new ScanResultError('Unknown scan job for this agent.', 404);
  if (job.status !== 'running') throw new ScanResultError(`Job is ${job.status}; results are only accepted for running jobs.`, 409);

  job.completedAt = new Date().toISOString();
  if (report.status === 'failed') {
    job.status = 'failed';
    job.error = str(report.error, 1024) || 'Agent reported failure.';
    return job;
  }
  if (job.kind === 'fim') ingestFim(job, agent, report);
  else if (job.kind === 'sca') ingestSca(job, agent, report);
  else ingestVuln(job, agent, report);
  job.status = 'completed';
  return job;
}
