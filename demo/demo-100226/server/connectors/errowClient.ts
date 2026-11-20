import { ErrowTask, ErrowFinding, ErrowMemoryPersistence, ErrowStatus } from '../../src/types';
import { db } from '../db';

export const SAFE_TOOL_PROFILES = [
  'nmap_scan',
  'nuclei_scan',
  'gobuster_scan',
  'subfinder_scan',
] as const;

export type SafeTool = typeof SAFE_TOOL_PROFILES[number];

export const ERROW_MEMORY_PERSISTENCE: ErrowMemoryPersistence = {
  storage: 'IN_MEMORY',
  durable: false,
  scopes: ['ALLOWLIST', 'JOBS'],
  message: 'Allowlist entries and scan jobs are held only in this server process; they are not durable and are lost on restart.',
};

// ERROW_MODE: embedded (local runner, default for onprem/airgap) | remote (hosted/API, cloud).
// ERROW_SANDBOX_RUNTIME: container runtime that isolates the errow-agent sandbox.
function runtimeInfo(configured: boolean) {
  return {
    agentMode: configured ? process.env.ERROW_MODE || 'remote' : 'unconfigured',
    sandboxRuntime: configured ? process.env.ERROW_SANDBOX_RUNTIME || 'docker' : 'unconfigured',
    integrations: { caido: false, projectdiscovery: false },
  };
}

export class ErrowUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ErrowUnavailableError';
  }
}

export function getErrowStatus(): ErrowStatus {
  const baseUrl = process.env.ERROW_BASE_URL?.trim() || undefined;
  const configured = Boolean(baseUrl);
  const activeScanCount = db.errowJobs.filter((j) => j.status === 'RUNNING').length;

  return {
    mode: configured ? 'CONFIGURED' : 'UNCONFIGURED',
    configured,
    credentialConfigured: Boolean(process.env.ERROW_API_KEY?.trim()),
    reachability: 'UNVERIFIED',
    verified: false,
    ...(baseUrl ? { baseUrl } : {}),
    activeScanCount,
    availableTools: SAFE_TOOL_PROFILES,
    ...runtimeInfo(configured),
    persistence: ERROW_MEMORY_PERSISTENCE,
    message: configured
      ? `Errow is configured at ${baseUrl}, but no health or authentication check has been performed. Reachability and API compatibility are unverified.`
      : 'No Errow connector is configured. Set ERROW_BASE_URL and, if required by the service, ERROW_API_KEY; no results are simulated.',
  };
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

/** Maps whatever finding objects the remote service returns onto ErrowFinding without inventing values. */
function normalizeFindings(raw: unknown, jobId: string): ErrowFinding[] {
  const list = Array.isArray(raw) ? raw : [];
  return list
    .filter((f): f is Record<string, any> => !!f && typeof f === 'object')
    .map((f, i) => {
      const sev = String(f.severity ?? f.risk ?? 'INFO').toUpperCase();
      return {
        id: String(f.id ?? `${jobId}-f${i + 1}`),
        title: String(f.title ?? f.name ?? f.template ?? 'Untitled finding'),
        severity: (SEVERITIES as readonly string[]).includes(sev) ? (sev as ErrowFinding['severity']) : 'INFO',
        cve: typeof f.cve === 'string' ? f.cve : undefined,
        cvss: typeof f.cvss === 'number' ? f.cvss : undefined,
        port: typeof f.port === 'number' ? f.port : undefined,
        endpoint: typeof f.endpoint === 'string' ? f.endpoint : undefined,
        description: String(f.description ?? ''),
        remediation: String(f.remediation ?? ''),
      };
    });
}

function authHeaders(): Record<string, string> {
  const apiKey = process.env.ERROW_API_KEY;
  return { 'Content-Type': 'application/json', ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}) };
}

const timeoutMs = () => Number(process.env.ERROW_REQUEST_TIMEOUT_MS) || 120_000;

/** Applies a remote task document to a job. Returns true when the remote task reached a terminal state. */
function applyRemoteResult(job: ErrowTask, doc: any): boolean {
  const remoteStatus = typeof doc?.status === 'string' ? doc.status.trim().toLowerCase() : '';
  job.remoteTaskId = doc?.id ?? doc?.taskId ?? job.remoteTaskId;
  const output = doc?.rawOutput ?? doc?.output ?? doc?.result;
  job.rawOutput = typeof output === 'string' ? output : JSON.stringify(doc, null, 2);
  job.findings = normalizeFindings(doc?.findings, job.id);
  job.findingsCount = job.findings.length;
  if (/^(queued|pending)$/.test(remoteStatus)) {
    job.status = 'QUEUED';
    return false;
  }
  if (/^(running|in_progress|started)$/.test(remoteStatus)) {
    job.status = 'RUNNING';
    return false;
  }
  if (/^(failed|error|cancelled|canceled)$/.test(remoteStatus)) {
    job.status = 'FAILED';
    job.error = String(doc?.error ?? doc?.message ?? `Errow reported the task as ${remoteStatus}.`);
  } else if (/^(completed|complete|succeeded|success|done)$/.test(remoteStatus)) {
    job.status = 'COMPLETED';
  } else {
    job.status = 'FAILED';
    job.error = `Errow returned a missing or unrecognized task status${remoteStatus ? `: ${remoteStatus}` : '.'}`;
  }
  job.completedAt = new Date().toISOString();
  return true;
}

function fail(job: ErrowTask, message: string): ErrowTask {
  job.status = 'FAILED';
  job.error = message;
  job.completedAt = new Date().toISOString();
  job.rawOutput = `[ERROW-CONNECTOR] ${message}`;
  return job;
}

/** Polls the remote service for jobs it accepted asynchronously. Failures leave the job unchanged. */
export async function refreshErrowJob(job: ErrowTask): Promise<void> {
  const baseUrl = process.env.ERROW_BASE_URL;
  if (!baseUrl || !job.remoteTaskId || (job.status !== 'QUEUED' && job.status !== 'RUNNING')) return;
  try {
    const resp = await fetch(`${baseUrl}/api/tasks/${encodeURIComponent(job.remoteTaskId)}`, {
      headers: authHeaders(),
      signal: AbortSignal.timeout(timeoutMs()),
    });
    if (resp.ok) applyRemoteResult(job, await resp.json());
  } catch (err: any) {
    console.warn('[Errow] Poll failed:', err.message);
  }
}

/**
 * Runs a scan through the remote Errow connector. There is no local simulation: when the connector is not
 * configured the call is rejected, and when the remote call fails the job is recorded as FAILED with the real error.
 */
export async function runErrowScan(
  targetHost: string,
  targetId: string,
  tool: SafeTool,
  triggeredBy: string
): Promise<ErrowTask> {
  const allowlistEntry = db.targetAllowlist.find(
    (t) => t.id === targetId || t.hostname.toLowerCase() === targetHost?.toLowerCase()
  );

  if (!allowlistEntry || allowlistEntry.status !== 'AUTHORIZED') {
    throw new Error(`Target '${targetHost}' is NOT authorized on the security allowlist. Scan rejected.`);
  }

  if (!SAFE_TOOL_PROFILES.includes(tool)) {
    throw new Error(`Tool profile '${tool}' is not in the approved safe reconnaissance allowlist.`);
  }

  const baseUrl = process.env.ERROW_BASE_URL;
  if (!baseUrl) {
    throw new ErrowUnavailableError('Errow connector is not configured (ERROW_BASE_URL). No scan was run and no results were simulated.');
  }

  const now = new Date().toISOString();
  const job: ErrowTask = {
    id: `task-errow-${Date.now()}`,
    targetId: allowlistEntry.id,
    targetHost: allowlistEntry.hostname,
    tool,
    status: 'RUNNING',
    startedAt: now,
    triggeredBy,
    findingsCount: 0,
    rawOutput: `[ERROW-CONNECTOR] Submitted ${tool} for ${allowlistEntry.hostname} to ${baseUrl}; awaiting remote result.`,
    findings: [],
    source: 'ERROW_REMOTE',
  };

  db.errowJobs.unshift(job);
  allowlistEntry.scanCount += 1;
  allowlistEntry.lastScanned = now;

  try {
    const resp = await fetch(`${baseUrl}/api/tasks`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ target: allowlistEntry.hostname, tool, profile: 'safe_recon' }),
      signal: AbortSignal.timeout(timeoutMs()),
    });
    if (!resp.ok) {
      const body = (await resp.text().catch(() => '')).slice(0, 500);
      return fail(job, `Errow responded HTTP ${resp.status}${body ? `: ${body}` : ''}`);
    }
    applyRemoteResult(job, await resp.json());
    return job;
  } catch (err: any) {
    console.warn('[Errow] Remote connector call failed:', err.message);
    return fail(job, `Errow connector call failed: ${err.message}`);
  }
}
