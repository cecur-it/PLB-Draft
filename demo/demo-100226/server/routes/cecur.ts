import { Router, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { db } from '../db';
import { auditDegraded, recordCriticalAudit } from '../auditOutcome';
import { requireAuth, requireRole, requirePanel, AuthenticatedRequest } from '../middleware/auth';
import { cecurEngine } from '../engine/cecurEngine';
import { getBackendFirestore, getResolvedFirebaseConfig, isFirestoreEnabled } from '../firestoreSync';
import { doc, setDoc } from 'firebase/firestore';
import {
  analyzeLogAnomalyWithAI,
  analyzeFIMEventWithAI,
  analyzeComplianceGapsWithAI,
  getAIStatus,
} from '../ai/cecurAI';
import { requireIngestKey, refreshAgentConnectivity } from '../fleet/enrollment';
import { eligibleAgents, expireStaleJobs, queueScans } from '../scans/jobs';
import { isIndexerEnabled, bulkIndexLogEvents } from '../integrations/opensearchSink';
import { CecurActiveResponseRequest, CecurLogEvent, CecurScanKind } from '../../src/types';
import { ingestManagerAlerts, looksLikeManagerAlert } from '../cecur/managerAlerts';
import { getRemediationJobService, RemediationJobError } from '../cecur/remediationJobs';
import { loadAssets } from '../assets/plbAssets';
import { resolveAsset } from '../assets/resolution';

export const cecurRouter = Router();

// -------------------------------------------------------------
// 1. CECUR SERVER & INDEXER DIAGNOSTICS
// -------------------------------------------------------------
cecurRouter.get('/status', requireAuth, requirePanel('cecur'), async (req: AuthenticatedRequest, res: Response) => {
  refreshAgentConnectivity();
  expireStaleJobs();
  res.json(await cecurEngine.getStatus(db.cecurAgents, db.cecurLogs, db.cecurScanJobs));
});

cecurRouter.get('/decoders', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  res.json({
    total: cecurEngine.decoders.length,
    decoders: cecurEngine.decoders,
  });
});

cecurRouter.get('/rules', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  res.json({
    total: cecurEngine.rulesCatalog.length,
    rules: cecurEngine.rulesCatalog,
  });
});

// -------------------------------------------------------------
// 2. AGENTS & FLEET MANAGEMENT
// -------------------------------------------------------------
cecurRouter.get('/agents', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  const { workload, status, search } = req.query;

  refreshAgentConnectivity();
  let agents = [...db.cecurAgents];

  if (workload && typeof workload === 'string' && workload !== 'all') {
    agents = agents.filter((a) => a.workloadType === workload);
  }

  if (status && typeof status === 'string' && status !== 'all') {
    agents = agents.filter((a) => a.status === status);
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    agents = agents.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.hostname.toLowerCase().includes(q) ||
        a.ip.includes(q) ||
        a.os.name.toLowerCase().includes(q) ||
        a.group.some((g) => g.toLowerCase().includes(q))
    );
  }

  res.json({
    total: agents.length,
    agents,
  });
});

cecurRouter.get('/agents/:id', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  const agent = db.cecurAgents.find((a) => a.id === req.params.id);
  if (!agent) {
    res.status(404).json({ error: 'Agent not found' });
    return;
  }
  res.json(agent);
});

const SCAN_COMMANDS: Record<string, CecurScanKind> = { 'trigger-fim-scan': 'fim', 'trigger-sca-scan': 'sca' };

// Active response. Scan commands are queued for the agent to run on its host. Containment commands (isolate, drop-ip,
// terminate, restart) need an agent-side enforcement channel that does not exist yet, so they are refused rather than
// reported as done: the console never claims a host was isolated unless the agent says so.
cecurRouter.post(
  '/agents/:id/action',
  requireAuth,
  requireRole(['admin', 'analyst']),
  requirePanel('cecur'),
  async (req: AuthenticatedRequest, res: Response) => {
    const agent = db.cecurAgents.find((a) => a.id === req.params.id);
    if (!agent) {
      res.status(404).json({ error: `Cecur Agent '${req.params.id}' not registered in fleet.` });
      return;
    }

    const { command, targetIp, processName } = req.body as CecurActiveResponseRequest;
    if (!command) {
      res.status(400).json({ error: 'Active response command is required.' });
      return;
    }

    const audit = (status: 'SUCCESS' | 'ERROR', details: string) =>
      recordCriticalAudit(res, {
        actorId: req.user!.id,
        actorUsername: req.user!.username,
        actorRole: req.user!.role,
        action: `CECUR_ACTIVE_RESPONSE_${String(command).toUpperCase()}`,
        panel: 'cecur',
        targetResource: `${agent.name} (${agent.ip})`,
        ipAddress: req.ip || '127.0.0.1',
        status,
        details: `${details}${targetIp ? ` target-ip=${targetIp}` : ''}${processName ? ` process=${processName}` : ''}`,
      });

    const kind = SCAN_COMMANDS[command];
    if (!kind) {
      const message = `'${command}' is not supported: agents have no enforcement channel yet, so no action was taken on ${agent.name}.`;
      await audit('ERROR', message);
      res.status(501).json({ error: 'Not Implemented', message });
      return;
    }

    const [job] = queueScans(kind, [agent], req.user!.username);
    const outcome = await audit(
      'SUCCESS',
      `Queued ${kind} scan ${job.id} (state ${job.status}); results are reported by the agent.`
    );
    if (auditDegraded(outcome)) {
      res.status(503).json({
        error: 'Audit Ledger Unavailable',
        message: `Scan ${job.id} was queued but its audit record is not durable.`,
        auditUnavailable: true,
        job,
      });
      return;
    }
    res.status(202).json({ success: true, agentId: agent.id, agentName: agent.name, job });
  }
);

// -------------------------------------------------------------
// 3. SIEM LOG MANAGEMENT & INGESTION
// -------------------------------------------------------------
cecurRouter.get('/logs', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  const { source, severity, anomalyOnly, search, limit } = req.query;

  let logs = [...db.cecurLogs];

  if (source && typeof source === 'string' && source !== 'all') {
    logs = logs.filter((l) => l.source === source);
  }

  if (severity && typeof severity === 'string' && severity !== 'all') {
    logs = logs.filter((l) => l.severity === severity);
  }

  if (anomalyOnly === 'true') {
    logs = logs.filter((l) => l.isAnomaly);
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    logs = logs.filter((l) => l.message.toLowerCase().includes(q) || l.agentName.toLowerCase().includes(q));
  }

  const max = limit ? parseInt(limit as string, 10) : 100;
  res.json({
    total: logs.length,
    logs: logs.slice(0, max),
  });
});

const MAX_INGEST_BATCH = Number(process.env.CS3_INGEST_MAX_BATCH) || 1000;

// Manager alert intake. Vendetta's manager is the decision point; this only adapts its structured
// alerts into CecurAlert rows (see server/cecur/managerAlerts.ts). Fail closed: a batch that cannot be
// stored returns 503 so Fluent Bit retries instead of dropping the alert, and replayed batches are
// deduplicated rather than doubled.
cecurRouter.post('/manager/alerts', requireIngestKey, async (req: AuthenticatedRequest, res: Response) => {
  const body = req.body;
  const events: any[] = Array.isArray(body) ? body : Array.isArray(body?.events) ? body.events : body ? [body] : [];
  if (events.length === 0) {
    res.status(400).json({ error: 'At least one manager alert is required.' });
    return;
  }
  if (events.length > MAX_INGEST_BATCH) {
    res.status(413).json({ error: `Batch too large; at most ${MAX_INGEST_BATCH} alerts per request.` });
    return;
  }

  const outcome = ingestManagerAlerts(events);

  // Nothing adapted is a producer/config fault, not a transient one: fail closed so it is visible.
  if (outcome.accepted.length === 0 && outcome.duplicates === 0) {
    res.status(422).json({ error: 'No manager alert could be adapted.', rejected: outcome.rejected, reasons: outcome.reasons });
    return;
  }

  const audit = await recordCriticalAudit(res, {
    actorId: (req as any).ingestAgentId || 'vendetta-manager',
    actorUsername: 'vendetta-manager',
    actorRole: 'analyst',
    action: 'INGEST_MANAGER_ALERTS',
    panel: 'cecur',
    targetResource: `manager-alerts:${outcome.accepted.length + outcome.duplicates}`,
    ipAddress: req.ip || '127.0.0.1',
    status: 'SUCCESS',
    details: `Adapted ${outcome.accepted.length} manager alert(s), ${outcome.duplicates} duplicate(s), ${outcome.rejected} rejected`,
  });
  if (auditDegraded(audit)) {
    res.status(503).json({
      error: 'Audit Ledger Unavailable',
      message: 'Manager alerts adapted but not durably recorded; retry is safe (duplicates are deduplicated).',
      accepted: outcome.accepted.map((a) => a.id),
      duplicates: outcome.duplicates,
      rejected: outcome.rejected,
    });
    return;
  }

  res.status(201).json({
    success: true,
    accepted: outcome.accepted.length,
    duplicates: outcome.duplicates,
    rejected: outcome.rejected,
    ...(outcome.reasons.length > 0 ? { reasons: outcome.reasons } : {}),
    alertIds: outcome.accepted.map((a) => a.id),
    deduplicated: outcome.deduplicated.map((a) => a.id),
  });
});

// Accepts a single event object, a JSON array of events (Fluent Bit `Format json`),
// or { events: [...] }. Batches are capped by CS3_INGEST_MAX_BATCH (HTTP 413 above it).
cecurRouter.post('/logs/ingest', requireIngestKey, async (req, res) => {
  const body = req.body;
  const isBatch = Array.isArray(body) || (body && Array.isArray(body.events));
  const events: any[] = Array.isArray(body) ? body : isBatch ? body.events : [body];

  if (events.length > MAX_INGEST_BATCH) {
    res.status(413).json({ error: `Batch too large; at most ${MAX_INGEST_BATCH} events per request.` });
    return;
  }

  const logIds: string[] = [];
  const toDurablyIndex: CecurLogEvent[] = [];
  let rejected = 0;
  // A manager alert carries rule ID, severity and a device identity that the log shape drops. Keep it
  // an alert when it arrives on this endpoint (the `vendetta.alerts` stream used to land here as a log).
  const managerAlerts = events.filter(looksLikeManagerAlert);
  const manager = managerAlerts.length > 0 ? ingestManagerAlerts(managerAlerts) : null;
  for (const ev of events) {
    if (looksLikeManagerAlert(ev)) continue; // already adapted above
    // requireIngestKey pins agentId for per-agent keys (stored on the request, not the payload).
    const { agentName, source, message, fields, severity } = ev || {};
    const agentId: string | undefined = (req as any).ingestAgentId || ev?.agentId;
    const knownAgent = agentId ? db.cecurAgents.find((a) => a.id === agentId) : undefined;
    if (typeof message !== 'string' || !message || typeof source !== 'string' || !source) {
      rejected++;
      continue;
    }
    const lower = message.toLowerCase();
    // Keyword heuristic over the real message; it is not a trained model score.
    const isAnomaly = lower.includes('failed') || lower.includes('error') || lower.includes('tamper');
    const newLog: CecurLogEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      agentId: agentId || 'unattributed',
      agentName: agentName || knownAgent?.name || fields?.host || fields?.hostname || 'unknown-host',
      source: (source as any) || 'syslog',
      severity: severity || (isAnomaly ? 'high' : 'info'),
      message,
      fields: fields || {},
      isAnomaly,
      anomalyScore: isAnomaly ? 0.85 : 0.05,
      decoder: 'cecur-syslog',
    };
    db.cecurLogs.unshift(newLog);
    toDurablyIndex.push(newLog);
    logIds.push(newLog.id);
  }
  // db.cecurLogs is only a bounded hot cache for the console's "recent events" view.
  // Durable, unbounded storage for real on-prem fleets is the OpenSearch sink below
  // (deployment/operations/opensearch-cluster.md, ism/cs3-logs-lifecycle.json).
  if (db.cecurLogs.length > 300) db.cecurLogs = db.cecurLogs.slice(0, 300);

  let indexed = false;
  const durableIndexingEnabled = isIndexerEnabled();
  if (durableIndexingEnabled && toDurablyIndex.length > 0) {
    try {
      const indexResult = await bulkIndexLogEvents(toDurablyIndex);
      indexed = indexResult.ok && indexResult.indexed > 0;
      if (!indexResult.ok) {
        console.error('[cecur] durable indexing failed:', indexResult.error);
      }
    } catch (err) {
      console.error('[cecur] durable indexing failed:', (err as Error).message);
    }
  }

  if (manager) rejected += manager.rejected;
  const alertIds = manager ? manager.accepted.map((a) => a.id) : [];
  const duplicates = manager ? manager.duplicates : 0;

  if (logIds.length === 0 && alertIds.length === 0 && duplicates === 0) {
    res.status(400).json({ error: 'Log payload and source are required.', rejected });
    return;
  }
  if (!isBatch && alertIds.length === 0 && duplicates === 0) {
    res.status(201).json({ success: true, logId: logIds[0], indexed });
    return;
  }
  res.status(201).json({
    success: true,
    accepted: logIds.length + alertIds.length,
    duplicates,
    rejected,
    indexed,
    ...(alertIds.length > 0 ? { alertIds } : {}),
  });
});

// -------------------------------------------------------------
// 4. SIEM & XDR THREAT DETECTION ALERTS
// -------------------------------------------------------------
cecurRouter.get('/alerts', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  const { category, minLevel, status, search } = req.query;

  let alerts = [...db.cecurAlerts];

  if (category && typeof category === 'string' && category !== 'all') {
    alerts = alerts.filter((a) => a.category === category);
  }

  if (minLevel && !isNaN(Number(minLevel))) {
    alerts = alerts.filter((a) => a.ruleLevel >= Number(minLevel));
  }

  if (status && typeof status === 'string' && status !== 'all') {
    alerts = alerts.filter((a) => a.status === status);
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    alerts = alerts.filter(
      (a) =>
        a.ruleTitle.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.agentName.toLowerCase().includes(q) ||
        a.mitreTechnique?.toLowerCase().includes(q)
    );
  }

  res.json({
    total: alerts.length,
    alerts,
  });
});

cecurRouter.patch(
  '/alerts/:id/status',
  requireAuth,
  requireRole(['admin', 'analyst']),
  requirePanel('cecur'),
  async (req: AuthenticatedRequest, res: Response) => {
    const { status } = req.body;
    const alert = db.cecurAlerts.find((a) => a.id === req.params.id);
    if (!alert) {
      res.status(404).json({ error: 'Alert not found' });
      return;
    }

    if (!['new', 'investigating', 'resolved', 'suppressed'].includes(status)) {
      res.status(400).json({ error: 'Invalid status' });
      return;
    }

    alert.status = status;

    const outcome = await recordCriticalAudit(res, {
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      actorRole: req.user!.role,
      action: 'UPDATE_CECUR_ALERT_STATUS',
      panel: 'cecur',
      targetResource: alert.id,
      ipAddress: req.ip || '127.0.0.1',
      status: 'SUCCESS',
      details: `Changed Cecur alert ${alert.id} status to ${status}`,
    });
    if (auditDegraded(outcome)) {
      res.status(503).json({ error: 'Audit Ledger Unavailable', message: 'Alert status changed but not durable.', alert });
      return;
    }

    res.json({ success: true, alert });
  }
);

// -------------------------------------------------------------
// 5. VULNERABILITY DETECTION (CVE DATABASE & AUDITING)
// -------------------------------------------------------------
cecurRouter.get('/vulnerabilities', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  const { severity, status, search } = req.query;

  let vulns = [...db.cecurVulnerabilities];

  if (severity && typeof severity === 'string' && severity !== 'all') {
    vulns = vulns.filter((v) => v.severity === severity);
  }

  if (status && typeof status === 'string' && status !== 'all') {
    vulns = vulns.filter((v) => v.status === status);
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    vulns = vulns.filter((v) => v.cve.toLowerCase().includes(q) || v.title.toLowerCase().includes(q) || v.package.toLowerCase().includes(q));
  }

  res.json({
    total: vulns.length,
    vulnerabilities: vulns,
  });
});

// Shared handler: queues a real scan task for one agent (body.agentId) or every active enrolled agent.
const queueScanHandler =
  (kind: CecurScanKind, label: string) => (req: AuthenticatedRequest, res: Response) => {
    const agentId = typeof req.body?.agentId === 'string' ? req.body.agentId : undefined;
    const agents = eligibleAgents(agentId);
    const audit = (status: 'SUCCESS' | 'ERROR', details: string) =>
      db.logAudit({
        actorId: req.user!.id,
        actorUsername: req.user!.username,
        actorRole: req.user!.role,
        action: `TRIGGER_${kind.toUpperCase()}_SCAN`,
        panel: 'cecur',
        targetResource: agentId ? `Agent ${agentId}` : 'All active agents',
        ipAddress: req.ip || '127.0.0.1',
        status,
        details,
      });

    if (agents.length === 0) {
      const message = agentId
        ? `Agent '${agentId}' is not enrolled.`
        : 'No active enrolled agents. Enroll endpoints (deployment/agents) before running scans.';
      audit('ERROR', `${label} not queued: ${message}`);
      res.status(409).json({ error: 'No scan targets', message });
      return;
    }

    const jobs = queueScans(kind, agents, req.user!.username);
    audit('SUCCESS', `Queued ${label} for ${jobs.length} agent(s): ${jobs.map((j) => j.id).join(', ')}. Results are reported by the agents.`);
    res.status(202).json({
      success: true,
      message: `${label} queued for ${jobs.length} agent(s). Results appear when each agent reports back.`,
      jobs,
    });
  };

cecurRouter.post(
  '/vulnerabilities/scan',
  requireAuth,
  requireRole(['admin', 'analyst']),
  requirePanel('cecur'),
  queueScanHandler('vuln', 'Vulnerability scan')
);

cecurRouter.get('/scan-jobs', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  expireStaleJobs();
  const limit = Math.min(Math.max(parseInt(String(req.query.limit ?? '50'), 10) || 50, 1), 500);
  res.json({ total: db.cecurScanJobs.length, jobs: db.cecurScanJobs.slice(0, limit) });
});

// -------------------------------------------------------------
// 6. FILE INTEGRITY MONITORING (FIM)
// -------------------------------------------------------------
cecurRouter.get('/fim', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  const { tamperOnly, search } = req.query;

  let fims = [...db.cecurFIMEvents];

  if (tamperOnly === 'true') {
    fims = fims.filter((f) => f.isTamperAlert);
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    fims = fims.filter((f) => f.path.toLowerCase().includes(q) || f.agentName.toLowerCase().includes(q));
  }

  res.json({
    total: fims.length,
    fimEvents: fims,
  });
});

cecurRouter.post(
  '/fim/scan',
  requireAuth,
  requireRole(['admin', 'analyst']),
  requirePanel('cecur'),
  queueScanHandler('fim', 'FIM baseline scan')
);

// -------------------------------------------------------------
// 7. SECURITY CONFIGURATION ASSESSMENT (SCA / CIS BENCHMARKS)
// -------------------------------------------------------------
cecurRouter.get('/sca', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  res.json({
    totalScans: db.cecurSCAScans.length,
    scans: db.cecurSCAScans,
  });
});

cecurRouter.post(
  '/sca/run',
  requireAuth,
  requireRole(['admin', 'analyst']),
  requirePanel('cecur'),
  queueScanHandler('sca', 'CIS configuration assessment')
);

// -------------------------------------------------------------
// 8. REGULATORY COMPLIANCE MATRIX (PCI DSS, HIPAA, GDPR, NIST)
// -------------------------------------------------------------
cecurRouter.get('/compliance', requireAuth, requirePanel('cecur'), (req: AuthenticatedRequest, res: Response) => {
  res.json({
    standards: db.cecurCompliance,
  });
});

// -------------------------------------------------------------
// 9. AI ENDPOINTS (routed through the inference gateway)
// -------------------------------------------------------------
cecurRouter.post('/ai/analyze-log', requireAuth, requirePanel('cecur'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { logMessage, source, agentName, agentOs, anomalyScore, agentId, agentIp, hostname, ip, fields } = req.body;
    if (typeof logMessage !== 'string' || !logMessage.trim()) {
      res.status(400).json({ error: 'logMessage is required' });
      return;
    }

    const enrolledAgent = typeof agentId === 'string'
      ? db.cecurAgents.find((agent) => agent.id === agentId)
      : typeof agentName === 'string'
        ? db.cecurAgents.find((agent) => agent.name === agentName || agent.hostname === agentName)
        : undefined;
    const resolvedAgentName = typeof agentName === 'string' && agentName.trim()
      ? agentName
      : enrolledAgent?.name ?? 'unknown-host';
    const resolvedAgentIp = typeof agentIp === 'string' ? agentIp : enrolledAgent?.ip;
    const structuredFields = fields && typeof fields === 'object' && !Array.isArray(fields)
      ? fields as Record<string, unknown>
      : undefined;
    const inventory = loadAssets();
    const assetContext = resolveAsset({
      logMessage,
      agentId: typeof agentId === 'string' ? agentId : enrolledAgent?.id,
      agentName: resolvedAgentName,
      agentIp: resolvedAgentIp,
      hostname: typeof hostname === 'string' ? hostname : undefined,
      ip: typeof ip === 'string' ? ip : undefined,
      fields: structuredFields,
    }, {
      inventory: inventory.assets,
      agents: db.cecurAgents,
      inventorySource: inventory.source,
      inventoryError: inventory.error,
    });

    const analysis = await analyzeLogAnomalyWithAI({
      logMessage,
      source: typeof source === 'string' && source ? source : 'syslog',
      agentName: resolvedAgentName,
      agentOs: typeof agentOs === 'string' && agentOs ? agentOs : enrolledAgent?.os.name ?? 'unknown',
      anomalyScore: typeof anomalyScore === 'number' ? anomalyScore : 0,
    }, assetContext);

    res.json({ success: true, analysis });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'AI analysis failed' });
  }
});

function remediationRouteError(res: Response, error: unknown): void {
  if (error instanceof RemediationJobError) {
    res.status(error.statusCode).json({ error: 'Remediation job unavailable', message: error.message });
    return;
  }
  console.error('[remediation] request failed:', error instanceof Error ? error.message : 'unknown error');
  res.status(500).json({ error: 'Remediation job request failed', message: 'The durable remediation request could not be completed.' });
}

cecurRouter.get('/ai/remediate-vuln/jobs/active', requireAuth, requirePanel('cecur'), async (req: AuthenticatedRequest, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const vulnerabilityId = req.query.vulnerabilityId;
    if (typeof vulnerabilityId !== 'string' || !vulnerabilityId) {
      res.status(400).json({ error: 'vulnerabilityId is required' });
      return;
    }
    const job = await getRemediationJobService().getActive(req.user!.id, vulnerabilityId);
    if (!job) {
      res.status(404).json({ error: 'No active remediation job' });
      return;
    }
    res.json({ success: true, job });
  } catch (error) {
    remediationRouteError(res, error);
  }
});

cecurRouter.get('/ai/remediate-vuln/jobs/:id', requireAuth, requirePanel('cecur'), async (req: AuthenticatedRequest, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const job = await getRemediationJobService().getOwned(req.params.id, req.user!.id);
    if (!job) {
      res.status(404).json({ error: 'Remediation job not found' });
      return;
    }
    res.json({ success: true, job });
  } catch (error) {
    remediationRouteError(res, error);
  }
});

cecurRouter.post('/ai/remediate-vuln', requireAuth, requirePanel('cecur'), async (req: AuthenticatedRequest, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const { job, deduplicated } = await getRemediationJobService().submit(req.user!, req.body?.vulnerability);
    db.logAudit({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      actorRole: req.user!.role,
      action: 'QUEUE_AI_VULNERABILITY_REMEDIATION',
      panel: 'cecur',
      targetResource: job.id,
      ipAddress: req.ip || '127.0.0.1',
      status: 'SUCCESS',
      details: `${deduplicated ? 'Returned existing' : 'Queued'} remediation job ${job.id} for ${job.vulnerability.cve} on ${job.vulnerability.agentId}; state=${job.status}.`,
    });
    res.status(202).json({ success: true, deduplicated, job });
  } catch (error) {
    remediationRouteError(res, error);
  }
});

cecurRouter.post('/ai/fim-triage', requireAuth, requirePanel('cecur'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { path, eventType, oldHash, newHash, user, processName, agentName } = req.body;
    if (!path) {
      res.status(400).json({ error: 'path is required' });
      return;
    }

    const triage = await analyzeFIMEventWithAI({
      path,
      eventType: eventType || 'MODIFIED',
      oldHash,
      newHash,
      user,
      processName,
      agentName: agentName || 'endpoint-01',
    });

    res.json({ success: true, triage });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'FIM triage failed' });
  }
});

cecurRouter.post('/ai/compliance-gap', requireAuth, requirePanel('cecur'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { standardId, failedChecksCount, topGaps } = req.body;
    const briefing = await analyzeComplianceGapsWithAI(
      standardId || 'PCI_DSS',
      typeof failedChecksCount === 'number' ? failedChecksCount : 5,
      Array.isArray(topGaps) ? topGaps : ['Patch cadence', 'Access control']
    );

    res.json({ success: true, briefing });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Compliance AI failed' });
  }
});

cecurRouter.get('/ai/status', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  res.json(getAIStatus());
});

// -------------------------------------------------------------
// 10. ENTERPRISE PRICING & FIRESTORE CHECKOUT
// -------------------------------------------------------------
cecurRouter.get('/pricing/config', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const cfg = getResolvedFirebaseConfig();
  res.json({
    projectId: cfg.projectId,
    firestoreDatabaseId: cfg.firestoreDatabaseId,
    apiKeyMasked: cfg.apiKey ? `${cfg.apiKey.substring(0, 7)}...${cfg.apiKey.substring(cfg.apiKey.length - 4)}` : 'NOT_CONFIGURED',
    status: isFirestoreEnabled() ? 'ACTIVE_CONFIGURED' : 'DEGRADED',
  });
});

cecurRouter.post('/pricing/checkout', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const {
      type,
      tierId,
      tierName,
      amountUSD,
      billingCycle,
      aiCreditsPurchased,
      paymentMethod,
      billingOrg,
    } = req.body;

    if (!type || !tierId || typeof amountUSD !== 'number') {
      res.status(400).json({ error: 'Invalid checkout parameters. type, tierId, and amountUSD are required.' });
      return;
    }

    const cfg = getResolvedFirebaseConfig();
    const txId = `tx-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    const createdAt = new Date().toISOString();

    const transactionRecord = {
      id: txId,
      type,
      tierId,
      tierName: tierName || 'Enterprise Subscription',
      amountUSD,
      billingCycle: billingCycle || 'MONTHLY',
      aiCreditsPurchased: typeof aiCreditsPurchased === 'number' ? aiCreditsPurchased : 0,
      paymentMethod: paymentMethod || 'credit_card',
      billingOrg: billingOrg || 'Enterprise Operator',
      operatorEmail: req.user!.email,
      operatorUsername: req.user!.username,
      operatorRole: req.user!.role,
      firebaseProjectId: cfg.projectId,
      firestoreDatabaseId: cfg.firestoreDatabaseId,
      status: 'COMPLETED',
      createdAt,
    };

    // 1. Sync transaction to Firestore backend
    if (isFirestoreEnabled()) {
      try {
        const firestore = getBackendFirestore();
        await setDoc(doc(firestore, 'transactions', txId), transactionRecord, { merge: true });
      } catch (fsErr) {
        console.warn('[PricingCheckout] Firestore sync notice:', fsErr);
      }
    }

    // 2. Log audit trail
    db.logAudit({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      actorRole: req.user!.role,
      action: `PRICING_CHECKOUT_${type.toUpperCase()}`,
      panel: 'pricing',
      targetResource: `${tierName || tierId} ($${amountUSD.toFixed(2)})`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'SUCCESS',
      details: `Processed ${type} payment of $${amountUSD.toFixed(2)} USD via ${paymentMethod || 'credit_card'}. ${isFirestoreEnabled() ? `Synced to Firestore project '${cfg.projectId}'.` : 'Firestore sync disabled for this deployment profile.'}`,
    });

    res.status(201).json({
      success: true,
      message: isFirestoreEnabled()
        ? 'Transaction successfully processed and persisted to Firestore.'
        : 'Transaction successfully processed and recorded in the audit ledger.',
      transaction: transactionRecord,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Payment checkout processing failed' });
  }
});

