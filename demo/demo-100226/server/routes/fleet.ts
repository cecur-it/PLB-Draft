import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { db } from '../db';
import { requireAuth, requireAction, requirePanel, AuthenticatedRequest } from '../middleware/auth';
import {
  bulkEnroll,
  claimEnrollment,
  fleetSummary,
  requireAgentKey,
  DEFAULT_TOKEN_TTL_HOURS,
  MAX_BULK_BATCH,
  MAX_TOKEN_TTL_HOURS,
} from '../fleet/enrollment';
import { loadAssets } from '../assets/plbAssets';
import { linkAssetsToTelemetry } from '../assets/linkage';
import { applyAgentReport, claimJobs, ScanResultError, type AgentScanReport } from '../scans/jobs';

export const fleetRouter = Router();

// Coarse per-IP request limiter for every fleet route (authenticated and unauthenticated alike).
const fleetLimiter = rateLimit({
  windowMs: 60_000,
  limit: Number(process.env.CS3_FLEET_RATE_LIMIT) || 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too Many Requests' },
});
fleetRouter.use(fleetLimiter);

// -------------------------------------------------------------
// Bulk enrollment (admin). Used by deployment/agents/cs3-enroll.mjs
// -------------------------------------------------------------
fleetRouter.post(
  '/enroll/bulk',
  requireAuth,
  requireAction('manage_fleet'),
  async (req: AuthenticatedRequest, res: Response) => {
    const { agents, group, ttlHours, dryRun } = req.body || {};
    if (!Array.isArray(agents) || agents.length === 0) {
      res.status(400).json({ error: 'Bad Request', message: '`agents` must be a non-empty array.' });
      return;
    }
    if (agents.length > MAX_BULK_BATCH) {
      res.status(413).json({
        error: 'Payload Too Large',
        message: `At most ${MAX_BULK_BATCH} agents per request; split the fleet into batches.`,
      });
      return;
    }
    const ttl = ttlHours === undefined ? DEFAULT_TOKEN_TTL_HOURS : Number(ttlHours);
    if (!Number.isFinite(ttl) || ttl < 1 || ttl > MAX_TOKEN_TTL_HOURS) {
      res.status(400).json({ error: 'Bad Request', message: `ttlHours must be between 1 and ${MAX_TOKEN_TTL_HOURS}.` });
      return;
    }
    const defaultGroups = (Array.isArray(group) ? group : group ? [group] : []).filter(
      (g: unknown): g is string => typeof g === 'string'
    );

    try {
      const out = await bulkEnroll({
        agents,
        defaultGroups,
        ttlHours: ttl,
        dryRun: dryRun === true,
        requestedBy: req.user!.username,
      });
      db.logAudit({
        actorId: req.user!.id,
        actorUsername: req.user!.username,
        actorRole: req.user!.role,
        action: out.dryRun ? 'FLEET_BULK_ENROLL_DRYRUN' : 'FLEET_BULK_ENROLL',
        panel: 'cecur',
        targetResource: `batch:${out.batchId}`,
        ipAddress: req.socket.remoteAddress || '127.0.0.1',
        status: 'SUCCESS',
        details: `Bulk enrollment ${out.batchId}: requested=${out.requested} enrolled=${out.enrolled} duplicates=${out.duplicates} invalid=${out.invalid}.`,
      });
      res.setHeader('Cache-Control', 'no-store');
      res.status(out.dryRun ? 200 : 201).json(out);
    } catch (err) {
      console.error('[fleet] bulk enroll failed:', (err as Error).message);
      res.status(500).json({ error: 'Internal Server Error', message: 'Enrollment could not be persisted; nothing was enrolled.' });
    }
  }
);

// -------------------------------------------------------------
// Agent self-claim: unauthenticated by design (the agent has no session);
// protected by single-use, expiring, high-entropy tokens + per-IP failure throttle.
// -------------------------------------------------------------
const failures = new Map<string, { count: number; resetAt: number }>();
const MAX_FAILURES = 20;
const WINDOW_MS = 60_000;

fleetRouter.post('/enroll/claim', async (req: Request, res: Response) => {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const f = failures.get(ip);
  if (f && f.resetAt > now && f.count >= MAX_FAILURES) {
    res.status(429).json({ error: 'Too Many Requests' });
    return;
  }
  const { agentId, token } = req.body || {};
  if (typeof agentId !== 'string' || typeof token !== 'string' || agentId.length > 64 || token.length > 128) {
    res.status(400).json({ error: 'Bad Request' });
    return;
  }
  try {
    const out = await claimEnrollment(agentId, token);
    if (!out) {
      const cur = f && f.resetAt > now ? f : { count: 0, resetAt: now + WINDOW_MS };
      cur.count++;
      failures.set(ip, cur);
      res.status(401).json({ error: 'Unauthorized', message: 'Invalid, expired or already-used enrollment token.' });
      return;
    }
    db.logAudit({
      actorId: out.agentId,
      actorUsername: out.agentId,
      actorRole: 'analyst',
      action: 'FLEET_AGENT_CLAIMED',
      panel: 'cecur',
      targetResource: `agent:${out.agentId}`,
      ipAddress: ip,
      status: 'SUCCESS',
      details: `Agent ${out.agentId} redeemed enrollment token (batch ${out.batchId}).`,
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ agentId: out.agentId, ingestKey: out.ingestKey, ingestPath: '/api/cecur/logs/ingest' });
  } catch (err) {
    console.error('[fleet] claim failed:', (err as Error).message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

fleetRouter.get('/summary', requireAuth, requirePanel('cecur'), (_req: AuthenticatedRequest, res: Response) => {
  res.json(fleetSummary());
});

// -------------------------------------------------------------
// Agent task channel: enrolled agents poll for queued scans and post back what they observed.
// Authenticated with the agent's own ingest key (never the shared secret).
// -------------------------------------------------------------
fleetRouter.get('/agent/tasks', requireAgentKey, (req: Request, res: Response) => {
  const agentId = (req as any).ingestAgentId as string;
  res.setHeader('Cache-Control', 'no-store');
  res.json({ tasks: claimJobs(agentId).map((j) => ({ jobId: j.id, kind: j.kind, requestedAt: j.requestedAt })) });
});

fleetRouter.post('/agent/results', requireAgentKey, (req: Request, res: Response) => {
  const agentId = (req as any).ingestAgentId as string;
  try {
    const job = applyAgentReport(agentId, req.body as AgentScanReport);
    db.logAudit({
      actorId: agentId,
      actorUsername: agentId,
      actorRole: 'analyst',
      action: `CECUR_${job.kind.toUpperCase()}_SCAN_${job.status.toUpperCase()}`,
      panel: 'cecur',
      targetResource: `${job.agentName} (${job.agentId})`,
      ipAddress: req.socket.remoteAddress || '127.0.0.1',
      status: job.status === 'completed' ? 'SUCCESS' : 'ERROR',
      details: `[source=agent] ${job.kind} scan ${job.id} ${job.status}${job.error ? `: ${job.error}` : ` ${JSON.stringify(job.summary ?? {})}`}`,
    });
    res.json({ success: true, job });
  } catch (err) {
    if (err instanceof ScanResultError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    console.error('[fleet] scan result ingest failed:', (err as Error).message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// -------------------------------------------------------------
// Asset inventory (PLB_Assets.csv) linked to real telemetry. Re-read on every call so the CSV stays the source of truth.
// -------------------------------------------------------------
fleetRouter.get('/assets', requireAuth, requirePanel('cecur'), (_req: AuthenticatedRequest, res: Response) => {
  const loaded = loadAssets();
  db.assets = loaded.assets;
  const assets = linkAssetsToTelemetry(loaded.assets);
  res.json({
    source: loaded.source,
    error: loaded.error,
    total: assets.length,
    withTelemetry: assets.filter((a) => a.telemetry.coverage !== 'none').length,
    assets,
  });
});
