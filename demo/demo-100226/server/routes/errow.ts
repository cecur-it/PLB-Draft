import { Router, Response } from 'express';
import { db } from '../db';
import { auditDegraded, recordCriticalAudit } from '../auditOutcome';
import { requireAuth, requirePanel, requireAction, AuthenticatedRequest } from '../middleware/auth';
import {
  getErrowStatus,
  runErrowScan,
  refreshErrowJob,
  ErrowUnavailableError,
  ERROW_MEMORY_PERSISTENCE,
  SAFE_TOOL_PROFILES,
  SafeTool,
} from '../connectors/errowClient';
import { TargetAllowlistEntry } from '../../src/types';

export const errowRouter = Router();

// Panel status (Admin only)
errowRouter.get('/status', requireAuth, requirePanel('errow'), (req: AuthenticatedRequest, res: Response) => {
  const status = getErrowStatus();
  res.json(status);
});

// Target Allowlist
errowRouter.get('/allowlist', requireAuth, requirePanel('errow'), (req: AuthenticatedRequest, res: Response) => {
  res.json({
    count: db.targetAllowlist.length,
    targets: db.targetAllowlist,
    persistence: ERROW_MEMORY_PERSISTENCE,
  });
});

// Add new target to allowlist (Admin only + strict validation)
errowRouter.post(
  '/allowlist',
  requireAuth,
  requirePanel('errow'),
  requireAction('manage_allowlist'),
  async (req: AuthenticatedRequest, res: Response) => {
    const { hostname, ipRange, ownerDepartment, notes } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    if (!hostname || !ipRange || !ownerDepartment) {
      res.status(400).json({ error: 'Missing required target information (hostname, ipRange, ownerDepartment)' });
      return;
    }

    // Check if target hostname already exists
    if (db.targetAllowlist.some((t) => t.hostname.toLowerCase() === hostname.toLowerCase())) {
      res.status(400).json({ error: 'Target hostname is already registered in the allowlist.' });
      return;
    }

    const newTarget: TargetAllowlistEntry = {
      id: `tgt-${Date.now()}`,
      hostname: hostname.trim(),
      ipRange: ipRange.trim(),
      ownerDepartment: ownerDepartment.trim(),
      authorizedBy: `${req.user?.displayName} (${req.user?.username})`,
      authorizationDate: new Date().toISOString().split('T')[0],
      status: 'AUTHORIZED',
      notes: notes || 'Authorized for scoped safe recon sweeps.',
      scanCount: 0,
    };

    // Audit authorization intent before touching the process-local allowlist. The audit ledger and
    // memory cannot be transactional; an intent record may therefore exist without a later mutation.
    const outcome = await recordCriticalAudit(res, {
      actorId: req.user?.id || 'unknown',
      actorUsername: req.user?.username || 'unknown',
      actorRole: req.user?.role || 'admin',
      action: 'ADD_TARGET_ALLOWLIST',
      panel: 'errow',
      targetResource: newTarget.hostname,
      ipAddress: clientIp,
      status: 'ALLOW',
      details: `Audit-first authorization to add '${newTarget.hostname}' (${newTarget.ipRange}) to the process-local Errow allowlist. This records intent, not a durable mutation.`,
    });
    if (!outcome.persisted || auditDegraded(outcome)) {
      res.status(503).json({
        error: 'Audit Ledger Unavailable',
        mutated: false,
        message: 'Critical audit requirements were not met; no allowlist change was made.',
      });
      return;
    }

    // Revalidate after the awaited audit because another request may have changed the array.
    if (db.targetAllowlist.some((t) => t.hostname.toLowerCase() === newTarget.hostname.toLowerCase())) {
      res.status(409).json({ error: 'Target hostname was registered while authorization was being audited.', mutated: false });
      return;
    }

    db.targetAllowlist.unshift(newTarget);
    res.json({ success: true, target: newTarget, persistence: ERROW_MEMORY_PERSISTENCE });
  }
);

// Revoke/remove target from allowlist
errowRouter.delete(
  '/allowlist/:id',
  requireAuth,
  requirePanel('errow'),
  requireAction('manage_allowlist'),
  async (req: AuthenticatedRequest, res: Response) => {
    const index = db.targetAllowlist.findIndex((t) => t.id === req.params.id);
    if (index === -1) {
      res.status(404).json({ error: 'Target not found' });
      return;
    }

    const target = db.targetAllowlist[index];
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    const outcome = await recordCriticalAudit(res, {
      actorId: req.user?.id || 'unknown',
      actorUsername: req.user?.username || 'unknown',
      actorRole: req.user?.role || 'admin',
      action: 'REVOKE_TARGET_ALLOWLIST',
      panel: 'errow',
      targetResource: target.hostname,
      ipAddress: clientIp,
      status: 'ALLOW',
      details: `Audit-first authorization to remove '${target.hostname}' from the process-local Errow allowlist. This records intent, not a durable mutation.`,
    });
    if (!outcome.persisted || auditDegraded(outcome)) {
      res.status(503).json({
        error: 'Audit Ledger Unavailable',
        mutated: false,
        message: 'Critical audit requirements were not met; no allowlist change was made.',
      });
      return;
    }

    const currentIndex = db.targetAllowlist.findIndex((t) => t.id === req.params.id);
    if (currentIndex === -1) {
      res.status(409).json({ error: 'Target was removed while authorization was being audited.', mutated: false });
      return;
    }

    const removed = db.targetAllowlist.splice(currentIndex, 1)[0];
    res.json({ success: true, message: `Target ${removed.hostname} removed from process memory.`, persistence: ERROW_MEMORY_PERSISTENCE });
  }
);

// Trigger scan (Admin only, strictly gated to allowlisted target & SAFE_TOOL_PROFILES)
errowRouter.post(
  '/run-scan',
  requireAuth,
  requirePanel('errow'),
  requireAction('run_scan'),
  async (req: AuthenticatedRequest, res: Response) => {
    const { targetId, targetHost, tool } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    if (!tool || !SAFE_TOOL_PROFILES.includes(tool as SafeTool)) {
      db.logAudit({
        actorId: req.user?.id || 'unknown',
        actorUsername: req.user?.username || 'unknown',
        actorRole: req.user?.role || 'admin',
        action: 'SCAN_TOOL_REJECTED',
        panel: 'errow',
        targetResource: `${targetHost || targetId} [${tool}]`,
        ipAddress: clientIp,
        status: 'DENY_403',
        details: `Rejected scan attempt using unapproved tool '${tool}'. Only safe scoped tools (${SAFE_TOOL_PROFILES.join(', ')}) are allowed.`,
      });

      res.status(400).json({
        error: 'Invalid Tool Profile',
        message: `Tool '${tool}' is not approved. Safe tools: ${SAFE_TOOL_PROFILES.join(', ')}`,
      });
      return;
    }

    try {
      const job = await runErrowScan(
        targetHost,
        targetId,
        tool as SafeTool,
        req.user?.username || 'admin'
      );

      if (job.status === 'FAILED') {
        db.logAudit({
          actorId: req.user?.id || 'unknown',
          actorUsername: req.user?.username || 'unknown',
          actorRole: req.user?.role || 'admin',
          action: 'SCAN_FAILED',
          panel: 'errow',
          targetResource: `${job.targetHost} [${job.tool}]`,
          ipAddress: clientIp,
          status: 'ERROR',
          details: `[source=${job.source}] ${job.tool} on '${job.targetHost}' failed (job ${job.id}): ${job.error}. No results were simulated.`,
        });
        res.status(502).json({ error: 'Errow Scan Failed', message: job.error, job });
        return;
      }

      const outcome = await recordCriticalAudit(res, {
        actorId: req.user?.id || 'unknown',
        actorUsername: req.user?.username || 'unknown',
        actorRole: req.user?.role || 'admin',
        action: 'EXECUTE_SAFE_SCAN',
        panel: 'errow',
        targetResource: `${job.targetHost} [${job.tool}]`,
        ipAddress: clientIp,
        status: 'SUCCESS',
        details: `[source=${job.source}] Submitted ${job.tool} on authorized target '${job.targetHost}' (job ${job.id}, remote ${job.remoteTaskId ?? 'n/a'}, state ${job.status}). Remote Errow returned ${job.findingsCount} findings.`,
      });
      if (auditDegraded(outcome)) {
        res.status(503).json({ error: 'Audit Ledger Unavailable', message: 'Scan submitted but not durable.', job });
        return;
      }

      res.json({ success: true, job });
    } catch (err: any) {
      db.logAudit({
        actorId: req.user?.id || 'unknown',
        actorUsername: req.user?.username || 'unknown',
        actorRole: req.user?.role || 'admin',
        action: 'SCAN_FAILED',
        panel: 'errow',
        targetResource: `${targetHost || targetId} [${tool}]`,
        ipAddress: clientIp,
        status: 'ERROR',
        details: `Scan execution failed: ${err.message}`,
      });

      res.status(err instanceof ErrowUnavailableError ? 503 : 400).json({ error: 'Scan Failed', message: err.message });
    }
  }
);

// Scan Jobs history
errowRouter.get('/jobs', requireAuth, requirePanel('errow'), async (req: AuthenticatedRequest, res: Response) => {
  await Promise.all(db.errowJobs.map(refreshErrowJob));
  res.json({
    total: db.errowJobs.length,
    jobs: db.errowJobs,
    persistence: ERROW_MEMORY_PERSISTENCE,
  });
});
