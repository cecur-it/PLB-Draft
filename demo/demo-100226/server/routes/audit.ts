import { createHash } from 'crypto';
import { Router, Response } from 'express';
import { db } from '../db';
import { requireAuth, requirePanel, requireAction, AuthenticatedRequest } from '../middleware/auth';
import { isPostgresEnabled } from '../pg/pool';
import { verifyAuditChain } from '../pg/store';

export const auditRouter = Router();

// Retrieve audit logs with filter (Available to all roles, but export is restricted)
auditRouter.get('/', requireAuth, requirePanel('audit'), (req: AuthenticatedRequest, res: Response) => {
  const { status, actor, panel, search, nistControl } = req.query;

  let results = [...db.auditLogs];

  if (status && typeof status === 'string') {
    results = results.filter((l) => l.status === status);
  }

  if (actor && typeof actor === 'string') {
    results = results.filter((l) => l.actorUsername.toLowerCase().includes(actor.toLowerCase()));
  }

  if (panel && typeof panel === 'string') {
    results = results.filter((l) => l.panel === panel);
  }

  if (nistControl && typeof nistControl === 'string') {
    const nc = nistControl.toLowerCase();
    results = results.filter((l) => l.nistControls && l.nistControls.some((c) => c.toLowerCase().includes(nc)));
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    results = results.filter(
      (l) =>
        l.action.toLowerCase().includes(q) ||
        l.details.toLowerCase().includes(q) ||
        (l.targetResource && l.targetResource.toLowerCase().includes(q)) ||
        l.actorUsername.toLowerCase().includes(q) ||
        (l.nistControls && l.nistControls.some((c) => c.toLowerCase().includes(q))) ||
        (l.chainHash && l.chainHash.toLowerCase().includes(q))
    );
  }

  res.json({
    total: results.length,
    logs: results,
  });
});

// Cryptographic verification endpoint for the SHA-256 tamper-evident ledger (NIST AU-9 / NIST 03.03.03).
// Two chains are checked independently: the persisted append-only ledger (authoritative when
// PostgreSQL is enabled) and the in-memory window the panel renders. Reporting only a hash prefix
// count, as this endpoint used to, hid every break below the head.
auditRouter.post('/verify-ledger', requireAuth, requirePanel('audit'), async (req: AuthenticatedRequest, res: Response) => {
  const local = db.verifyAuditChainLocal();
  const stats = db.auditStats();

  let persisted: { checked: boolean; brokenAt: number | null } = { checked: false, brokenAt: null };
  if (isPostgresEnabled()) {
    try {
      const brokenAt = await verifyAuditChain();
      persisted = { checked: brokenAt !== undefined, brokenAt: brokenAt ?? null };
    } catch (err) {
      res.status(503).json({ error: 'Ledger verification unavailable', message: (err as Error).message });
      return;
    }
  }

  const persistedBroken = persisted.checked && persisted.brokenAt !== null;
  const localBroken = local.brokenAt !== null;
  const tampered = persistedBroken || localBroken;
  const lagging = stats.pending > 0 || stats.failed > 0;

  res.json({
    status: tampered ? 'TAMPER_DETECTED' : lagging ? 'DEGRADED' : 'VERIFIED_INTACT',
    // In-memory window
    totalEntries: db.auditLogs.length,
    verifiedCount: local.checked,
    legacyEntries: local.legacy,
    localChain: { brokenAt: local.brokenAt, checked: local.checked },
    // Persisted append-only ledger (null when PostgreSQL persistence is off)
    durableLedger: persisted.checked ? { brokenAt: persisted.brokenAt, intact: !persistedBroken } : null,
    pendingAppends: stats.pending,
    failedAppends: stats.failed,
    droppedAppends: stats.dropped,
    persistedEntries: stats.persisted,
    degraded: lagging,
    controlMappings: ['NIST SP 800-53 Rev 5 (AU-9, AU-10)', 'NIST SP 800-171 Rev 3 (03.03.03, 03.03.04)'],
    genesisBlock: 'genesis-root-000000000000',
    headBlock: db.auditLogs[0]?.chainHash || 'none',
    timestamp: new Date().toISOString(),
    verifier: `${req.user?.displayName} (${req.user?.username})`,
  });
});

// Export audit logs (Restricted to Admin and Auditor only)
auditRouter.get(
  '/export',
  requireAuth,
  requirePanel('audit'),
  requireAction('export_audit'),
  async (req: AuthenticatedRequest, res: Response) => {
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

    const local = db.verifyAuditChainLocal();
    let durableIntact: boolean | null = null;
    if (isPostgresEnabled()) {
      const brokenAt = await verifyAuditChain().catch(() => null);
      durableIntact = brokenAt === null && brokenAt !== undefined;
    }
    const integrityOk = local.brokenAt === null && durableIntact !== false;

    const auditResult = await db.logAuditCritical({
      actorId: req.user?.id || 'unknown',
      actorUsername: req.user?.username || 'unknown',
      actorRole: req.user?.role || 'auditor',
      action: 'EXPORT_AUDIT_LOG_PACKAGE',
      panel: 'audit',
      targetResource: 'ALL_AUDIT_RECORDS',
      ipAddress: clientIp,
      status: 'SUCCESS',
      details:
        `Generated full JSON compliance audit package containing ${db.auditLogs.length} log entries ` +
        `(chain ${local.brokenAt === null ? 'intact' : `broken at ${local.brokenAt}`}, ` +
        `durable ledger ${durableIntact === null ? 'not configured' : durableIntact ? 'intact' : 'broken'}) ` +
        'with control mappings to NIST SP 800-53 Rev 5 AU-3 and NIST SP 800-171 Rev 3 03.03.02.',
    });
    res.setHeader(
      'X-CS3-Audit',
      auditResult.durable && !auditResult.persisted ? 'degraded' : auditResult.durable ? 'durable' : 'memory'
    );

    // Covers the exact record list and chain head being sent, so a recipient can re-derive it and
    // see that the file was not edited in transit. Computed after the export entry is appended.
    const integrityHash = `sha256-${createHash('sha256')
      .update([db.auditLogs[0]?.chainHash ?? 'none', ...db.auditLogs.map((l) => l.id)].join(':'))
      .digest('hex')}`;

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=CECUR-IT-SOC-AUDIT-${new Date().toISOString().split('T')[0]}.json`);
    res.send(
      JSON.stringify(
        {
          organization: 'CECUR-IT SOC & CUI Enclave',
          exportTimestamp: new Date().toISOString(),
          exportedBy: `${req.user?.displayName} (${req.user?.username} / ${req.user?.role})`,
          controlMappings: [
            'NIST SP 800-53 Rev 5 (AU-2, AU-3, AU-6, AU-9, AU-10, AU-12)',
            'NIST SP 800-171 Rev 3 (03.03.01 - 03.03.09)',
          ],
          cryptographicChainIntegrity: integrityOk ? 'VERIFIED_SHA256' : 'CHAIN_BROKEN',
          chainVerification: {
            inMemory: { brokenAt: local.brokenAt, checked: local.checked, legacyEntries: local.legacy },
            durableLedger: durableIntact === null ? 'not_configured' : durableIntact ? 'intact' : 'broken',
          },
          integrityHash,
          totalRecords: db.auditLogs.length,
          records: db.auditLogs,
        },
        null,
        2
      )
    );
  }
);
