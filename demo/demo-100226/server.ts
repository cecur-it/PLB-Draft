import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { db } from './server/db';
import { authRouter } from './server/routes/auth';
import { overviewRouter } from './server/routes/overview';
import { incidentsRouter } from './server/routes/incidents';
import { cecurRouter } from './server/routes/cecur';
import { activtrakRouter } from './server/routes/activtrak';
import { sensorsRouter } from './server/routes/sensors';
import { fusionRouter } from './server/routes/fusion';
import { errowRouter } from './server/routes/errow';
import { auditRouter } from './server/routes/audit';
import { executiveRouter } from './server/routes/executive';
import { systemRouter } from './server/routes/system';
import { fleetRouter } from './server/routes/fleet';
import { hydrateFleet } from './server/fleet/enrollment';
import { modelsRouter } from './server/routes/models';
import { isPostgresEnabled } from './server/pg/pool';
import { appendAudit, getDoc, listDocs, readAuditHead, verifyAuditChain } from './server/pg/store';
import { envFlag } from './server/auditOutcome';
import { startPgEventBridge } from './server/pg/events';
import { assertNoDemoMode, getProfile } from './server/profile';
import { getResolvedFirebaseConfig, isFirestoreEnabled } from './server/firestoreSync';
import { resolveTrustProxyHops } from './server/proxy';
import { startRemediationJobs, stopRemediationJobs } from './server/cecur/remediationJobs';
import { hydrateUserRegistry } from './server/accounts';

dotenv.config();

// Highest chain_no known to be broken in the persisted ledger, as last observed. Sticky within a
// process: a repair re-anchors new writes but does not make the existing rows valid again.
let durableBrokenAt: number | null = null;

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  assertNoDemoMode();
  app.set('trust proxy', resolveTrustProxyHops());

  // JSON Body Parser (limit sized for bulk enrollment batches of up to CS3_ENROLL_MAX_BATCH agents)
  app.use(express.json({ limit: process.env.CS3_JSON_LIMIT || '2mb' }));

  // Runtime config for the SPA (loaded by index.html before the bundle). Lets the same
  // prebuilt image honour CS3_PROFILE: onprem/airgap clients get no hosted Firebase config.
  app.get('/cs3-runtime-config.js', (req, res) => {
    const fb = getResolvedFirebaseConfig();
    const firebase = isFirestoreEnabled() ? fb : null;
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(
      `window.__CS3_CONFIG__ = ${JSON.stringify({ profile: getProfile(), firebase }).replace(/</g, '\\u003c')};\n`
    );
  });

  // Health check endpoint
  app.get('/api/health', (req, res) => {
    const audit = db.auditStats();
    const chain = db.verifyAuditChainLocal();
    // A broken chain (in memory, or persisted as last observed) means the ledger was altered: fail
    // the probe. A backlog is reported but stays 200 so a transient database blip does not flap
    // container health.
    const broken = chain.brokenAt !== null || durableBrokenAt !== null;
    res.status(broken ? 503 : 200).json({
      status: broken || audit.backlogHigh ? 'degraded' : 'nominal',
      service: 'CECUR-IT Unified SOC Console',
      timestamp: new Date().toISOString(),
      sensorsCount: db.sensors.length,
      incidentsCount: db.incidents.length,
      cecurAgentsCount: db.cecurAgents.length,
      audit: {
        durable: audit.durable,
        pendingAppends: audit.pending,
        failedAppends: audit.failed,
        droppedAppends: audit.dropped,
        chainBrokenAt: chain.brokenAt,
        durableChainBrokenAt: durableBrokenAt,
        backlogAlert: audit.backlogHigh,
      },
    });
  });

  // Track active SSE client connections for real-time live events
  const sseClients = new Set<express.Response>();

  // Real-time live event stream (Server-Sent Events); /api/events is the canonical alias.
  app.get(['/api/live/stream', '/api/events'], (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    // Send initial handshake
    res.write(`data: ${JSON.stringify({ type: 'CONNECTED', timestamp: new Date().toISOString() })}\n\n`);

    sseClients.add(res);

    req.on('close', () => {
      sseClients.delete(res);
    });
  });

  const broadcast = (payload: unknown) => {
    if (sseClients.size === 0) return;
    const frame = `data: ${JSON.stringify(payload)}\n\n`;
    sseClients.forEach((client) => {
      try {
        client.write(frame);
      } catch (e) {
        sseClients.delete(client);
      }
    });
  };

  // PostgreSQL persistence (optional): mirror the audit ledger into the append-only
  // cs3.audit_logs table and replace Firestore onSnapshot with LISTEN/NOTIFY -> SSE.
  let stopPgEvents = () => {};
  if (process.env.CS3_PERSISTENCE === 'postgres' && !isPostgresEnabled()) {
    throw new Error('CS3_PERSISTENCE=postgres requires DATABASE_URL; refusing non-durable account operation.');
  }
  if (isPostgresEnabled()) {
    try {
      const users = await hydrateUserRegistry(db);
      console.log(`[accounts] hydrated ${users} persisted user(s)`);
    } catch (err) {
      console.error('[accounts] user registry hydration failed:', (err as Error).message);
      throw err;
    }
    db.setAuditSink((entry) => appendAudit(entry as any));
    // Boot-time hydration: continue the persisted chain and restore persisted operational state.
    try {
      const head = await readAuditHead();
      if (head) db.hydrateAuditHead(head.chainNo, head.chainHash);
      const brokenAt = await verifyAuditChain();
      if (brokenAt) {
        durableBrokenAt = brokenAt;
        console.error(`[audit] cs3_audit_chain_broken at chain_no=${brokenAt} — the persisted ledger was altered`);
        if (envFlag('CS3_AUDIT_REPAIR') && head) {
          db.hydrateAuditHead(head.chainNo, head.chainHash);
          console.warn(`[audit] CS3_AUDIT_REPAIR=1: re-anchored the in-memory head to chain_no=${head.chainNo}`);
          db.logAudit({
            actorId: 'system',
            actorUsername: 'system',
            actorRole: 'admin',
            action: 'AUDIT_CHAIN_REPAIRED',
            panel: 'audit',
            targetResource: `chain_no=${head.chainNo}`,
            ipAddress: '127.0.0.1',
            status: 'ERROR',
            details: `Chain verification failed at chain_no=${brokenAt}; head re-anchored to ${head.chainHash}.`,
          });
        }
      } else if (brokenAt === null) {
        console.log(`[audit] ledger chain verified intact at boot (head chain_no=${head?.chainNo ?? 0})`);
      }
      // Re-verify periodically: the mutation triggers stop UPDATE/DELETE, but a party that can
      // disable them would otherwise go unnoticed until the next restart.
      const intervalMs = process.env.CS3_AUDIT_VERIFY_INTERVAL_MS === undefined
        ? 300_000
        : Number(process.env.CS3_AUDIT_VERIFY_INTERVAL_MS) || 0;
      if (intervalMs > 0) {
        const timer = setInterval(() => {
          void verifyAuditChain()
            .then((at) => {
              if (at && durableBrokenAt !== at) {
                durableBrokenAt = at;
                console.error(`[audit] cs3_audit_chain_broken at chain_no=${at} on re-verification`);
              }
            })
            .catch(() => undefined);
        }, intervalMs);
        timer.unref?.();
      }
    } catch (err) {
      console.error('[audit] head hydration failed:', (err as Error).message);
    }
    try {
      const fleet = await hydrateFleet();
      console.log(`[fleet] hydrated ${fleet.agents} agent(s) and ${fleet.enrollments} enrollment record(s)`);
    } catch (err) {
      console.error('[pg] fleet hydration failed:', (err as Error).message);
    }
    try {
      const rows = await listDocs<any>('incidents', 500);
      if (rows.length) db.incidents.splice(0, db.incidents.length, ...rows);
    } catch (err) {
      console.error('[pg] incident hydration failed:', (err as Error).message);
    }
    stopPgEvents = startPgEventBridge(async (change) => {
      if (change.collection === 'incidents') {
        try {
          const idx = db.incidents.findIndex((i: any) => i.id === change.id);
          if (change.op === 'DELETE') {
            if (idx >= 0) db.incidents.splice(idx, 1);
          } else {
            const doc = await getDoc<any>('incidents', change.id);
            if (doc) {
              if (idx >= 0) db.incidents[idx] = doc;
              else db.incidents.unshift(doc);
            }
          }
        } catch (err) {
          console.error('[pg] incident sync failed:', (err as Error).message);
        }
      }
      broadcast({ type: 'DB_CHANGE', change, timestamp: new Date().toISOString() });
    });
    console.log('[CECUR-IT SOC] PostgreSQL persistence enabled (CS3_PERSISTENCE=postgres)');
  }

  // Polling fallback endpoint for live telemetry
  app.get('/api/live/telemetry', (req, res) => {
    res.json({
      sensors: db.sensors,
      activeIncidentsCount: db.incidents.filter((i) => i.status !== 'RESOLVED').length,
      recentCecurAlerts: db.cecurAlerts.slice(0, 5),
      timestamp: new Date().toISOString(),
    });
  });

  // Mount API Resource Routers
  app.use('/api/auth', authRouter);
  app.use('/api/overview', overviewRouter);
  app.use('/api/incidents', incidentsRouter);
  app.use('/api/cecur', cecurRouter);
  app.use('/api/activtrak', activtrakRouter);
  app.use('/api/sensors', sensorsRouter);
  app.use('/api/fusion', fusionRouter);
  app.use('/api/errow', errowRouter);
  app.use('/api/audit', auditRouter);
  app.use('/api/executive', executiveRouter);
  app.use('/api/system', systemRouter);
  app.use('/api/fleet', fleetRouter);
  app.use('/api/models', modelsRouter);

  // Vite middleware for development vs Static dist for production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  await startRemediationJobs();

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CECUR-IT SOC] Server active and listening on http://0.0.0.0:${PORT}`);
  });

  // Graceful shutdown (Kubernetes SIGTERM / rolling updates)
  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    setTimeout(() => process.exit(0), 10_000).unref();
    void stopRemediationJobs()
      .catch((error) => console.error('[remediation] shutdown failed:', error instanceof Error ? error.message : 'unknown error'))
      .finally(() => {
        stopPgEvents();
        sseClients.forEach((c) => c.end());
        server.close(() => process.exit(0));
      });
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

startServer();
