import bcrypt from 'bcryptjs';
import { createHash } from 'crypto';
import {
  User,
  SensorNode,
  CecurAgent,
  CecurAlert,
  CecurLogEvent,
  CecurVulnerability,
  CecurFIMEvent,
  CecurSCAScan,
  CecurComplianceStandard,
  ActivTrakSession,
  Incident,
  TargetAllowlistEntry,
  ErrowTask,
  AuditLogEntry,
  AssetRecord,
  CecurScanJob,
} from '../src/types';

/** Trust anchor for an empty ledger. Mirrors cs3.audit_chain() in 003_audit_protection.sql. */
export const GENESIS_HASH = 'genesis-root-000000000000';

/**
 * Version tag for the in-memory chain digest. Rows appended by an older console build carry a
 * digest that was never recomputable, so verification skips them and reports them as legacy.
 */
export const AUDIT_HASH_VERSION = 2;

/**
 * Field projection hashed into the chain, joined with US (0x1f) so no field value can shift the
 * boundary of the next one. Key order is fixed here rather than taken from the object, which makes
 * the digest reproducible from a stored entry alone.
 */
export function canonicalAuditBody(entry: Omit<AuditLogEntry, 'id' | 'timestamp' | 'chainHash' | 'seq' | 'hashVersion'>): string {
  return [
    entry.actorId,
    entry.actorUsername,
    entry.actorRole,
    entry.action,
    entry.panel,
    entry.targetResource ?? '',
    entry.ipAddress,
    entry.status,
    entry.details,
    (entry.nistControls ?? []).join(','),
    entry.cuiProtected ? '1' : '0',
    entry.nonRepudiationVerified ? '1' : '0',
  ].join('\u001f');
}

/** Digest of one link: previous hash, sequence number, timestamp and the canonical body. */
export function computeChainHash(prevHash: string, seq: number, timestamp: string, body: string): string {
  return `sha256-${createHash('sha256').update(`${prevHash}:${seq}:${timestamp}:${body}`).digest('hex')}`;
}

export type AuditSink = (entry: AuditLogEntry) => Promise<boolean>;

export interface AuditSinkResult {
  /** The entry reached the durable ledger. */
  persisted: boolean;
  /** The wait elapsed before the ledger confirmed the append. */
  timedOut: boolean;
  /** A durable backend is configured at all; false means in-memory only. */
  durable: boolean;
  entry: AuditLogEntry;
}

export interface AuditStats {
  durable: boolean;
  pending: number;
  failed: number;
  dropped: number;
  persisted: number;
  backlogHigh: boolean;
}

export class SOCDatabase {
  public users: User[] = [];
  public sensors: SensorNode[] = [];
  public cecurAgents: CecurAgent[] = [];
  public cecurAlerts: CecurAlert[] = [];
  public cecurLogs: CecurLogEvent[] = [];
  public cecurVulnerabilities: CecurVulnerability[] = [];
  public cecurFIMEvents: CecurFIMEvent[] = [];
  public cecurSCAScans: CecurSCAScan[] = [];
  public cecurCompliance: CecurComplianceStandard[] = [];
  public activtrakSessions: ActivTrakSession[] = [];
  public incidents: Incident[] = [];
  public targetAllowlist: TargetAllowlistEntry[] = [];
  public errowJobs: ErrowTask[] = [];
  /** Asset inventory loaded from PLB_Assets.csv (see server/assets/plbAssets.ts). */
  public assets: AssetRecord[] = [];
  /** Scan tasks queued for enrolled agents; results come back from the agents themselves. */
  public cecurScanJobs: CecurScanJob[] = [];
  public auditLogs: AuditLogEntry[] = [];
  public initializedAt: string = '';
  /** Hooks invoked for every audit entry, before the durable append (UI/SSE fan-out, tests). */
  public auditListeners: Array<(entry: AuditLogEntry) => void> = [];

  /** Durable ledger writer. Set once at boot; null means the console runs in-memory only. */
  private auditSink: AuditSink | null = null;
  /** Single-writer FIFO: one drainer at a time, so appends cannot interleave out of order. */
  private auditQueue: AuditLogEntry[] = [];
  private auditWaiters = new Map<string, (settled: boolean) => void>();
  private auditDraining = false;
  private auditRetryTimer: NodeJS.Timeout | null = null;
  private auditFailures = 0;
  private auditDropped = 0;
  private auditPersistedCount = 0;
  private auditBacklogAlerted = false;
  /** Monotonic per-entry sequence. Continues from the persisted chain_no after hydration. */
  private auditSeq = 0;
  /** Previous chain hash, i.e. the head of the ledger as this process knows it. */
  private auditHead: string = GENESIS_HASH;
  /** Distinguishes two consoles appending to the same ledger within one millisecond. */
  private readonly auditBootNonce = Math.random().toString(16).slice(2, 8);

  constructor() {
    this.initializedAt = new Date().toISOString();
    this.bootstrapAdmin();
  }

  /** Create a single admin from CS3_BOOTSTRAP_ADMIN_PASSWORD (set by onboarding/wizard.mjs). */
  private bootstrapAdmin() {
    const password = process.env.CS3_BOOTSTRAP_ADMIN_PASSWORD;
    if (!password || this.users.length > 0) return;
    const now = new Date().toISOString();
    this.users.push({
      id: 'usr-bootstrap-admin',
      username: 'admin',
      email: 'admin@localhost',
      passwordHash: bcrypt.hashSync(password, 10),
      role: 'admin',
      displayName: 'Bootstrap Administrator',
      title: 'SOC Administrator',
      department: 'Security Operations',
      avatar: '',
      createdAt: now,
      lastLogin: now,
    } as User);
  }

  /** Register the durable ledger writer (PostgreSQL). Called once during boot. */
  public setAuditSink(sink: AuditSink | null) {
    this.auditSink = sink;
  }

  /**
   * Continue an existing chain instead of restarting at genesis: the in-memory head and the
   * sequence counter are seeded from the persisted ledger tail so a restart cannot silently
   * fork the chain, and the next entry links onto the persisted head hash.
   */
  public hydrateAuditHead(chainNo: number, chainHash: string) {
    this.auditSeq = Math.max(this.auditSeq, chainNo);
    this.auditHead = chainHash;
  }

  /** NIST AU-2/AU-3 auto-mapping for entries that do not declare their own controls. */
  private inferNistControls(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): string[] {
    if (entry.nistControls?.length) return entry.nistControls;
    if (entry.status === 'DENY_403') return ['AC-3', 'AC-6', '03.01.07'];
    if (entry.panel === 'incidents') return ['IR-4', 'IR-5', '03.06.01'];
    if (entry.panel === 'errow') return ['CA-8', 'RA-5', '03.11.02'];
    if (entry.panel === 'audit') return ['AU-2', 'AU-3', 'AU-9', '03.03.01', '03.03.03'];
    if (entry.panel === 'cecur') return ['SI-4', 'CM-6', '03.14.01'];
    return ['AU-2', 'AU-3', '03.03.01'];
  }

  /**
   * Append one chained entry to the in-memory ledger and hand it to the durable writer.
   * Returns synchronously; use logAuditCritical() when the caller must know the entry landed.
   */
  public logAudit(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const log = this.appendAuditEntry(entry);
    void this.drainAudit();
    return log;
  }

  /**
   * Append an entry that must be durable before the caller answers (active response, incident
   * mutation, approval, authentication). Resolves once the sink confirms the append, or once
   * CS3_AUDIT_PERSIST_TIMEOUT_MS elapses — the write keeps retrying in the background either way.
   */
  public async logAuditCritical(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): Promise<AuditSinkResult> {
    const log = this.appendAuditEntry(entry);
    const durable = this.auditSink !== null;
    if (!durable) {
      return { persisted: true, timedOut: false, durable: false, entry: log };
    }

    let confirmed = false;
    const settled = new Promise<boolean>((resolve) => {
      this.auditWaiters.set(log.id, (ok) => {
        confirmed = true;
        resolve(ok);
      });
    });
    void this.drainAudit();

    const timeoutMs = Number(process.env.CS3_AUDIT_PERSIST_TIMEOUT_MS) || 2_000;
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), Math.max(1, timeoutMs));
      timer.unref?.();
    });
    const persisted = await Promise.race([settled, timedOut]);
    if (timer) clearTimeout(timer);
    return { persisted, timedOut: !confirmed, durable: true, entry: log };
  }

  private appendAuditEntry(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const timestamp = new Date().toISOString();
    const nistControls = this.inferNistControls(entry);
    const seq = ++this.auditSeq;

    // Computed fields go last: callers may pass an empty nistControls array or a stale chainHash.
    // The digest is taken over the finished entry so verification can recompute it exactly.
    const log: AuditLogEntry = {
      ...entry,
      id: `aud-${this.auditBootNonce}-${seq}`,
      seq,
      timestamp,
      prevHash: this.auditHead,
      nistControls,
      hashVersion: AUDIT_HASH_VERSION,
      cuiProtected: true,
      nonRepudiationVerified: true,
    };
    log.chainHash = computeChainHash(log.prevHash!, seq, timestamp, canonicalAuditBody(log));
    this.auditHead = log.chainHash;
    this.auditLogs.unshift(log);
    for (const listener of this.auditListeners) {
      try {
        listener(log);
      } catch (err) {
        console.error('[SOCDatabase] audit listener failed:', (err as Error).message);
      }
    }
    // The durable ledger is the record of truth; the in-memory window is only a view.
    if (this.auditLogs.length > 500) {
      this.auditLogs = this.auditLogs.slice(0, 500);
    }

    if (this.auditSink) {
      this.auditQueue.push(log);
      const maxQueue = Number(process.env.CS3_AUDIT_QUEUE_MAX) || 5_000;
      while (this.auditQueue.length > maxQueue) {
        const dropped = this.auditQueue.shift()!;
        this.auditDropped += 1;
        this.settle(dropped.id, false);
      }
      this.retryBacklogAlert();
    }
    return log;
  }

  private settle(id: string, ok: boolean) {
    const resolve = this.auditWaiters.get(id);
    if (resolve) {
      this.auditWaiters.delete(id);
      resolve(ok);
    }
  }

  /** Single drainer. Failures are counted, alerted and retried with capped backoff. */
  private async drainAudit(): Promise<void> {
    if (this.auditDraining || !this.auditSink) return;
    this.auditDraining = true;
    try {
      while (this.auditQueue.length > 0) {
        const entry = this.auditQueue[0];
        let ok = false;
        try {
          ok = await this.auditSink(entry);
        } catch (err) {
          console.error('[audit] cs3_audit_persist_failed', (err as Error).message);
        }
        if (ok) {
          this.auditQueue.shift();
          this.settle(entry.id, true);
          this.auditPersistedCount += 1;
          this.auditFailures = 0;
          this.retryBacklogAlert();
          continue;
        }
        this.auditFailures += 1;
        // Re-queue at the tail so one poison entry cannot block everything behind it.
        this.auditQueue.push(this.auditQueue.shift()!);
        this.settle(entry.id, false);
        this.scheduleAuditRetry();
        break;
      }
    } finally {
      this.auditDraining = false;
    }
  }

  private scheduleAuditRetry() {
    if (this.auditRetryTimer) return;
    const delay = Math.min(30_000, 500 * 2 ** Math.min(this.auditFailures, 6));
    this.auditRetryTimer = setTimeout(() => {
      this.auditRetryTimer = null;
      void this.drainAudit();
    }, delay);
    this.auditRetryTimer.unref?.();
  }

  /** Emits cs3_audit_persist_backlog once per crossing so log-based alerting fires exactly once. */
  private retryBacklogAlert() {
    const pending = this.auditQueue.length;
    const threshold = Number(process.env.CS3_AUDIT_BACKLOG_ALERT) || 50;
    if (pending >= threshold && !this.auditBacklogAlerted) {
      this.auditBacklogAlerted = true;
      console.error(
        `[audit] cs3_audit_persist_backlog pending=${pending} failed=${this.auditFailures} dropped=${this.auditDropped}: ` +
          'the audit ledger is behind and entries are not yet durable. Check DATABASE_URL / cs3.audit_logs.'
      );
    } else if (pending === 0 && this.auditBacklogAlerted) {
      this.auditBacklogAlerted = false;
      console.info(`[audit] cs3_audit_persist_backlog cleared after persisting ${this.auditPersistedCount} entries`);
    }
  }

  public auditStats(): AuditStats {
    return {
      durable: this.auditSink !== null,
      pending: this.auditQueue.length,
      failed: this.auditFailures,
      dropped: this.auditDropped,
      persisted: this.auditPersistedCount,
      backlogHigh: this.auditBacklogAlerted,
    };
  }

  /**
   * Recompute the in-memory chain from the oldest retained entry forward. The oldest entry's
   * prev_hash is trusted (it may link to an archived or hydrated head), which is the same
   * contract as cs3.verify_audit_chain(). Returns the seq of the first broken link, or null.
   */
  public verifyAuditChainLocal(): { brokenAt: number | null; checked: number; legacy: number } {
    const ordered = [...this.auditLogs].reverse();
    let expectedPrev: string | null = null;
    let checked = 0;
    let legacy = 0;
    for (const entry of ordered) {
      if (entry.hashVersion !== AUDIT_HASH_VERSION) {
        legacy += 1;
        expectedPrev = entry.chainHash ?? null;
        continue;
      }
      if (expectedPrev !== null && entry.prevHash !== expectedPrev) {
        return { brokenAt: entry.seq ?? -1, checked, legacy };
      }
      const expected = computeChainHash(entry.prevHash ?? GENESIS_HASH, entry.seq!, entry.timestamp, canonicalAuditBody(entry));
      if (entry.chainHash !== expected) {
        return { brokenAt: entry.seq ?? -1, checked, legacy };
      }
      expectedPrev = entry.chainHash;
      checked += 1;
    }
    return { brokenAt: null, checked, legacy };
  }

  public getUserByUsername(username: string): User | undefined {
    return this.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  }

  public getUserByEmail(email: string): User | undefined {
    return this.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  }

  public getUserById(id: string): User | undefined {
    return this.users.find((u) => u.id === id);
  }

  public createUser(user: User): User {
    this.users.push(user);
    return user;
  }

  public updateUser(id: string, updates: Partial<User>): User | undefined {
    const idx = this.users.findIndex((u) => u.id === id);
    if (idx === -1) return undefined;
    this.users[idx] = { ...this.users[idx], ...updates };
    return this.users[idx];
  }
}

export const db = new SOCDatabase();
