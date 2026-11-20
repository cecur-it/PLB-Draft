import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AUDIT_HASH_VERSION, GENESIS_HASH, SOCDatabase, canonicalAuditBody, computeChainHash } from '../../server/db';
import type { AuditLogEntry } from '../../src/types';

/**
 * The audit ledger used to be a decorative hash: the digest covered six fields, the verifier only
 * counted "sha256-" prefixes, appends were fire-and-forget, and the chain restarted at genesis on
 * every boot. These tests pin the behaviours that make it an actual ledger.
 */

function entry(overrides: Partial<Omit<AuditLogEntry, 'id' | 'timestamp'>> = {}) {
  return {
    actorId: 'usr-1',
    actorUsername: 'analyst',
    actorRole: 'analyst' as const,
    action: 'CECUR_ACTIVE_RESPONSE_ISOLATE',
    panel: 'cecur',
    targetResource: 'ws-01 (10.0.0.5)',
    ipAddress: '10.0.0.9',
    status: 'SUCCESS' as const,
    details: 'queued isolate',
    ...overrides,
  };
}

function fresh() {
  const database = new SOCDatabase();
  database.users.splice(0);
  return database;
}

test('entries link to their predecessor and start from genesis', () => {
  const database = fresh();
  const first = database.logAudit(entry());
  const second = database.logAudit(entry({ action: 'UPDATE_CECUR_ALERT_STATUS' }));

  assert.equal(first.prevHash, GENESIS_HASH);
  assert.equal(first.seq, 1);
  assert.equal(second.prevHash, first.chainHash);
  assert.equal(second.seq, 2);
  assert.equal(database.auditStats().durable, false);
});

test('the stored hash is recomputable from the stored entry', () => {
  const database = fresh();
  const record = database.logAudit(entry());
  assert.equal(record.hashVersion, AUDIT_HASH_VERSION);
  assert.match(record.chainHash!, /^sha256-[a-f0-9]{64}$/);
  assert.equal(computeChainHash(record.prevHash!, record.seq!, record.timestamp, canonicalAuditBody(record)), record.chainHash);

  const broken = database.verifyAuditChainLocal();
  assert.equal(broken.brokenAt, null);
  assert.equal(broken.checked, 1);
});

test('a mutated field is detected at its sequence number', () => {
  const database = fresh();
  database.logAudit(entry());
  const target = database.logAudit(entry({ action: 'SECOND' }));
  database.logAudit(entry({ action: 'THIRD' }));

  target.details = 'queued isolate (rewritten)';
  assert.equal(database.verifyAuditChainLocal().brokenAt, target.seq);
});

test('a removed middle entry breaks the linkage', () => {
  const database = fresh();
  database.logAudit(entry());
  database.logAudit(entry());
  const third = database.logAudit(entry());
  database.auditLogs.splice(1, 1);

  assert.equal(database.verifyAuditChainLocal().brokenAt, third.seq);
});

test('hydration continues the persisted chain instead of forking at genesis', () => {
  const database = fresh();
  const persistedHead = `sha256-${'a'.repeat(64)}`;
  database.hydrateAuditHead(41, persistedHead);

  const next = database.logAudit(entry());
  assert.equal(next.seq, 42);
  assert.equal(next.prevHash, persistedHead);
  assert.equal(database.verifyAuditChainLocal().brokenAt, null);
});

test('the oldest retained entry is the trust anchor, not a break', () => {
  const database = fresh();
  database.hydrateAuditHead(7, `sha256-${'b'.repeat(64)}`);
  database.logAudit(entry());
  database.logAudit(entry());
  database.auditLogs.pop();

  assert.equal(database.verifyAuditChainLocal().brokenAt, null);
});

test('a critical entry reports success once the sink confirms it', async () => {
  const database = fresh();
  const seen: string[] = [];
  database.setAuditSink(async (record) => {
    seen.push(record.id);
    return true;
  });

  const result = await database.logAuditCritical(entry());
  assert.equal(result.persisted, true);
  assert.equal(result.durable, true);
  assert.equal(result.timedOut, false);
  assert.deepEqual(seen, [result.entry.id]);
  assert.equal(database.auditStats().persisted, 1);
});

test('a rejected append reports failure and is counted, not swallowed', async () => {
  const database = fresh();
  database.setAuditSink(async () => {
    throw new Error('connection reset');
  });

  const result = await database.logAuditCritical(entry());
  assert.equal(result.persisted, false);
  assert.equal(result.durable, true);
  assert.ok(database.auditStats().failed >= 1);
  assert.ok(database.auditStats().pending >= 1, 'the entry is retained for retry');
});

test('entries are offered to the sink one at a time, in sequence order', async () => {
  const database = fresh();
  let inFlight = 0;
  let overlapped = false;
  const order: number[] = [];
  database.setAuditSink(async (record) => {
    if (inFlight > 0) overlapped = true;
    inFlight += 1;
    await new Promise((resolve) => setTimeout(resolve, 5));
    order.push(record.seq!);
    inFlight -= 1;
    return true;
  });

  await Promise.all([
    database.logAuditCritical(entry()),
    database.logAuditCritical(entry()),
    database.logAuditCritical(entry()),
  ]);
  assert.equal(overlapped, false);
  assert.deepEqual(order, [1, 2, 3]);
});

test('a failed append is retried and drains without losing order', async () => {
  const database = fresh();
  let calls = 0;
  const delivered: number[] = [];
  database.setAuditSink(async (record) => {
    calls += 1;
    if (calls === 1) throw new Error('transient');
    delivered.push(record.seq!);
    return true;
  });

  await database.logAuditCritical(entry());
  await database.logAuditCritical(entry());

  const deadline = Date.now() + 2_000;
  while (database.auditStats().pending > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(database.auditStats().pending, 0);
  assert.deepEqual(delivered, [1, 2]);
});

test('a hung sink times out instead of blocking the caller', async () => {
  const database = fresh();
  database.setAuditSink(() => new Promise<boolean>(() => {}));
  const previous = process.env.CS3_AUDIT_PERSIST_TIMEOUT_MS;
  process.env.CS3_AUDIT_PERSIST_TIMEOUT_MS = '20';
  try {
    const result = await database.logAuditCritical(entry());
    assert.equal(result.persisted, false);
    assert.equal(result.timedOut, true);
  } finally {
    if (previous === undefined) delete process.env.CS3_AUDIT_PERSIST_TIMEOUT_MS;
    else process.env.CS3_AUDIT_PERSIST_TIMEOUT_MS = previous;
  }
});

test('the backlog alert fires once per crossing and clears when drained', async () => {
  const database = fresh();
  const lines: string[] = [];
  const previous = { alert: process.env.CS3_AUDIT_BACKLOG_ALERT, queue: process.env.CS3_AUDIT_QUEUE_MAX };
  process.env.CS3_AUDIT_BACKLOG_ALERT = '2';
  process.env.CS3_AUDIT_QUEUE_MAX = '100';
  const originalError = console.error;
  const originalInfo = console.info;
  console.error = (...args: unknown[]) => void lines.push(args.join(' '));
  console.info = (...args: unknown[]) => void lines.push(args.join(' '));
  try {
    let release: (() => void) | null = null;
    database.setAuditSink(async () => {
      if (!release) await new Promise<void>((resolve) => (release = resolve));
      return true;
    });

    database.logAudit(entry());
    database.logAudit(entry());
    database.logAudit(entry());
    assert.equal(lines.filter((l) => l.includes('cs3_audit_persist_backlog')).length, 1);
    assert.equal(database.auditStats().backlogHigh, true);

    release!();
    const deadline = Date.now() + 2_000;
    while (database.auditStats().pending > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.ok(lines.some((l) => l.includes('cs3_audit_persist_backlog cleared')));
    assert.equal(database.auditStats().backlogHigh, false);
  } finally {
    console.error = originalError;
    console.info = originalInfo;
    for (const [key, value] of [
      ['CS3_AUDIT_BACKLOG_ALERT', previous.alert],
      ['CS3_AUDIT_QUEUE_MAX', previous.queue],
    ] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('overflow drops the oldest queued entry and counts it', () => {
  const database = fresh();
  const previous = process.env.CS3_AUDIT_QUEUE_MAX;
  process.env.CS3_AUDIT_QUEUE_MAX = '2';
  database.setAuditSink(() => new Promise<boolean>(() => {}));
  try {
    database.logAudit(entry());
    database.logAudit(entry());
    database.logAudit(entry());
    database.logAudit(entry());
    assert.equal(database.auditStats().pending, 2);
    assert.equal(database.auditStats().dropped, 2);
  } finally {
    if (previous === undefined) delete process.env.CS3_AUDIT_QUEUE_MAX;
    else process.env.CS3_AUDIT_QUEUE_MAX = previous;
  }
});
