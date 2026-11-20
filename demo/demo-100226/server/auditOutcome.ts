import type { Response } from 'express';
import type { AuditLogEntry } from '../src/types';
import { db } from './db';

/**
 * Emits the audit record for an action that has already changed state (active response, incident
 * mutation, approval, scan submission) and waits for the durable ledger to confirm it.
 *
 * The action is never rolled back: the caller answers with its normal status plus an
 * `auditPersisted: false` body field and an `X-CS3-Audit: degraded` header. Setting
 * CS3_AUDIT_STRICT=1 makes the caller answer 503 instead, for deployments where an unaudited
 * containment action must never look successful.
 */
/** Manifests set these as "true"; shells use "1". Accept both, and "yes". */
export function envFlag(name: string): boolean {
  const value = (process.env[name] || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes';
}

export interface AuditOutcome {
  persisted: boolean;
  strict: boolean;
  timedOut: boolean;
}

export async function recordCriticalAudit(
  res: Response,
  entry: Omit<AuditLogEntry, 'id' | 'timestamp'>
): Promise<AuditOutcome> {
  const result = await db.logAuditCritical(entry);
  const strict = envFlag('CS3_AUDIT_STRICT');
  const degraded = result.durable && !result.persisted;
  res.setHeader('X-CS3-Audit', degraded ? 'degraded' : result.durable ? 'durable' : 'memory');
  return { persisted: result.persisted, strict, timedOut: result.timedOut };
}

/**
 * True when the caller mutated state but the audit record is not durable and strict mode is on, i.e.
 * the response should be 503. The caller supplies a body describing what did happen so the
 * operator still learns the action's outcome.
 */
export function auditDegraded(outcome: AuditOutcome): boolean {
  return outcome.strict && !outcome.persisted;
}
