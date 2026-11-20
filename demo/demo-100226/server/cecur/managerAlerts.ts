import { randomUUID } from 'node:crypto';
import type { CecurAlert, CecurAlertCategory } from '../../src/types';
import { db } from '../db';

/**
 * Adapter for Vendetta/Wazuh manager alerts.
 *
 * The manager decides; this only translates its structured alert into the CS3 alert model. Four
 * things are preserved verbatim because they are what an analyst or an auditor needs later:
 * `rule.id` (which rule fired), the original event time (not the arrival time), the device identity,
 * and `rule.level` as severity. Everything the manager already extracted (MITRE, compliance tags,
 * src/dst, user, path, hash) is carried across; the raw alert stays in `fullLog`.
 */

/** Natural key of an alert: same rule, same device, same primary locator means "the same thing". */
export interface DedupEntry {
  alertId: string;
  lastSeenMs: number;
}

const DEDUP_MAX_ENTRIES = 5000;
const dedup = new Map<string, DedupEntry>();

/** 0 disables deduplication. */
export function dedupWindowMs(): number {
  const seconds = process.env.CS3_ALERT_DEDUP_WINDOW_S;
  if (seconds === undefined) return 300_000;
  const parsed = Number(seconds);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed * 1000 : 300_000;
}

export function pruneDedupCache(now = Date.now()): void {
  const windowMs = dedupWindowMs();
  if (windowMs === 0) {
    dedup.clear();
    return;
  }
  for (const [key, entry] of dedup) {
    if (now - entry.lastSeenMs > windowMs) dedup.delete(key);
  }
}

export function clearDedupCache(): void {
  dedup.clear();
}

/** Agent 000 is the manager itself: an event it received over a remote, not one an agent reported. */
function isSelfReported(agentId: string | undefined): boolean {
  return !agentId || agentId === 'unattributed' || /^0+$/.test(agentId);
}

export function dedupKeyFor(alert: CecurAlert): string {
  // Keyed on the agent only when the event actually came from one. For syslog-sourced alerts the id is 000 for every
  // endpoint, so keying on it would fold alerts from different hosts into a single row.
  const device = isSelfReported(alert.agentId) ? alert.agentName : alert.agentId!;
  const locator = alert.srcIp || alert.filePath || alert.hash || alert.process || alert.user || alert.decoderMatched;
  return `${alert.ruleId}|${device}|${locator}`;
}

function str(value: unknown, max = 512): string {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

function num(value: unknown): number | undefined {
  const parsed = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  return Number.isFinite(parsed) ? parsed : undefined;
}

const GROUP_CATEGORIES: Array<[RegExp, CecurAlertCategory]> = [
  [/fim|syscheck|file_integrity/i, 'fim'],
  [/vulnerab|cve|vuln/i, 'vulnerability'],
  [/\bsca\b|cis_|policy/i, 'sca'],
  [/privilege|sudo|rootcheck|rootkit/i, 'privilege_escalation'],
  [/malware|virus|yara|ransom/i, 'malware'],
  [/lateral|netflow/i, 'lateral_movement'],
  [/web|http|apache|nginx|sql_injection|xss/i, 'web_attack'],
  [/auth|login|sshd|pam|password|brute/i, 'authentication'],
];

export function categoryFromGroups(groups: string[]): CecurAlertCategory {
  for (const group of groups) {
    for (const [pattern, category] of GROUP_CATEGORIES) {
      if (pattern.test(group)) return category;
    }
  }
  return 'log_anomaly';
}

/** The manager reports compliance as bare identifiers (`10.2.4`); CS3 tags them with the framework. */
export function complianceTags(rule: Record<string, unknown>): string[] {
  const tags: string[] = [];
  const add = (key: string, prefix: string) => {
    const value = rule[key];
    const list = Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
    for (const item of list) {
      const id = str(item, 64);
      if (id) tags.push(`${prefix}_${id.replace(/[^0-9A-Za-z.]/g, '.')}`);
    }
  };
  add('pci_dss', 'PCI_DSS');
  add('nist_800_53', 'NIST_800_53');
  add('hipaa', 'HIPAA');
  add('gdpr', 'GDPR');
  add('tsc', 'TSC');
  return [...new Set(tags)].slice(0, 20);
}

function eventTime(raw: Record<string, unknown>): string {
  const candidate = str(raw.timestamp, 64);
  const parsed = candidate ? Date.parse(candidate) : NaN;
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : new Date().toISOString();
}

export interface AdaptResult {
  alert: CecurAlert | null;
  /** Why the record was dropped, for the caller's response body. */
  reason?: string;
}

/**
 * Translates one manager alert. Returns `null` (with a reason) for records that carry no rule id or
 * no usable description, so a malformed record cannot create an empty alert.
 */
export function adaptManagerAlert(raw: unknown): AdaptResult {
  if (!raw || typeof raw !== 'object') return { alert: null, reason: 'not an object' };
  const record = raw as Record<string, any>;
  const rule = (record.rule ?? {}) as Record<string, any>;
  const agent = (record.agent ?? {}) as Record<string, any>;
  const data = (record.data ?? {}) as Record<string, any>;
  const mitre = (rule.mitre ?? {}) as Record<string, unknown>;

  const ruleId = num(rule.id);
  if (ruleId === undefined) return { alert: null, reason: 'missing rule.id' };
  const ruleTitle = str(rule.description, 200);
  if (!ruleTitle) return { alert: null, reason: 'missing rule.description' };

  const groups = Array.isArray(rule.groups) ? rule.groups.map((g: unknown) => str(g, 64)).filter(Boolean) : [];
  // An event received through the manager's syslog remote is attributed by remoted to the manager itself (agent 000), so
  // `agent.name` is the manager's hostname, not the device that logged. The device is in the RFC3164 header the sending
  // Fluent Bit wrote, which the manager exposes as `predecoder.hostname`; that is what a syslog-sourced alert must carry,
  // otherwise every endpoint collapses onto one "device" and the dedup key folds unrelated alerts together.
  const syslogSource = /^0+$/.test(str(agent.id, 64));
  const headerHost = str(record.predecoder?.hostname, 128);
  const agentName =
    (syslogSource ? headerHost : '') ||
    str(agent.name, 128) ||
    headerHost ||
    str(data.hostname, 128) ||
    str(data.host, 128) ||
    'unknown-host';
  const level = Math.min(15, Math.max(1, Math.round(num(rule.level) ?? 5)));
  const location = str(record.location, 256);
  const mitreTactic = Array.isArray(mitre.tactic) ? str(mitre.tactic[0], 96) : '';
  const mitreTechnique = Array.isArray(mitre.id) ? str(mitre.id[0], 32) : '';
  const when = eventTime(record);

  const descriptionParts = [ruleTitle, `on ${agentName}`];
  if (location) descriptionParts.push(`(${location})`);
  if (mitreTechnique && mitreTactic) descriptionParts.push(`MITRE ${mitreTactic} / ${mitreTechnique}`);

  return {
    alert: {
      id: `alert-${randomUUID()}`,
      timestamp: when,
      ruleId,
      ruleLevel: level,
      ruleTitle,
      description: descriptionParts.join(' ').slice(0, 1024),
      category: categoryFromGroups(groups),
      agentId: str(agent.id, 64) || 'unattributed',
      agentName,
      agentIp: str(agent.ip, 64) || str(data.srcip, 64),
      agentOs: str(agent.os, 128) || 'unknown',
      complianceTags: complianceTags(rule),
      mitreTactic: mitreTactic || undefined,
      mitreTechnique: mitreTechnique || undefined,
      decoderMatched: str(record.decoder?.name, 64) || 'vendetta-manager',
      srcIp: str(data.srcip, 64) || undefined,
      destIp: str(data.dstip, 64) || undefined,
      user: str(data.user ?? data.srcuser, 128) || undefined,
      process: str(data.command ?? data.process, 256) || undefined,
      filePath: str(data.file ?? data.path, 1024) || undefined,
      hash: str(data.md5 ?? data.sha256 ?? data.hash, 128) || undefined,
      fullLog: JSON.stringify(record).slice(0, 8000),
      status: 'new',
      firstSeen: when,
      lastSeen: when,
      count: 1,
    },
  };
}

export interface IngestOutcome {
  accepted: CecurAlert[];
  duplicates: number;
  rejected: number;
  reasons: string[];
  deduplicated: CecurAlert[];
}

/**
 * Adapts and stores a batch. A repeat inside the dedup window increments the existing alert's count
 * and `lastSeen` instead of creating a second row, which is also what makes a fail-closed retry
 * safe: replaying a batch that was already stored is deduplicated, not doubled.
 */
export function ingestManagerAlerts(raws: unknown[], now = Date.now()): IngestOutcome {
  const outcome: IngestOutcome = { accepted: [], duplicates: 0, rejected: 0, reasons: [], deduplicated: [] };
  const windowMs = dedupWindowMs();
  if (windowMs > 0) pruneDedupCache(now);

  for (const raw of raws) {
    const { alert, reason } = adaptManagerAlert(raw);
    if (!alert) {
      outcome.rejected += 1;
      if (reason && outcome.reasons.length < 8) outcome.reasons.push(reason);
      continue;
    }
    const key = dedupKeyFor(alert);
    const existing = windowMs > 0 ? dedup.get(key) : undefined;
    const previous = existing ? db.cecurAlerts.find((a) => a.id === existing.alertId) : undefined;
    if (existing && previous) {
      existing.lastSeenMs = now;
      previous.count = (previous.count ?? 1) + 1;
      previous.lastSeen = alert.timestamp;
      // A more severe recurrence upgrades the row rather than hiding behind the first severity.
      if (alert.ruleLevel > previous.ruleLevel) previous.ruleLevel = alert.ruleLevel;
      outcome.duplicates += 1;
      outcome.deduplicated.push(previous);
      continue;
    }

    db.cecurAlerts.unshift(alert);
    if (windowMs > 0) {
      if (dedup.size >= DEDUP_MAX_ENTRIES) {
        const oldest = dedup.keys().next().value;
        if (oldest !== undefined) dedup.delete(oldest);
      }
      dedup.set(key, { alertId: alert.id, lastSeenMs: now });
    }
    outcome.accepted.push(alert);
  }
  if (db.cecurAlerts.length > 5000) db.cecurAlerts.length = 5000;
  return outcome;
}

/** Shape detection used by the generic log endpoint so manager alerts are not flattened to logs. */
export function looksLikeManagerAlert(event: unknown): boolean {
  if (!event || typeof event !== 'object') return false;
  const record = event as Record<string, any>;
  return num(record.rule?.id) !== undefined && typeof record.rule?.description === 'string';
}
