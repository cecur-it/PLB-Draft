import { beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  adaptManagerAlert,
  categoryFromGroups,
  clearDedupCache,
  complianceTags,
  dedupKeyFor,
  dedupWindowMs,
  ingestManagerAlerts,
  looksLikeManagerAlert,
  pruneDedupCache,
} from '../../server/cecur/managerAlerts';
import { db } from '../../server/db';

/**
 * The manager is the decision point for host logs; CS3 only adapts its alerts. What matters is that the
 * adaptation loses nothing an analyst needs (rule ID, original time, device, severity) and that a replay —
 * Fluent Bit retrying a fail-closed batch — cannot turn one incident into N rows.
 */

const EVENT_TIME = '2024-06-01T09:15:00.000Z';

function wazuhAlert(overrides: Record<string, any> = {}) {
  return {
    timestamp: EVENT_TIME,
    rule: {
      id: 110012,
      level: 7,
      description: 'CS3: SSH authentication failure for admin from 10.0.0.5',
      groups: ['cs3_auth', 'authentication_failed'],
      mitre: { tactic: ['Credential Access'], id: ['T1110'] },
      pci_dss: ['10.2.4'],
      nist_800_53: ['AU.9'],
      ...(overrides.rule ?? {}),
    },
    agent: { id: '001', name: 'ws-01', ip: '10.0.0.5', os: 'Ubuntu 22.04', ...(overrides.agent ?? {}) },
    data: { srcip: '198.51.100.9', user: 'admin', ...(overrides.data ?? {}) },
    decoder: { name: 'cs3-sshd-failed' },
    location: '/var/log/auth.log',
    ...(overrides.top ?? {}),
  };
}

beforeEach(() => {
  clearDedupCache();
  db.cecurAlerts.splice(0);
  delete process.env.CS3_ALERT_DEDUP_WINDOW_S;
});

test('adapts a manager alert without losing rule ID, original time, device or severity', () => {
  const { alert, reason } = adaptManagerAlert(wazuhAlert());
  assert.equal(reason, undefined);
  assert.ok(alert);
  assert.equal(alert.ruleId, 110012);
  assert.equal(alert.ruleLevel, 7);
  assert.equal(alert.timestamp, EVENT_TIME, 'the event time must survive, not the arrival time');
  assert.equal(alert.agentId, '001');
  assert.equal(alert.agentName, 'ws-01');
  assert.equal(alert.agentIp, '10.0.0.5');
  assert.equal(alert.decoderMatched, 'cs3-sshd-failed');
  assert.equal(alert.srcIp, '198.51.100.9');
  assert.equal(alert.user, 'admin');
  // Enrichment the manager already did is carried across, not re-derived.
  assert.equal(alert.mitreTechnique, 'T1110');
  assert.equal(alert.mitreTactic, 'Credential Access');
  assert.ok(alert.complianceTags.includes('PCI_DSS_10.2.4'));
  assert.ok(alert.complianceTags.includes('NIST_800_53_AU.9'));
  assert.match(alert.fullLog ?? '', /cs3-sshd-failed/);
  assert.equal(alert.status, 'new');
  assert.equal(alert.count, 1);
});

test('clamps an out-of-range manager level into the CS3 1-15 scale', () => {
  assert.equal(adaptManagerAlert(wazuhAlert({ rule: { level: 99 } })).alert?.ruleLevel, 15);
  assert.equal(adaptManagerAlert(wazuhAlert({ rule: { level: 0 } })).alert?.ruleLevel, 1);
  assert.equal(adaptManagerAlert(wazuhAlert({ rule: { level: 'unknown' } })).alert?.ruleLevel, 5);
});

test('an unusable event time falls back to now instead of producing an invalid date', () => {
  const { alert } = adaptManagerAlert(wazuhAlert({ top: { timestamp: 'not-a-date' } }));
  assert.ok(alert);
  assert.ok(Number.isFinite(Date.parse(alert.timestamp)));
});

test('rejects records with no rule id or no description, with a reason', () => {
  assert.deepEqual(adaptManagerAlert({ rule: { description: 'x' } }), { alert: null, reason: 'missing rule.id' });
  assert.deepEqual(adaptManagerAlert({ rule: { id: 5 } }), { alert: null, reason: 'missing rule.description' });
  assert.equal(adaptManagerAlert(null).alert, null);
  assert.equal(adaptManagerAlert('nope').alert, null);
});

test('maps manager groups onto CS3 categories, and falls back when nothing matches', () => {
  assert.equal(categoryFromGroups(['syscheck', 'fim']), 'fim');
  assert.equal(categoryFromGroups(['vulnerability-detector']), 'vulnerability');
  assert.equal(categoryFromGroups(['cs3_auth', 'authentication_failed']), 'authentication');
  assert.equal(categoryFromGroups(['cs3_audit', 'privilege_escalation']), 'privilege_escalation');
  assert.equal(categoryFromGroups(['cs3_catchall']), 'log_anomaly');
  assert.equal(categoryFromGroups([]), 'log_anomaly');
});

test('compliance tags are prefixed, de-duplicated and capped', () => {
  const tags = complianceTags({ pci_dss: ['10.2.4', '10.2.4'], hipaa: '164.312' });
  assert.deepEqual(tags, ['PCI_DSS_10.2.4', 'HIPAA_164.312']);
});

test('looksLikeManagerAlert only matches the alert shape, not a log line', () => {
  assert.equal(looksLikeManagerAlert(wazuhAlert()), true);
  assert.equal(looksLikeManagerAlert({ message: 'hello', source: 'syslog' }), false);
  assert.equal(looksLikeManagerAlert({ rule: { id: 5 } }), false);
  assert.equal(looksLikeManagerAlert(null), false);
});

test('a repeat inside the window folds into the existing alert', () => {
  const first = ingestManagerAlerts([wazuhAlert()], 1_000_000);
  assert.equal(first.accepted.length, 1);
  assert.equal(db.cecurAlerts.length, 1);

  const second = ingestManagerAlerts([wazuhAlert()], 1_030_000);
  assert.equal(second.accepted.length, 0);
  assert.equal(second.duplicates, 1);
  assert.equal(db.cecurAlerts.length, 1, 'a replay must not create a second row');
  assert.equal(db.cecurAlerts[0].count, 2);
  assert.equal(db.cecurAlerts[0].firstSeen, EVENT_TIME);
  assert.equal(second.deduplicated[0].id, db.cecurAlerts[0].id);
});

test('a more severe recurrence raises the stored level', () => {
  ingestManagerAlerts([wazuhAlert()], 1_000_000);
  ingestManagerAlerts([wazuhAlert({ rule: { level: 12 } })], 1_010_000);
  assert.equal(db.cecurAlerts[0].ruleLevel, 12);
});

test('the same rule on a different device or locator is a separate alert', () => {
  ingestManagerAlerts([wazuhAlert()], 1_000_000);
  ingestManagerAlerts([wazuhAlert({ agent: { id: '002', name: 'ws-02' } })], 1_000_000);
  ingestManagerAlerts([wazuhAlert({ data: { srcip: '198.51.100.10', user: 'admin' } })], 1_000_000);
  assert.equal(db.cecurAlerts.length, 3);
});

test('an expired window produces a new alert, and 0 disables deduplication entirely', () => {
  ingestManagerAlerts([wazuhAlert()], 1_000_000);
  ingestManagerAlerts([wazuhAlert()], 1_000_000 + 301_000);
  assert.equal(db.cecurAlerts.length, 2);

  process.env.CS3_ALERT_DEDUP_WINDOW_S = '0';
  assert.equal(dedupWindowMs(), 0);
  ingestManagerAlerts([wazuhAlert()], 1_000_000);
  ingestManagerAlerts([wazuhAlert()], 1_000_000);
  assert.equal(db.cecurAlerts.length, 4);
  assert.equal(db.cecurAlerts[0].count, 1);
});

test('the window is configurable and survives junk values', () => {
  process.env.CS3_ALERT_DEDUP_WINDOW_S = '60';
  assert.equal(dedupWindowMs(), 60_000);
  process.env.CS3_ALERT_DEDUP_WINDOW_S = 'nope';
  assert.equal(dedupWindowMs(), 300_000);
  process.env.CS3_ALERT_DEDUP_WINDOW_S = '-5';
  assert.equal(dedupWindowMs(), 300_000);
});

test('pruning drops expired entries so the cache stays bounded', () => {
  ingestManagerAlerts([wazuhAlert()], 1_000_000);
  pruneDedupCache(1_000_000 + 400_000);
  ingestManagerAlerts([wazuhAlert()], 1_000_000 + 400_000);
  assert.equal(db.cecurAlerts.length, 2, 'a pruned key must behave as unseen');
});

test('a rejected record is counted with its reason and stores nothing', () => {
  const outcome = ingestManagerAlerts([{ rule: { id: 1 } }, wazuhAlert()], 1_000_000);
  assert.equal(outcome.rejected, 1);
  assert.deepEqual(outcome.reasons, ['missing rule.description']);
  assert.equal(db.cecurAlerts.length, 1);
});

test('a syslog-sourced alert keeps the device from the RFC3164 header, not the manager identity', () => {
  // What remoted writes for an event received over the syslog remote: agent 000 (the manager), the real device only in the
  // header. Without this the CS3 alert says the manager's own hostname for every endpoint.
  const syslogAlert = adaptManagerAlert(
    wazuhAlert({
      agent: { id: '000', name: 'manager-container', ip: '' },
      top: { predecoder: { hostname: 'web01', program_name: 'containerd', timestamp: 'Nov 14 09:23:27' } },
    }),
  ).alert!;
  assert.equal(syslogAlert.agentName, 'web01');

  // Different endpoints must not share a dedup key: both carry agent 000, so keying on it would fold them together.
  const other = adaptManagerAlert(
    wazuhAlert({
      agent: { id: '000', name: 'manager-container', ip: '' },
      top: { predecoder: { hostname: 'web02', program_name: 'containerd', timestamp: 'Nov 14 09:23:28' } },
    }),
  ).alert!;
  assert.match(dedupKeyFor(syslogAlert), /\|web01\|/);
  assert.match(dedupKeyFor(other), /\|web02\|/);
  assert.notEqual(dedupKeyFor(syslogAlert), dedupKeyFor(other));

  // A real agent still wins: agents report their own identity and the header is only a transport detail.
  const fromAgent = adaptManagerAlert(
    wazuhAlert({ agent: { id: '001', name: 'ws-01' }, top: { predecoder: { hostname: 'other.example' } } }),
  ).alert!;
  assert.equal(fromAgent.agentName, 'ws-01');
});

test('dedupKeyFor uses the agent when known and the address when there is no agent', () => {
  const withAgent = adaptManagerAlert(wazuhAlert()).alert!;
  const withoutAgent = adaptManagerAlert(wazuhAlert({ agent: { id: '', name: '' } })).alert!;
  assert.match(dedupKeyFor(withAgent), /^110012\|001\|/);
  assert.match(dedupKeyFor(withoutAgent), /^110012\|unknown-host\|/);
});
