import { Router, Response } from 'express';
import { db } from '../db';
import { requireAuth, requirePanel, AuthenticatedRequest } from '../middleware/auth';
import { postureScore } from '../posture';

export const executiveRouter = Router();

const DAY = 86_400_000;
const mean = (xs: number[]) => (xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10 : null);

// Executive KPI dashboard. Every figure is computed from stored incidents, alerts and agent-reported scans; no baselines are assumed.
executiveRouter.get('/', requireAuth, requirePanel('executive'), (_req: AuthenticatedRequest, res: Response) => {
  const now = Date.now();
  const openIncidents = db.incidents.filter((i) => i.status !== 'RESOLVED');
  const criticalCount = openIncidents.filter((i) => i.severity === 'CRITICAL').length;
  const { score } = postureScore();

  const resolved = db.incidents.filter((i) => i.status === 'RESOLVED');
  const mttrMinutes = mean(resolved.map((i) => (Date.parse(i.updatedAt) - Date.parse(i.createdAt)) / 60_000).filter((n) => n >= 0));
  const mttdSamples: number[] = [];
  for (const inc of db.incidents) {
    const times = inc.correlatedAlertIds
      .map((id) => db.cecurAlerts.find((a) => a.id === id)?.timestamp)
      .filter((t): t is string => !!t)
      .map((t) => Date.parse(t));
    if (times.length) mttdSamples.push((Date.parse(inc.createdAt) - Math.min(...times)) / 60_000);
  }
  const mttdMinutes = mean(mttdSamples.filter((n) => n >= 0));

  const recentOpened = db.incidents.filter((i) => now - Date.parse(i.createdAt) <= 7 * DAY).length;
  const priorOpened = db.incidents.filter((i) => {
    const age = now - Date.parse(i.createdAt);
    return age > 7 * DAY && age <= 14 * DAY;
  }).length;
  const riskTrend = `${recentOpened} incidents opened in the last 7 days (${priorOpened} in the 7 days before)`;

  // Compliance: average of agent-reported CIS benchmark scores, per benchmark.
  const byBenchmark = new Map<string, { scores: number[]; failed: number; hosts: Set<string> }>();
  for (const scan of db.cecurSCAScans) {
    const entry = byBenchmark.get(scan.benchmark) ?? { scores: [], failed: 0, hosts: new Set<string>() };
    entry.scores.push(scan.score);
    entry.failed += scan.failCount;
    entry.hosts.add(scan.agentId);
    byBenchmark.set(scan.benchmark, entry);
  }
  const complianceBreakdown = [...byBenchmark.entries()].map(([benchmark, e]) => {
    const score = mean(e.scores) ?? 0;
    return {
      framework: benchmark.replace(/_/g, ' '),
      score,
      status: score >= 90 ? 'TARGET_MET' : 'NEEDS_ATTENTION',
      auditsRemaining: e.failed,
      baseline: `${e.hosts.size} host(s), ${e.failed} failed check(s)`,
    };
  });
  const complianceReadinessScore = mean(db.cecurSCAScans.map((s) => s.score));

  // Threat vectors: alerts from the last 30 days grouped by category.
  const recentAlerts = db.cecurAlerts.filter((a) => now - Date.parse(a.timestamp) <= 30 * DAY);
  const groups = new Map<string, { count: number; recent: number; prior: number }>();
  for (const a of recentAlerts) {
    const g = groups.get(a.category) ?? { count: 0, recent: 0, prior: 0 };
    g.count++;
    const age = now - Date.parse(a.timestamp);
    if (age <= 7 * DAY) g.recent++;
    else if (age <= 14 * DAY) g.prior++;
    groups.set(a.category, g);
  }
  const threatVectors = [...groups.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .map(([name, g]) => ({
      name: name.replace(/_/g, ' '),
      share: Math.round((g.count / recentAlerts.length) * 100),
      count: g.count,
      trend: g.recent > g.prior ? 'UP' : g.recent < g.prior ? 'DOWN' : 'STABLE',
    }));

  // Incident velocity: last 6 calendar months by creation date.
  const months: Array<{ key: string; month: string; critical: number; high: number; medium: number }> = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(new Date().getFullYear(), new Date().getMonth() - i, 1);
    months.push({
      key: `${d.getFullYear()}-${d.getMonth()}`,
      month: d.toLocaleString('en-US', { month: 'short' }),
      critical: 0,
      high: 0,
      medium: 0,
    });
  }
  for (const inc of db.incidents) {
    const d = new Date(inc.createdAt);
    const m = months.find((x) => x.key === `${d.getFullYear()}-${d.getMonth()}`);
    if (!m) continue;
    if (inc.severity === 'CRITICAL') m.critical++;
    else if (inc.severity === 'HIGH') m.high++;
    else m.medium++;
  }

  res.json({
    provenance: {
      generatedAt: new Date(now).toISOString(),
      incidentRecords: db.incidents.length,
      resolvedIncidentSamples: resolved.length,
      mttdSamples: mttdSamples.length,
      scaReports: db.cecurSCAScans.length,
      alertsIn30DayWindow: recentAlerts.length,
      note: 'Metrics summarize currently available records. Empty runtime collections are not evidence of complete asset coverage or zero risk.',
    },
    kpis: {
      enterpriseRiskIndex: score,
      riskTrend,
      mttdMinutes,
      mttrMinutes,
      openCriticalIncidents: criticalCount,
      complianceReadinessScore,
      frameworksAssessed: complianceBreakdown.length,
    },
    complianceBreakdown,
    threatVectors,
    incidentVelocityMonthly: months.map(({ key: _key, ...m }) => m),
    activeExecutiveEscalations: openIncidents.filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH').slice(0, 2),
  });
});
