import { db } from './db';

export interface PostureInputs {
  openCriticalIncidents: number;
  openHighIncidents: number;
  newCriticalAlerts: number;
  criticalVulnerabilities: number;
  disconnectedAgents: number;
}

export function postureInputs(): PostureInputs {
  const open = db.incidents.filter((i) => i.status !== 'RESOLVED');
  return {
    openCriticalIncidents: open.filter((i) => i.severity === 'CRITICAL').length,
    openHighIncidents: open.filter((i) => i.severity === 'HIGH').length,
    newCriticalAlerts: db.cecurAlerts.filter((a) => a.status === 'new' && a.ruleLevel >= 12).length,
    criticalVulnerabilities: db.cecurVulnerabilities.filter((v) => v.severity === 'CRITICAL' && v.status === 'VULNERABLE').length,
    disconnectedAgents: db.cecurAgents.filter((a) => a.status === 'disconnected').length,
  };
}

/**
 * 0-100 score (100 = no open findings) computed only from real open incidents, alerts, vulnerabilities and agent
 * connectivity. Returns null when nothing has been enrolled or ingested, since there is nothing to assess.
 */
export function postureScore(): { score: number | null; inputs: PostureInputs } {
  const inputs = postureInputs();
  const hasTelemetry = db.cecurAgents.length > 0 || db.cecurLogs.length > 0 || db.incidents.length > 0;
  if (!hasTelemetry) return { score: null, inputs };
  const penalty =
    inputs.openCriticalIncidents * 15 +
    inputs.openHighIncidents * 6 +
    inputs.newCriticalAlerts * 5 +
    inputs.criticalVulnerabilities * 3 +
    inputs.disconnectedAgents * 4;
  return { score: Math.max(0, 100 - penalty), inputs };
}
