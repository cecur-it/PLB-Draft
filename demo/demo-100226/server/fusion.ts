import { db } from './db';
import { loadAssets } from './assets/plbAssets';
import { linkAssetsToTelemetry } from './assets/linkage';
import type {
  CecurAgent,
  CecurAlert,
  FusionGraphData,
  FusionGraphNode,
  Incident,
} from '../src/types';

type ThreatLevel = FusionGraphNode['threatLevel'];

const threatFromAlerts = (alerts: CecurAlert[], critVulns: number): ThreatLevel => {
  const maxLevel = alerts.reduce((m, a) => Math.max(m, a.ruleLevel), 0);
  if (maxLevel >= 12) return 'CRITICAL';
  if (maxLevel >= 9 || critVulns > 0) return 'HIGH';
  if (maxLevel >= 6 || alerts.length > 0) return 'ELEVATED';
  return 'NOMINAL';
};

const openAlerts = (alerts: CecurAlert[]) => alerts.filter((a) => a.status !== 'resolved' && a.status !== 'suppressed');

const incidentsFor = (identifiers: string[]): Incident[] => {
  const ids = identifiers.filter(Boolean).map((i) => i.toLowerCase());
  return db.incidents.filter(
    (inc) => inc.status !== 'RESOLVED' && inc.affectedAssets.some((a) => ids.includes(a.toLowerCase()))
  );
};

const agentNodeType = (agent: CecurAgent): FusionGraphNode['type'] => {
  if (agent.workloadType === 'cloud') return 'cloud_s3';
  return agent.os.platform === 'windows' || agent.os.platform === 'macos' ? 'workstation' : 'server';
};

/**
 * Builds the asset graph from real inventory (PLB_Assets.csv), enrolled agents, ingested alerts and incidents.
 * No topology/flow telemetry exists, so no links, attack paths or blast estimates are produced.
 */
export function buildAssetFusionGraph(): FusionGraphData {
  const nodes: FusionGraphNode[] = [];
  const claimedAgents = new Set<string>();
  const loaded = loadAssets();
  const inventory = linkAssetsToTelemetry(loaded.assets);

  for (const asset of inventory) {
    const agent = asset.telemetry.agentId ? db.cecurAgents.find((a) => a.id === asset.telemetry.agentId) : undefined;
    if (agent) claimedAgents.add(agent.id);
    const host = asset.hostname.toLowerCase();
    const ip = asset.duplicateIp ? undefined : asset.managementIp;
    const alerts = openAlerts(
      db.cecurAlerts.filter(
        (a) =>
          (!!agent && a.agentId === agent.id) ||
          a.agentName.toLowerCase() === host ||
          (!!ip && a.agentIp === ip)
      )
    );
    const critVulns = agent?.vulnerabilitiesCount.critical ?? 0;
    const threatLevel = threatFromAlerts(alerts, critVulns);
    const incidents = incidentsFor([asset.hostname, ip ?? '', agent?.name ?? '']);

    nodes.push({
      id: `asset:${asset.id}`,
      label: asset.hostname,
      type: asset.category === 'firewall' ? 'firewall' : asset.category === 'other' ? 'server' : 'network_device',
      ip: asset.managementIp ?? '',
      zone: asset.category === 'firewall' ? 'EDGE' : 'INTERNAL',
      threatLevel,
      compromised: threatLevel === 'CRITICAL',
      blastRadius: 0,
      os: agent ? `${agent.os.name} ${agent.os.version}` : asset.baseOs,
      cpuUsage: agent?.cpuUsage,
      memoryUsage: agent?.memoryUsage,
      vulnerabilitiesCount: agent ? { critical: agent.vulnerabilitiesCount.critical, high: agent.vulnerabilitiesCount.high, medium: agent.vulnerabilitiesCount.medium } : undefined,
      activeAlertsCount: alerts.length,
      agentId: agent?.id,
      linkedIncidentIds: incidents.map((i) => i.id),
      linkedAlertIds: alerts.map((a) => a.id),
      scaScore: agent?.scaScore,
      fimMonitoredFilesCount: agent?.fimMonitoredFilesCount,
      installedPackagesCount: agent?.installedPackagesCount,
      quarantined: agent?.isolationStatus ?? false,
      coverage: asset.telemetry.coverage,
      lastEventAt: asset.telemetry.lastEventAt,
      model: [asset.oem, asset.model].filter(Boolean).join(' '),
      location: asset.location,
    });
  }

  // Enrolled agents that are not in the CSV inventory are still real endpoints and are shown as such.
  for (const agent of db.cecurAgents) {
    if (claimedAgents.has(agent.id)) continue;
    const alerts = openAlerts(db.cecurAlerts.filter((a) => a.agentId === agent.id));
    const threatLevel = threatFromAlerts(alerts, agent.vulnerabilitiesCount.critical);
    const incidents = incidentsFor([agent.name, agent.hostname, agent.ip]);
    nodes.push({
      id: `agent:${agent.id}`,
      label: agent.name,
      type: agentNodeType(agent),
      ip: agent.ip,
      zone: agent.workloadType === 'cloud' ? 'CLOUD' : 'INTERNAL',
      threatLevel,
      compromised: threatLevel === 'CRITICAL',
      blastRadius: 0,
      os: `${agent.os.name} ${agent.os.version}`,
      cpuUsage: agent.cpuUsage,
      memoryUsage: agent.memoryUsage,
      vulnerabilitiesCount: { critical: agent.vulnerabilitiesCount.critical, high: agent.vulnerabilitiesCount.high, medium: agent.vulnerabilitiesCount.medium },
      activeAlertsCount: alerts.length,
      agentId: agent.id,
      linkedIncidentIds: incidents.map((i) => i.id),
      linkedAlertIds: alerts.map((a) => a.id),
      scaScore: agent.scaScore,
      fimMonitoredFilesCount: agent.fimMonitoredFilesCount,
      installedPackagesCount: agent.installedPackagesCount,
      quarantined: agent.isolationStatus,
      coverage: 'agent',
    });
  }

  const total = nodes.length;
  const withTelemetry = nodes.filter((n) => n.coverage && n.coverage !== 'none').length;
  const atRisk = nodes.filter((n) => n.threatLevel !== 'NOMINAL').length;

  return {
    nodes,
    links: [],
    criticalPath: [],
    attackPaths: [],
    source: loaded.source,
    sourceError: loaded.error,
    metrics: {
      totalAssets: total,
      compromisedCount: nodes.filter((n) => n.compromised).length,
      quarantinedCount: nodes.filter((n) => n.quarantined).length,
      activeThreatHops: 0,
      overallNetworkRiskScore: total ? Math.round((atRisk / total) * 100) : 0,
      zeroTrustCoveragePercent: total ? Math.round((withTelemetry / total) * 1000) / 10 : 0,
    },
  };
}
