import React, { useEffect, useState } from 'react';
import { Server, Database, Shield, Laptop, Cloud, Layers, Radio, X } from 'lucide-react';
import { FusionGraphNode, CecurVulnerability, CecurAlert } from '../../../types';
import { apiRequest } from '../../../lib/api';

interface NodeDetailsDrawerProps {
  node: FusionGraphNode | null;
  onClose: () => void;
}

type Tab = 'OVERVIEW' | 'VULNERABILITIES' | 'ALERTS';

const ICONS: Record<string, React.ReactNode> = {
  domain_controller: <Server className="w-5 h-5 text-purple-400" />,
  server: <Server className="w-5 h-5 text-purple-400" />,
  db_cluster: <Database className="w-5 h-5 text-blue-400" />,
  workstation: <Laptop className="w-5 h-5 text-cyan-400" />,
  web_server: <Layers className="w-5 h-5 text-emerald-400" />,
  cloud_s3: <Cloud className="w-5 h-5 text-amber-400" />,
  sensor_tap: <Radio className="w-5 h-5 text-[#00E5FF]" />,
};

const Row: React.FC<{ label: string; value?: React.ReactNode }> = ({ label, value }) => (
  <div className="flex items-center justify-between gap-3 py-1 border-b border-slate-800/70">
    <span className="text-[10px] uppercase text-slate-400 font-mono">{label}</span>
    <span className="font-mono text-slate-200 text-right break-all">{value ?? 'n/a'}</span>
  </div>
);

/** Shows only data that was collected for the node: inventory fields, agent counters and the agent's real findings/alerts. */
export const NodeDetailsDrawer: React.FC<NodeDetailsDrawerProps> = ({ node, onClose }) => {
  const [tab, setTab] = useState<Tab>('OVERVIEW');
  const [vulns, setVulns] = useState<CecurVulnerability[]>([]);
  const [alerts, setAlerts] = useState<CecurAlert[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    setVulns([]);
    setAlerts([]);
    setLoadError(null);
    if (!node?.agentId) return;
    let cancelled = false;
    Promise.all([
      apiRequest<{ vulnerabilities: CecurVulnerability[] }>('/api/cecur/vulnerabilities'),
      apiRequest<{ alerts: CecurAlert[] }>('/api/cecur/alerts'),
    ])
      .then(([v, a]) => {
        if (cancelled) return;
        setVulns(v.vulnerabilities.filter((x) => x.agentId === node.agentId));
        setAlerts(a.alerts.filter((x) => x.agentId === node.agentId));
      })
      .catch((err: any) => !cancelled && setLoadError(err.message || 'Failed to load findings'));
    return () => {
      cancelled = true;
    };
  }, [node?.id, node?.agentId]);

  if (!node) return null;

  const tabs: Array<{ id: Tab; label: string; count?: number }> = [
    { id: 'OVERVIEW', label: 'Overview' },
    { id: 'VULNERABILITIES', label: 'Vulnerabilities', count: vulns.length },
    { id: 'ALERTS', label: 'Alerts', count: alerts.length },
  ];

  return (
    <div
      id="node-details-drawer"
      className="bg-[#111318] border border-slate-800 rounded-xl flex flex-col h-full max-h-[720px] overflow-hidden text-slate-200 shadow-xl"
    >
      <div className="p-3.5 bg-[#151821] border-b border-slate-800 flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-9 h-9 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center shrink-0">
            {ICONS[node.type] || <Shield className="w-5 h-5 text-orange-400" />}
          </div>
          <div className="truncate">
            <h3 className="text-xs font-bold text-white truncate">{node.label}</h3>
            <div className="text-[11px] text-slate-400 font-mono mt-0.5">
              {node.ip || 'no IP'} • {node.zone} • threat {node.threatLevel}
            </div>
          </div>
        </div>
        <button
          id="close-node-details-btn"
          onClick={onClose}
          className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          title="Close details"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="px-2 pt-1.5 border-b border-slate-800 bg-[#13151D] flex gap-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            id={`node-tab-${t.id.toLowerCase()}`}
            onClick={() => setTab(t.id)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 ${
              tab === t.id ? 'bg-[#1E222D] text-[#00E5FF] border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {t.label}
            {t.count !== undefined && <span className="text-[9px] font-mono text-slate-400">{t.count}</span>}
          </button>
        ))}
      </div>

      <div className="flex-1 p-3.5 overflow-y-auto space-y-1 text-xs">
        {loadError && <div className="text-rose-400">{loadError}</div>}

        {tab === 'OVERVIEW' && (
          <>
            <Row label="Telemetry" value={node.coverage ? node.coverage.toUpperCase() : undefined} />
            <Row label="Last event" value={node.lastEventAt ? new Date(node.lastEventAt).toLocaleString() : 'none received'} />
            <Row label="Model" value={node.model} />
            <Row label="Location" value={node.location} />
            <Row label="OS" value={node.os} />
            <Row label="Agent" value={node.agentId ?? 'not enrolled'} />
            <Row label="CPU / Memory" value={node.cpuUsage !== undefined ? `${node.cpuUsage}% / ${node.memoryUsage}%` : undefined} />
            <Row label="Installed packages" value={node.installedPackagesCount} />
            <Row label="FIM monitored files" value={node.fimMonitoredFilesCount} />
            <Row label="SCA score" value={node.scaScore !== undefined ? `${node.scaScore}%` : undefined} />
            <Row label="Open alerts" value={node.activeAlertsCount ?? 0} />
            <Row label="Linked incidents" value={(node.linkedIncidentIds || []).join(', ') || 'none'} />
            <Row label="Isolated" value={node.quarantined ? 'YES' : 'NO'} />
          </>
        )}

        {tab === 'VULNERABILITIES' &&
          (!node.agentId ? (
            <div className="text-slate-400">No agent is enrolled on this asset, so no vulnerability scan data exists for it.</div>
          ) : vulns.length === 0 ? (
            <div className="text-slate-400">No vulnerabilities reported by this agent.</div>
          ) : (
            vulns.map((v) => (
              <div key={v.id} className="border border-slate-800 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between font-mono">
                  <span className="font-bold text-white">{v.cve}</span>
                  <span className="text-slate-400">CVSS {v.cvss} ({v.severity})</span>
                </div>
                <div className="text-slate-300">{v.title}</div>
                <div className="text-slate-400 font-mono">
                  {v.package} {v.installedVersion}{v.fixedVersion ? ` → ${v.fixedVersion}` : ''} • {v.status}
                </div>
              </div>
            ))
          ))}

        {tab === 'ALERTS' &&
          (alerts.length === 0 ? (
            <div className="text-slate-400">No alerts for this asset.</div>
          ) : (
            alerts.map((a) => (
              <div key={a.id} className="border border-slate-800 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between font-mono">
                  <span className="font-bold text-white">{a.ruleTitle}</span>
                  <span className="text-slate-400">L{a.ruleLevel}</span>
                </div>
                <div className="text-slate-300">{a.description}</div>
                <div className="text-slate-400 font-mono">{new Date(a.timestamp).toLocaleString()} • {a.status}</div>
              </div>
            ))
          ))}
      </div>
    </div>
  );
};
