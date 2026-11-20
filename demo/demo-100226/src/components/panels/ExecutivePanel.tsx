import React, { useState, useEffect } from 'react';
import {
  PieChart,
  TrendingDown,
  TrendingUp,
  Clock,
  ShieldCheck,
  ShieldAlert,
  Award,
  BarChart3,
  Layers,
  ChevronRight,
  Share2,
  Download,
  AlertTriangle,
  Database,
} from 'lucide-react';
import { apiRequest } from '../../lib/api';
import { Incident } from '../../types';
import { ExportModal } from '../common/ExportModal';
import { buildExecutiveReportExportPayload, ExportPayload } from '../../lib/exportUtils';

interface ExecutiveData {
  provenance: {
    generatedAt: string;
    incidentRecords: number;
    resolvedIncidentSamples: number;
    mttdSamples: number;
    scaReports: number;
    alertsIn30DayWindow: number;
    note: string;
  };
  kpis: {
    enterpriseRiskIndex: number | null;
    riskTrend: string;
    mttdMinutes: number | null;
    mttrMinutes: number | null;
    openCriticalIncidents: number;
    complianceReadinessScore: number | null;
    frameworksAssessed: number;
  };
  complianceBreakdown: Array<{
    framework: string;
    score: number;
    status: string;
    auditsRemaining: number;
  }>;
  threatVectors: Array<{
    name: string;
    share: number;
    count: number;
    trend: string;
  }>;
  incidentVelocityMonthly: Array<{
    month: string;
    critical: number;
    high: number;
    medium: number;
  }>;
  activeExecutiveEscalations: Incident[];
}

export const ExecutivePanel: React.FC = () => {
  const [data, setData] = useState<ExecutiveData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [exportPayload, setExportPayload] = useState<ExportPayload | null>(null);

  useEffect(() => {
    const fetchExec = async () => {
      try {
        setLoading(true);
        setError(null);
        const res = await apiRequest<ExecutiveData>('/api/executive');
        setData(res);
      } catch (err: any) {
        setError(err instanceof Error ? err.message : 'Failed to load executive KPIs.');
      } finally {
        setLoading(false);
      }
    };

    fetchExec();
  }, []);

  const handleExportBrief = () => {
    if (!data) return;
    const payload = buildExecutiveReportExportPayload(data);
    setExportPayload(payload);
    setExportModalOpen(true);
  };

  if (loading && !data) {
    return (
      <div className="p-8 text-center text-[var(--color-primary)] font-sans font-bold text-xs">
        Synthesizing Executive Threat Posture & GRC Metrics...
      </div>
    );
  }

  const kpis = data?.kpis;

  return (
    <div id="panel-executive" className="p-4 lg:p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Export & Sharing Modal */}
      <ExportModal
        isOpen={exportModalOpen}
        onClose={() => setExportModalOpen(false)}
        payload={exportPayload}
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-start gap-2">
            <PieChart className="w-5 h-5 shrink-0 text-[var(--color-primary)]" />
            <h1 className="min-w-0 text-lg leading-snug font-sans font-extrabold text-[var(--color-text-dark)] uppercase tracking-wider break-words">
              Executive Cybersecurity Posture & CISO KPIs
            </h1>
          </div>
          <p className="text-xs text-[var(--color-text-muted)] font-sans mt-0.5 break-words">
            Enterprise risk index, Mean-Time-To-Detect (MTTD), Mean-Time-To-Respond (MTTR), and regulatory compliance readiness.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            id="btn-export-executive-brief"
            onClick={handleExportBrief}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-sm bg-[var(--color-primary)] hover:bg-[#0070E0] text-white text-xs font-bold font-mono transition-colors shadow-xs cursor-pointer"
          >
            <Share2 className="w-3.5 h-3.5" />
            <span>Export Executive Briefing</span>
          </button>

          <div className="flex items-center gap-2 text-xs font-sans font-bold text-[var(--color-text-dark)] bg-[var(--color-surface)] border border-[var(--color-border-card)] px-3 py-1.5 rounded-sm shadow-xs">
            <Award className="w-4 h-4 text-[var(--color-primary)]" />
            <span>Computed from available records</span>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-sm bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /><span>{error}</span>
        </div>
      )}

      {data?.provenance && (
        <div className="p-3 rounded-sm bg-[var(--color-surface)] border border-[var(--color-border-card)] text-[11px] text-[var(--color-text-muted)] flex items-start gap-2">
          <Database className="w-4 h-4 shrink-0 text-[var(--color-primary)]" />
          <div className="min-w-0 break-words">
            <div>{data.provenance.note}</div>
            <div className="mt-1 font-mono leading-relaxed">
              Samples: {data.provenance.incidentRecords} incidents · {data.provenance.mttdSamples} MTTD · {data.provenance.resolvedIncidentSamples} MTTR · {data.provenance.scaReports} SCA reports · {data.provenance.alertsIn30DayWindow} alerts/30d
            </div>
          </div>
        </div>
      )}

      {/* Top 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Enterprise Risk Index */}
        <div className="app-card p-4 min-w-0 flex flex-col">
          <div className="min-h-8 text-[11px] leading-4 font-sans uppercase text-[var(--color-text-muted)] font-extrabold tracking-wider break-words">Enterprise Risk Index</div>
          <div className="mt-2 flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span
              className={`text-3xl leading-tight font-sans font-extrabold ${
                (kpis?.enterpriseRiskIndex ?? 0) > 75 ? 'text-emerald-700' : 'text-blue-700'
              }`}
            >
              {kpis?.enterpriseRiskIndex ?? 'n/a'}
            </span>
            {kpis?.enterpriseRiskIndex != null && <span className="text-xs font-mono text-[var(--color-text-muted)]">/100</span>}
          </div>
          <p className="mt-1 text-[11px] leading-4 font-mono text-[var(--color-text-muted)] break-words">Computed from open findings</p>
          <div className="mt-auto pt-2 text-[11px] leading-4 font-sans font-bold text-[var(--color-primary)] flex items-start gap-1">
            <TrendingUp className="w-3.5 h-3.5 shrink-0 text-[var(--color-primary)]" />
            <span className="min-w-0 break-words">{kpis?.riskTrend}</span>
          </div>
        </div>

        {/* MTTD */}
        <div className="app-card p-4 min-w-0 flex flex-col">
          <div className="min-h-8 text-[11px] leading-4 font-sans uppercase text-[var(--color-text-muted)] font-extrabold tracking-wider break-words">Mean Time to Detect (MTTD)</div>
          <div className="mt-2 flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="text-3xl leading-tight font-sans font-extrabold text-[var(--color-primary)]">{kpis?.mttdMinutes ?? 'n/a'}</span>
            {kpis?.mttdMinutes != null && <span className="text-xs font-mono text-[var(--color-text-muted)]">Minutes</span>}
          </div>
          <p className="mt-auto pt-2 text-[11px] leading-4 text-emerald-800 font-sans font-bold break-words">
            Alert timestamp to incident creation
          </p>
        </div>

        {/* MTTR */}
        <div className="app-card p-4 min-w-0 flex flex-col">
          <div className="min-h-8 text-[11px] leading-4 font-sans uppercase text-[var(--color-text-muted)] font-extrabold tracking-wider break-words">Mean Time to Respond (MTTR)</div>
          <div className="mt-2 flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="text-3xl leading-tight font-sans font-extrabold text-[var(--color-text-dark)]">{kpis?.mttrMinutes ?? 'n/a'}</span>
            {kpis?.mttrMinutes != null && <span className="text-xs font-mono text-[var(--color-text-muted)]">Minutes</span>}
          </div>
          <p className="mt-auto pt-2 text-[11px] leading-4 text-[var(--color-text-muted)] font-sans break-words">
            Creation to latest update on resolved records
          </p>
        </div>

        {/* Compliance Readiness */}
        <div className="app-card p-4 min-w-0 flex flex-col">
          <div className="min-h-8 text-[11px] leading-4 font-sans uppercase text-[var(--color-text-muted)] font-extrabold tracking-wider break-words">Compliance Readiness</div>
          <div className="mt-2 flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="text-3xl leading-tight font-sans font-extrabold text-emerald-700">
              {kpis?.complianceReadinessScore != null ? `${kpis.complianceReadinessScore}%` : 'n/a'}
            </span>
          </div>
          <p className="mt-1 text-[11px] leading-4 font-mono text-[var(--color-text-muted)] break-words">Mean reported SCA score</p>
          <p className="mt-auto pt-2 text-[11px] leading-4 text-[var(--color-text-muted)] font-sans break-words">
            {kpis?.frameworksAssessed ?? 0} benchmark(s) with agent-reported results
          </p>
        </div>
      </div>

      {/* Middle Section: Compliance Framework Breakdown & Threat Vectors */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Compliance Frameworks */}
        <div className="app-card p-5 space-y-4 min-w-0">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <h2 className="min-w-0 text-xs leading-relaxed font-sans font-extrabold text-[var(--color-text-dark)] uppercase tracking-wider flex items-start gap-2 break-words">
              <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-700" />
              <span>Regulatory Compliance Readiness</span>
            </h2>
            <span className="shrink-0 text-[10px] font-sans uppercase font-bold text-[var(--color-text-muted)]">Reported benchmark results</span>
          </div>

          <div className="space-y-3">
            {data && data.complianceBreakdown.length === 0 && (
              <p className="text-xs text-[var(--color-text-muted)]">No agent-reported SCA benchmark results are available.</p>
            )}
            {data?.complianceBreakdown.map((item, idx) => (
              <div key={idx} className="p-3 bg-[var(--color-surface-subtle)] rounded-sm border border-[var(--color-border-card)] space-y-1.5 text-xs font-sans">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <span className="min-w-0 font-bold text-[var(--color-text-dark)] break-words">{item.framework}</span>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold text-emerald-700 font-mono">{item.score}%</span>
                    <span className={`text-[10px] uppercase font-bold px-1.5 py-0.2 border rounded-sm ${item.status === 'TARGET_MET' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'}`}>
                      {item.status}
                    </span>
                  </div>
                </div>
                <div className="w-full bg-[var(--color-border-card)] rounded-full h-1.5 overflow-hidden">
                  <div className={`h-full rounded-full ${item.status === 'TARGET_MET' ? 'bg-emerald-700' : 'bg-amber-600'}`} style={{ width: `${item.score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Vector Distribution */}
        <div className="app-card p-5 space-y-4 min-w-0">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <h2 className="min-w-0 text-xs leading-relaxed font-sans font-extrabold text-[var(--color-text-dark)] uppercase tracking-wider flex items-start gap-2 break-words">
              <BarChart3 className="w-4 h-4 shrink-0 text-[var(--color-primary)]" />
              <span>Active Threat Vector Distribution</span>
            </h2>
            <span className="shrink-0 text-[10px] font-sans uppercase font-bold text-[var(--color-text-muted)]">Trailing 30 Days</span>
          </div>

          <div className="space-y-3">
            {data && data.threatVectors.length === 0 && (
              <p className="text-xs text-[var(--color-text-muted)]">No alerts were recorded in the trailing 30-day window. This does not establish zero risk.</p>
            )}
            {data?.threatVectors.map((tv, idx) => (
              <div key={idx} className="p-3 bg-[var(--color-surface-subtle)] rounded-sm border border-[var(--color-border-card)] space-y-1.5 text-xs font-sans">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <span className="min-w-0 text-[var(--color-text-dark)] font-bold break-words">{tv.name}</span>
                  <span className="text-[var(--color-primary)] font-bold font-mono">{tv.share}% ({tv.count} events)</span>
                </div>
                <div className="w-full bg-[var(--color-border-card)] rounded-full h-1.5 overflow-hidden">
                  <div
                    className="h-full bg-[var(--color-primary)] rounded-full"
                    style={{ width: `${tv.share * 2}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Monthly Incident Velocity Bar Chart */}
      <div className="app-card p-5 space-y-4">
        <div className="text-xs font-sans font-extrabold text-[var(--color-text-dark)] uppercase tracking-wider">
          Monthly Incident Resolution Velocity
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 text-center text-xs font-sans">
          {data?.incidentVelocityMonthly.map((m, idx) => (
            <div key={idx} className="min-w-0 p-3 bg-[var(--color-surface-subtle)] rounded-sm border border-[var(--color-border-card)] space-y-2">
              <div className="text-[var(--color-text-dark)] font-extrabold break-words">{m.month}</div>
              <div className="space-y-1 text-[11px] font-mono">
                <div className="text-rose-700 font-bold">Crit: {m.critical}</div>
                <div className="text-blue-800 font-bold">High: {m.high}</div>
                <div className="text-[var(--color-primary)] font-bold">Med: {m.medium}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

