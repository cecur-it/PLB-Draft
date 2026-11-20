import React, { useEffect, useState } from 'react';
import { ArrowRight, BookOpen, CheckCircle2, ChevronLeft, ChevronRight, Database, FileCheck2, ListChecks, ShieldCheck } from 'lucide-react';
import { BaseModal } from './Modals';

interface GuideSection {
  title: string;
  points: string[];
}

interface PanelGuideContent {
  title: string;
  purpose: string;
  sections: GuideSection[];
  operatorChecks: string[];
  relatedPanels: string[];
  terms: Array<{ term: string; definition: string }>;
}

export const PANEL_GUIDE_TOPICS = ['overview', 'incidents', 'cecur', 'activtrak', 'sensors', 'fusion', 'errow', 'audit', 'executive', 'pricing'] as const;

type PanelGuideBase = Omit<PanelGuideContent, 'operatorChecks' | 'relatedPanels'>;
type PanelGuideWorkflow = Pick<PanelGuideContent, 'operatorChecks' | 'relatedPanels'>;

const PANEL_GUIDES: Record<string, PanelGuideBase> = {
  overview: {
    title: 'Command Center',
    purpose: 'Prioritize current operational signals before moving into the pane that owns the underlying evidence.',
    sections: [
      { title: 'Read the evidence', points: [
        'Posture, incidents, alerts, endpoint logs, sensors, and user-risk records are related operational views—not interchangeable data sources.',
        'Endpoint-log EPS is a 60-second hot-cache estimate. Sensor rates describe configured sensor nodes; SSE only reports stream connectivity.',
        'No sensors or no telemetry means NO DATA, not 100% operational. Confirm collection coverage before drawing a posture conclusion.',
      ] },
      { title: 'Recommended workflow', points: [
        'Start with critical incidents and unacknowledged alerts, then open CECUR for raw evidence or Incident Queue for case handling.',
        'Use Asset Fusion Graph to establish which inventory asset owns a signal and whether identity matching is unambiguous.',
      ] },
    ],
    terms: [
      { term: 'EPS', definition: 'Events per second. Always check its measurement window and source before comparing values.' },
      { term: 'SSE', definition: 'Server-Sent Events. A connected stream can be healthy while no events are arriving.' },
      { term: 'Posture', definition: 'A summary of available controls and evidence; it is not a guarantee that every asset is covered.' },
    ],
  },
  incidents: {
    title: 'Incident Queue',
    purpose: 'Manage security cases from triage through resolution while retaining the evidence and accountability behind each transition.',
    sections: [
      { title: 'Recommended workflow', points: [
        'Confirm severity, affected asset identity, timestamps, and linked evidence before assigning or changing a case.',
        'Acknowledgement records operator awareness. Resolution should follow validation on the affected asset, not merely a quieter dashboard.',
        'Use the audit record to reconstruct who changed the case and why.',
      ] },
      { title: 'Correlation discipline', points: [
        'Shared hostname or IP evidence can support a correlation, but duplicate addresses and stale hot-cache records require caution.',
        'Agentic output is decision support. Validate root cause against source events and asset context before containment.',
      ] },
    ],
    terms: [
      { term: 'MTTD', definition: 'Mean time to detect: elapsed time from the earliest supported event to detection.' },
      { term: 'MTTR', definition: 'Mean time to respond or resolve; check the platform metric definition before reporting it.' },
      { term: 'Correlation', definition: 'An evidence-backed relationship between records, not proof of causation by itself.' },
    ],
  },
  cecur: {
    title: 'Cecur SIEM & XDR',
    purpose: 'Inspect enrolled-endpoint telemetry, alerts, integrity findings, compliance evidence, vulnerabilities, and AI-assisted triage.',
    sections: [
      { title: 'Evidence and coverage', points: [
        'The console log view uses a bounded hot cache; OpenSearch indexing and transport acceptance are separate outcomes.',
        'Fleet hydration preserves enrolled agents, but some findings and scan views are runtime state. After recreation, queue a fresh scan when required.',
        'Agentless switches, firewalls, and wireless access points normally provide syslog or external-check evidence rather than endpoint-agent scans.',
      ] },
      { title: 'Safe AI workflow', points: [
        'Triage uses available asset context and source evidence. Check AI versus deterministic provenance and the stated confidence.',
        'Remediation jobs continue on the Host if their modal closes. Duplicate active submissions should return the existing job.',
        'Treat generated Bash, PowerShell, and Ansible as reviewable text. Test vendor-appropriate actions; nothing should run automatically.',
      ] },
    ],
    terms: [
      { term: 'FIM', definition: 'File Integrity Monitoring: detecting changes to watched files and comparing expected and observed state.' },
      { term: 'SCA', definition: 'Security Configuration Assessment: evaluating endpoint configuration against a defined policy.' },
      { term: 'OVAL/USN', definition: 'Machine-readable vulnerability definitions and Ubuntu Security Notices used for distribution-appropriate package findings.' },
    ],
  },
  activtrak: {
    title: 'ActivTrak Insider Risk',
    purpose: 'Review available user-activity and risk records without confusing locally stored observations with a verified external provider connection.',
    sections: [
      { title: 'Read the evidence', points: [
        'Check provenance and fetch status before interpreting records. An empty local dataset is not evidence of zero insider risk.',
        'Risk scores prioritize review; they do not establish intent. Correlate with endpoint, authentication, and incident evidence.',
        'External ActivTrak ingestion requires an explicit provider contract and configuration that is separate from the local session view.',
      ] },
      { title: 'Responsible use', points: [
        'Limit access through RBAC, handle employee telemetry as sensitive data, and document investigative decisions in the case record.',
      ] },
    ],
    terms: [
      { term: 'Insider risk', definition: 'Potential harm involving an authorized identity, whether accidental, negligent, compromised, or malicious.' },
      { term: 'Risk score', definition: 'A prioritization signal derived from available activity—not a determination of guilt or intent.' },
      { term: 'Provenance', definition: 'The source and processing history that tells you where a displayed record came from.' },
    ],
  },
  sensors: {
    title: 'CS3 Sensor Grid',
    purpose: 'Monitor configured network-probe nodes separately from enrolled endpoint agents and their telemetry.',
    sections: [
      { title: 'Read the evidence', points: [
        'Sensor packet rates, dropped packets, and node status belong to the sensor store; they do not measure all endpoint-log ingestion.',
        'Zero configured sensors is NO DATA. Confirm node identity and last observation before treating a stale value as current.',
        'Calibrate and reboot remain unavailable until an authenticated sensor-management channel exists; a visible control must never imply remote success.',
      ] },
      { title: 'Coverage planning', points: [
        'Use sensors for network observation, CS3 endpoint agents for host telemetry, and authorized external checks for agentless appliances.',
      ] },
    ],
    terms: [
      { term: 'Dropped packets', definition: 'Packets reported as unprocessed by a sensor; investigate capture load and collection health.' },
      { term: 'Drift', definition: 'A meaningful change from an expected configuration or observed baseline.' },
      { term: 'Management channel', definition: 'An authenticated control path required for remote actions; telemetry ingestion alone is not one.' },
    ],
  },
  fusion: {
    title: 'Asset Fusion Graph',
    purpose: 'Articulate PLB inventory, enrolled endpoints, network devices, and observed telemetry around stable asset identities.',
    sections: [
      { title: 'Identity before topology', points: [
        'Hostname and unique management-IP matches can link inventory to agents or logs. Duplicate IPs deliberately reduce match confidence.',
        'Endpoints, switches, firewalls, and wireless access points have different collection capabilities; absence of an agent is expected for many appliances.',
        'Do not infer network edges, attack paths, or blast radius when no verified relationship evidence exists.',
      ] },
      { title: 'Recommended workflow', points: [
        'Review newly enrolled or newly discovered targets, resolve ambiguous identities, then use the linked evidence in triage and root-cause analysis.',
      ] },
    ],
    terms: [
      { term: 'PLB asset', definition: 'An inventory record representing an endpoint or infrastructure device tracked by the platform.' },
      { term: 'Match confidence', definition: 'The strength and uniqueness of evidence associating telemetry with an inventory identity.' },
      { term: 'Blast radius', definition: 'The potential scope of impact, which requires reliable dependency or topology evidence.' },
    ],
  },
  errow: {
    title: 'Errow Recon',
    purpose: 'Run only explicitly authorized, allowlist-gated reconnaissance and keep task state distinct from verified external-service connectivity.',
    sections: [
      { title: 'Authorization first', points: [
        'Add only targets you are authorized to assess. An allowlist entry is a safety boundary, not proof of external reachability.',
        'Configured, reachable, and contract-verified are different integration states. A base URL alone does not make Errow LIVE.',
        'Check task provenance and persistence before relying on queued or completed state across a console restart.',
      ] },
      { title: 'Safe workflow', points: [
        'Use the safe profile, review the target and task contract, monitor terminal status, and preserve failures for diagnosis.',
        'Do not broaden scope or execute follow-on actions merely because a task produced a finding.',
      ] },
    ],
    terms: [
      { term: 'Allowlist', definition: 'The explicit set of targets eligible for a bounded operation.' },
      { term: 'Reconnaissance', definition: 'Authorized information gathering; it is separate from exploitation or automatic remediation.' },
      { term: 'Contract verification', definition: 'Evidence that the configured service implements the exact request, response, authentication, and polling API expected.' },
    ],
  },
  audit: {
    title: 'Audit & Compliance',
    purpose: 'Verify operational accountability, append-only ledger integrity, and the durability of security-relevant actions.',
    sections: [
      { title: 'Verify, do not assume', points: [
        'Health reports pending, failed, and dropped appends separately. A healthy HTTP response must still be checked for backlog or chain breakage.',
        'Verification checks hash linkage; it does not prove the absence of unaudited actions or establish that every compliance control is effective.',
        'Export and retain evidence according to lab or organizational policy without exposing credentials or session tokens.',
      ] },
      { title: 'Compliance workflow', points: [
        'Map findings and actions to control identifiers, review exceptions, and record remediation evidence with timestamps and accountable operators.',
      ] },
    ],
    terms: [
      { term: 'Hash chain', definition: 'Linked digests that make modification of earlier ledger entries detectable.' },
      { term: 'Append-only', definition: 'Records may be added but not rewritten or deleted through the protected ledger interface.' },
      { term: 'Non-repudiation', definition: 'Evidence binding an action to an identity and record, subject to the strength of authentication and key controls.' },
    ],
  },
  executive: {
    title: 'Executive KPIs',
    purpose: 'Communicate operational posture and trends while preserving the source, coverage, and limitations behind every headline number.',
    sections: [
      { title: 'Interpret responsibly', points: [
        'Executive KPIs summarize available incidents, alerts, and agent-reported SCA scans; they are only as complete as their underlying coverage.',
        'Empty or stale input should be reported as unknown or NO DATA, never converted into a claim of zero risk.',
        'Use drill-down evidence to investigate movement rather than adding unexplained targets or synthetic activity.',
      ] },
      { title: 'Reporting workflow', points: [
        'State the reporting window, affected asset population, metric definitions, and known telemetry gaps alongside posture and response trends.',
      ] },
    ],
    terms: [
      { term: 'KPI', definition: 'A defined performance indicator with a source, calculation, and reporting interval.' },
      { term: 'Coverage', definition: 'The assets and data sources actually represented by a metric.' },
      { term: 'NO DATA', definition: 'Insufficient current evidence to calculate a trustworthy operational value.' },
    ],
  },
  pricing: {
    title: 'Plans & Transactions',
    purpose: 'Review platform plan options and transaction records separately from security posture and operational authorization.',
    sections: [
      { title: 'Operational boundary', points: [
        'A completed transaction record does not grant endpoint authorization, change RBAC by itself, or prove external payment-provider settlement.',
        'Confirm deployment configuration and retain transaction references without pasting credentials, tokens, or payment secrets into support logs.',
      ] },
    ],
    terms: [
      { term: 'Transaction record', definition: 'The platform’s durable record of a checkout request and its reported outcome.' },
      { term: 'Entitlement', definition: 'A capability granted by policy; it is distinct from a displayed plan or checkout status.' },
    ],
  },
};

const PANEL_GUIDE_WORKFLOWS: Record<string, PanelGuideWorkflow> = {
  overview: {
    operatorChecks: [
      'Confirm LIVE FEED connectivity, then compare the 60-second hot-cache EPS with SENSOR RATE; they measure different sources and need not match.',
      'Open any critical alert or incident and verify its timestamp, affected asset identity, and originating evidence before assigning priority.',
      'Record known collection gaps. NO SENSOR DATA or stale cache is a coverage limitation, not an all-clear.',
    ],
    relatedPanels: ['incidents', 'cecur', 'fusion'],
  },
  incidents: {
    operatorChecks: [
      'Before acknowledgement, capture the incident ID, severity, affected asset, source timestamps, and the evidence supporting triage.',
      'Assign an accountable operator and document each status transition; acknowledgement alone does not mean containment or resolution.',
      'Resolve only after validation on the affected asset, then cross-check the resulting audit entry and executive metrics.',
    ],
    relatedPanels: ['cecur', 'audit', 'executive'],
  },
  cecur: {
    operatorChecks: [
      'Match the agent ID, hostname, and management IP to the intended endpoint before interpreting a scan or forwarding result.',
      'For AI triage, record AI versus deterministic provenance, confidence, and source evidence; Not determined is preferable to an invented classification.',
      'After a console recreation, run a fresh authorized scan if runtime findings are required. Never execute generated remediation text automatically.',
    ],
    relatedPanels: ['fusion', 'incidents', 'audit'],
  },
  activtrak: {
    operatorChecks: [
      'Read the provenance banner first: local, non-durable activity is not verified external ActivTrak ingestion.',
      'Treat an empty activity list as missing evidence, not zero insider risk; correlate with endpoint and incident records.',
      'Limit disclosure to authorized investigators and document why each sensitive activity record was reviewed.',
    ],
    relatedPanels: ['incidents', 'cecur', 'audit'],
  },
  sensors: {
    operatorChecks: [
      'Distinguish sensor-node health from endpoint-agent health and SSE connectivity; each has a different data path.',
      'Check node identity and last observation before relying on packet or drop rates. Zero configured sensors means NO SENSOR DATA.',
      'Do not report calibrate or reboot as successful unless a real authenticated management channel and confirmed result exist.',
    ],
    relatedPanels: ['overview', 'fusion', 'audit'],
  },
  fusion: {
    operatorChecks: [
      'Start with hostname and management-IP evidence, then confirm the associated enrolled agent or PLB inventory record.',
      'Resolve duplicate-IP or conflicting-hostname matches before using an asset identity in triage or reporting.',
      'Treat missing topology edges as unknown relationships; do not infer attack paths or blast radius from visual proximity.',
    ],
    relatedPanels: ['cecur', 'incidents', 'sensors'],
  },
  errow: {
    operatorChecks: [
      'Confirm written authorization, exact target scope, and allowlist membership before considering any task.',
      'Treat CONFIGURED — UNVERIFIED literally: reachability, authentication, API contract, and durable task state still require evidence.',
      'Do not execute reconnaissance during routine UI acceptance or broaden scope because an earlier task returned a finding.',
    ],
    relatedPanels: ['fusion', 'audit', 'incidents'],
  },
  audit: {
    operatorChecks: [
      'Run ledger verification and separately check durable-chain state plus pending, failed, dropped, and backlog indicators.',
      'For an incident review, retain chain number, action, actor, role, target, status, and timestamp—not session tokens or secrets.',
      'Remember that an intact hash chain proves linkage, not complete collection coverage or effectiveness of every compliance control.',
    ],
    relatedPanels: ['incidents', 'executive', 'cecur'],
  },
  executive: {
    operatorChecks: [
      'Check sample counts and provenance beside every KPI; n/a and NO DATA must remain distinct from a numeric zero.',
      'For MTTD and MTTR, verify the reporting window and which incident timestamps were actually available.',
      'Drill into incidents, CECUR, and Audit before briefing stakeholders on changes in posture or response trends.',
    ],
    relatedPanels: ['incidents', 'cecur', 'audit'],
  },
  pricing: {
    operatorChecks: [
      'Confirm the displayed plan and transaction reference against the durable transaction record before reporting an outcome.',
      'Do not equate checkout status with RBAC entitlement, endpoint authorization, or verified external payment settlement.',
      'Keep credentials, session tokens, private keys, and payment secrets out of exports and support evidence.',
    ],
    relatedPanels: ['audit', 'overview'],
  },
};

export function getPanelGuide(panelId: string): PanelGuideContent {
  const resolvedPanel = PANEL_GUIDES[panelId] ? panelId : 'overview';
  return { ...PANEL_GUIDES[resolvedPanel], ...PANEL_GUIDE_WORKFLOWS[resolvedPanel] };
}

export const PanelGuideModal: React.FC<{ panelId: string; isOpen: boolean; onClose: () => void }> = ({ panelId, isOpen, onClose }) => {
  const [selectedPanel, setSelectedPanel] = useState(PANEL_GUIDES[panelId] ? panelId : 'overview');
  const guide = getPanelGuide(selectedPanel);
  const topicIndex = Math.max(0, PANEL_GUIDE_TOPICS.findIndex((topic) => topic === selectedPanel));
  const sectionId = (suffix: string) => `guide-${selectedPanel}-${suffix}`;

  useEffect(() => {
    if (isOpen) setSelectedPanel(PANEL_GUIDES[panelId] ? panelId : 'overview');
  }, [isOpen, panelId]);

  useEffect(() => {
    if (!isOpen) return;
    const frame = requestAnimationFrame(() => {
      document.getElementById(sectionId('purpose'))?.scrollIntoView({ block: 'start' });
    });
    return () => cancelAnimationFrame(frame);
  }, [isOpen, selectedPanel]);

  const scrollToSection = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const tocButtonClass = 'px-2.5 py-1 rounded border border-[#1A3959] bg-[#0C1B2B] text-[10px] font-semibold text-[#BAE3FF] hover:text-[#FFFFFF] hover:border-[#00E5FF]/50 transition-colors';

  return (
    <BaseModal isOpen={isOpen} onClose={onClose} title={`${guide.title} — Operator Guide`} badge="Contextual Help">
      <div className="space-y-5">
        <nav aria-label="Operator guide navigation" className="sticky top-0 z-10 space-y-3 p-3 -mx-2 rounded-lg bg-[#060B12]/95 border border-[#1A3959] backdrop-blur-sm">
          <div className="flex flex-col sm:flex-row sm:items-end gap-2">
            <div className="flex-1 min-w-0">
              <label htmlFor="panel-guide-topic" className="block mb-1 text-[10px] font-bold uppercase tracking-wider text-[#00E5FF]">Guide topic</label>
              <select
                id="panel-guide-topic"
                value={selectedPanel}
                onChange={(event) => setSelectedPanel(event.target.value)}
                className="w-full min-w-0 px-3 py-2 rounded bg-[#0C1B2B] border border-[#1A3959] text-xs text-[#FFFFFF] outline-none focus:border-[#00E5FF]"
              >
                {PANEL_GUIDE_TOPICS.map((topic) => (
                  <option key={topic} value={topic}>{getPanelGuide(topic).title}</option>
                ))}
              </select>
            </div>
            <div className="flex gap-2 shrink-0">
              <button
                type="button"
                aria-label="Previous guide topic"
                disabled={topicIndex === 0}
                onClick={() => setSelectedPanel(PANEL_GUIDE_TOPICS[topicIndex - 1])}
                className="flex items-center gap-1 px-2.5 py-2 rounded border border-[#1A3959] bg-[#0C1B2B] text-[#BAE3FF] text-xs hover:border-[#00E5FF]/50 disabled:opacity-35 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-3.5 h-3.5" />Previous
              </button>
              <button
                type="button"
                aria-label="Next guide topic"
                disabled={topicIndex === PANEL_GUIDE_TOPICS.length - 1}
                onClick={() => setSelectedPanel(PANEL_GUIDE_TOPICS[topicIndex + 1])}
                className="flex items-center gap-1 px-2.5 py-2 rounded border border-[#1A3959] bg-[#0C1B2B] text-[#BAE3FF] text-xs hover:border-[#00E5FF]/50 disabled:opacity-35 disabled:cursor-not-allowed"
              >
                Next<ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          <div>
            <div className="mb-1.5 text-[10px] font-bold uppercase tracking-wider text-[#94A3B8]">On this page</div>
            <div className="flex flex-wrap gap-1.5">
              <button type="button" className={tocButtonClass} onClick={() => scrollToSection(sectionId('purpose'))}>Purpose</button>
              {guide.sections.map((section, index) => (
                <button type="button" key={section.title} className={tocButtonClass} onClick={() => scrollToSection(sectionId(`section-${index}`))}>{section.title}</button>
              ))}
              <button type="button" className={tocButtonClass} onClick={() => scrollToSection(sectionId('checks'))}>Quick checks</button>
              <button type="button" className={tocButtonClass} onClick={() => scrollToSection(sectionId('terms'))}>Terms</button>
            </div>
          </div>
        </nav>

        <section id={sectionId('purpose')} className="scroll-mt-44 flex items-start gap-3 p-4 rounded-lg bg-[#0C1B2B] border border-[#1A3959]">
          <BookOpen className="w-5 h-5 text-[#00E5FF] shrink-0 mt-0.5" />
          <div>
            <h4 className="mb-1 text-xs font-bold uppercase tracking-wider text-[#00E5FF]">Purpose</h4>
            <p className="text-sm text-[#FFFFFF] leading-relaxed">{guide.purpose}</p>
          </div>
        </section>

        {guide.sections.map((section, index) => (
          <section id={sectionId(`section-${index}`)} key={section.title} className="scroll-mt-44 space-y-2">
            <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#00E5FF]">
              <ShieldCheck className="w-4 h-4 shrink-0" />{section.title}
            </h4>
            <ul className="space-y-2">
              {section.points.map((point) => (
                <li key={point} className="flex items-start gap-2 text-xs leading-relaxed">
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#0A84FF] shrink-0 mt-0.5" />
                  <span>{point}</span>
                </li>
              ))}
            </ul>
          </section>
        ))}

        <section id={sectionId('checks')} className="scroll-mt-44 space-y-2">
          <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#00E5FF]">
            <ListChecks className="w-4 h-4 shrink-0" />Operator quick checks
          </h4>
          <ol className="grid gap-2">
            {guide.operatorChecks.map((check, index) => (
              <li key={check} className="flex items-start gap-3 p-3 rounded bg-[#0C1B2B] border border-[#1A3959] text-xs leading-relaxed">
                <span className="flex items-center justify-center w-5 h-5 shrink-0 rounded-full bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-[10px] font-mono text-[#00E5FF]">{index + 1}</span>
                <span>{check}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="flex items-start gap-3 p-3 rounded-lg border border-[#0A84FF]/35 bg-[#0A84FF]/5">
          <FileCheck2 className="w-4 h-4 shrink-0 mt-0.5 text-[#00E5FF]" />
          <div>
            <h4 className="text-xs font-bold text-[#FFFFFF]">Evidence handoff</h4>
            <p className="mt-1 text-[11px] leading-relaxed">When reporting an issue, record the panel, asset or account ID, timestamp, source/provenance, and exact error text. Never include passwords, session tokens, private keys, or other secrets.</p>
          </div>
        </section>

        <section className="space-y-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-[#00E5FF]">Continue with related guides</h4>
          <div className="flex flex-wrap gap-2">
            {guide.relatedPanels.map((relatedPanel) => (
              <button
                type="button"
                key={relatedPanel}
                onClick={() => setSelectedPanel(relatedPanel)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0C1B2B] border border-[#1A3959] text-xs text-[#BAE3FF] hover:text-[#FFFFFF] hover:border-[#00E5FF]/50 transition-colors"
              >
                {getPanelGuide(relatedPanel).title}<ArrowRight className="w-3.5 h-3.5" />
              </button>
            ))}
          </div>
        </section>

        <section id={sectionId('terms')} className="scroll-mt-44 space-y-2">
          <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#00E5FF]">
            <Database className="w-4 h-4 shrink-0" />Terms &amp; jargon
          </h4>
          <dl className="grid gap-2 sm:grid-cols-3">
            {guide.terms.map(({ term, definition }) => (
              <div key={term} className="min-w-0 p-3 rounded bg-[#0C1B2B] border border-[#1A3959]">
                <dt className="text-xs font-bold text-[#FFFFFF] break-words">{term}</dt>
                <dd className="mt-1 text-[11px] leading-relaxed break-words">{definition}</dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
    </BaseModal>
  );
};
