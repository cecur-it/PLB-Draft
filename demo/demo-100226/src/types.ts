export type UserRole = 'analyst' | 'admin' | 'auditor' | 'executive' | 'model_curator' | 'gpu_capacity_owner';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: UserRole;
  displayName: string;
  email: string;
  avatar: string;
  title: string;
  department: string;
  createdAt: string;
  lastLogin: string;
}

export interface HotCacheEpsEstimate {
  name: 'cecur_hot_cache_60s_eps';
  value: number;
  unit: 'events_per_second';
  source: 'db.cecurLogs';
  cache: 'in_memory_hot_cache';
  windowSeconds: 60;
  windowStart: string;
  windowEnd: string;
  eventCount: number;
  cacheEventCount: number;
  latestEventAt: string | null;
  status: 'current' | 'stale' | 'no_data';
  stale: boolean;
}

export interface SensorHealthSummary {
  total: number;
  online: number;
  degraded: number;
  offline: number;
  status: 'NO_SENSORS' | 'OFFLINE' | 'DEGRADED' | 'OPERATIONAL';
}

export interface SensorNode {
  id: string;
  name: string;
  location: string;
  ipAddress: string;
  type: 'edge_gateway' | 'dmz_tap' | 'core_db_probe' | 'cloud_vpc_flow' | 'ics_scada_monitor';
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'MAINTENANCE';
  packetRate: number; // packets/sec
  droppedPackets: number; // %
  jitterMs: number;
  anomalyRate: number; // %
  cpuUsage: number; // %
  memoryUsage: number; // %
  lastPing: string;
  firmwareVersion: string;
  alerts24h: number;
}

// -------------------------------------------------------------
// CECUR SIEM & XDR TYPES
// -------------------------------------------------------------

export type CecurWorkloadType = 'local' | 'virtual' | 'container' | 'cloud';
export type CecurAgentStatus = 'active' | 'disconnected' | 'pending' | 'isolated';

export interface CecurAgent {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  os: {
    name: string;
    platform: 'linux' | 'windows' | 'macos' | 'container';
    version: string;
    arch: string;
  };
  workloadType: CecurWorkloadType;
  status: CecurAgentStatus;
  version: string;
  lastKeepAlive: string;
  registeredAt: string;
  group: string[];
  cpuUsage: number; // %
  memoryUsage: number; // %
  diskUsage: number; // %
  installedPackagesCount: number;
  vulnerabilitiesCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  fimMonitoredFilesCount: number;
  scaScore: number; // 0-100
  isolationStatus: boolean;
}

export type CecurAlertCategory =
  | 'log_anomaly'
  | 'vulnerability'
  | 'fim'
  | 'sca'
  | 'authentication'
  | 'malware'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'web_attack';

export interface CecurAlert {
  id: string;
  timestamp: string;
  ruleId: number;
  ruleLevel: number; // 1 - 15
  ruleTitle: string;
  description: string;
  category: CecurAlertCategory;
  agentId: string;
  agentName: string;
  agentIp: string;
  agentOs: string;
  complianceTags: string[]; // e.g. ["PCI_DSS_10.2.4", "NIST_800_53_AC_7", "HIPAA_164.312", "GDPR_Art_32"]
  mitreTactic?: string;
  mitreTechnique?: string;
  decoderMatched: string;
  srcIp?: string;
  destIp?: string;
  user?: string;
  process?: string;
  filePath?: string;
  hash?: string;
  fullLog: string;
  status: 'new' | 'investigating' | 'resolved' | 'suppressed';
  /** First/last occurrence and repeat count when the same alert is deduplicated. */
  firstSeen?: string;
  lastSeen?: string;
  count?: number;
}

export interface CecurLogEvent {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  source: 'syslog' | 'auth.log' | 'auditd' | 'windows_event' | 'nginx' | 'k8s_audit' | 'cloudtrail';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  message: string;
  fields: Record<string, any>;
  isAnomaly: boolean;
  anomalyScore: number; // 0.0 - 1.0
  decoder: string;
}

export interface CecurLogAnomalyResult {
  triageSummary: string;
  severityAssessment: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitreTactic: string;
  mitreTechnique: string;
  probableRootCause: string;
  recommendedImmediateAction: string;
  confidenceScore: number;
  engineUsed: string;
  source: 'ai' | 'deterministic';
  assetContext: AssetResolution;
}

export interface CecurVulnerability {
  id: string;
  cve: string;
  title: string;
  package: string;
  installedVersion: string;
  fixedVersion: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss: number;
  status: 'VULNERABLE' | 'PATCHED' | 'MITIGATED';
  agentId: string;
  agentName: string;
  agentOs: string;
  detectionDate: string;
  exploitAvailable: boolean;
  remediationGuide: string;
  compliance: string[];
}

export interface CecurRemediationResult {
  executiveSummary: string;
  patchSteps: string[];
  bashScript: string;
  powerShellScript: string;
  ansiblePlaybook: string;
  exploitMitigationWorkaround: string;
  engineUsed: string;
  source: 'ai' | 'deterministic';
}

export type CecurRemediationJobStatus = 'queued' | 'running' | 'completed' | 'fallback' | 'failed' | 'interrupted';

export interface CecurRemediationJob {
  id: string;
  ownerId: string;
  ownerUsername: string;
  vulnerability: CecurVulnerability;
  fingerprint: string;
  status: CecurRemediationJobStatus;
  timeoutMs: number;
  createdAt: string;
  updatedAt: string;
  startedAt?: string;
  completedAt?: string;
  message?: string;
  remediation?: CecurRemediationResult;
}

export interface CecurFIMEvent {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  path: string;
  eventType: 'MODIFIED' | 'ADDED' | 'DELETED' | 'PERMISSIONS_CHANGED';
  fileType: 'binary' | 'config' | 'system' | 'credential' | 'web_root';
  oldHash?: string;
  newHash?: string;
  oldPerms?: string;
  newPerms?: string;
  processName?: string;
  user?: string;
  isTamperAlert: boolean;
  compliance: string[];
}

export interface CecurSCACheck {
  id: string;
  checkId: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'MANUAL';
  rationale: string;
  remediation: string;
  compliance: string[];
  section: string;
}

export interface CecurSCAScan {
  id: string;
  benchmark: 'CIS_Linux_2.0' | 'CIS_Windows_11' | 'CIS_Kubernetes_1.8' | 'CIS_macOS_14';
  agentId: string;
  agentName: string;
  agentOs: string;
  passCount: number;
  failCount: number;
  totalChecks: number;
  score: number; // 0-100%
  lastScanDate: string;
  checks: CecurSCACheck[];
}

export type CecurScanKind = 'fim' | 'sca' | 'vuln';
export type CecurScanJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'timeout';

/** A scan the console asked an enrolled agent to run. Results are whatever the agent reports back; nothing is generated server-side. */
export interface CecurScanJob {
  id: string;
  kind: CecurScanKind;
  agentId: string;
  agentName: string;
  status: CecurScanJobStatus;
  requestedBy: string;
  requestedAt: string;
  startedAt?: string;
  completedAt?: string;
  /** Counts reported by the agent (files checked, checks run, packages evaluated). */
  summary?: Record<string, number>;
  error?: string;
}

export type AssetCategory = 'endpoint' | 'switch' | 'wireless_ap' | 'firewall' | 'other';
export type AssetCriticality = 'TIER_0_MISSION_CRITICAL' | 'TIER_1_HIGH' | 'TIER_2_MEDIUM' | 'TIER_3_LOW';
export type AssetResolutionSource = 'plb_inventory' | 'enrolled_agent';

/** One row of PLB_Assets.csv, optionally linked to the real telemetry received for it. */
export interface AssetRecord {
  id: string;
  sourceRow: number;
  cmdbNumber?: string;
  hostname: string;
  managementIp?: string;
  location: string;
  category: Exclude<AssetCategory, 'endpoint'>;
  assetType: string;
  /** Only populated when the inventory explicitly records it; never inferred from device role. */
  criticality?: AssetCriticality;
  role: string;
  oem: string;
  model: string;
  serialNo?: string;
  monitoringTool?: string;
  adminAccountHolders: string[];
  authentication?: string;
  configBackup?: string;
  baseOs?: string;
  softwareVersion?: string;
  requiredSoftwareVersion?: string;
  endOfLife?: string;
  endOfSupport?: string;
  assetOwner?: string;
  managedBy?: string;
  redundancy: boolean;
  thresholds: { cpu?: string; memory?: string; interface?: string };
}

export interface ResolvedAssetIdentity {
  id: string;
  hostname: string | null;
  ip: string | null;
  category: AssetCategory;
  criticality: AssetCriticality | null;
  sources: AssetResolutionSource[];
  agentId: string | null;
  inventoryAssetId: string | null;
}

export interface AssetResolutionEvidence {
  field: string;
  kind: 'agent_id' | 'hostname' | 'ip';
  observedValue: string;
  normalizedValue: string;
  candidateIds: string[];
}

export interface AssetResolution {
  resolver: 'plb_inventory_enrolled_agents_v1';
  status: 'matched' | 'ambiguous' | 'unmatched';
  scope: 'identity_only';
  asset: ResolvedAssetIdentity | null;
  candidates: ResolvedAssetIdentity[];
  matchConfidence: number;
  matchMethod: 'agent_id' | 'hostname' | 'ip' | null;
  evidence: AssetResolutionEvidence[];
  inventorySource: string | null;
  inventoryError?: string;
  reason: string;
}

export interface AssetTelemetryView extends AssetRecord {
  telemetry: {
    /** agent = CS3 forwarder enrolled for this host; syslog = events received that name this host/IP; none = nothing received yet */
    coverage: 'agent' | 'syslog' | 'none';
    agentId?: string;
    eventCount: number;
    lastEventAt?: string;
    /** Why scans are not applicable, e.g. network appliances cannot run the CS3 agent. */
    scanSupport: string;
  };
  softwareCompliant?: boolean;
  duplicateIp: boolean;
}

export interface CecurComplianceDomain {
  name: string;
  score: number;
  rulesCount: number;
  passingRules: number;
  familyCode?: string; // e.g., 'AC', 'AU', '03.01', '03.03'
  description?: string;
}

export interface POAMItem {
  id: string;
  controlId: string;
  title: string;
  description: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  scheduledCompletion: string;
  status: 'IN_PROGRESS' | 'SCHEDULED' | 'VALIDATING';
  owner: string;
  milestones: string[];
}

export interface CecurComplianceStandard {
  id: 'PCI_DSS' | 'HIPAA' | 'GDPR' | 'NIST_800_53' | 'NIST_800_171';
  name: string;
  version: string;
  description: string;
  complianceScore: number; // 0-100%
  controlsCount: number;
  passedControls: number;
  failedControls: number;
  topGaps: string[];
  domains: CecurComplianceDomain[];
  sprsScore?: number; // DoD Supplier Performance Risk System score (110 max baseline)
  cuiEnclaveStatus?: string;
  cmmcLevelAlignment?: string;
  poamItems?: POAMItem[];
}

export interface CecurServerStatus {
  service: string;
  uptimeSeconds: number;
  /** null when no OpenSearch indexer is enabled/reachable; values are read live from the cluster. */
  indexerStatus: {
    status: 'green' | 'yellow' | 'red';
    indexedEvents: number;
    storageMb: number;
    searchLatencyMs: number;
  } | null;
  /** Events/second received over the last minute, computed from real ingested events. */
  ingestion: {
    eps: number;
    eventsLastMinute: number;
    lastEventAt: string | null;
    bufferedEvents: number;
  };
  serverStatus: {
    decodersLoaded: number;
    rulesLoaded: number;
  };
  agentsSummary: {
    total: number;
    active: number;
    disconnected: number;
    isolated: number;
    byWorkload: {
      local: number;
      virtual: number;
      container: number;
      cloud: number;
    };
  };
  scanQueue: {
    queued: number;
    running: number;
  };
  inference: {
    active: boolean;
    backend?: string;
    profile?: string;
    triageModel?: string;
    forensicModel?: string;
  };
  message: string;
}

export interface CecurActiveResponseRequest {
  agentId: string;
  command: 'isolate-host' | 'unisolate-host' | 'drop-ip' | 'terminate-process' | 'trigger-fim-scan' | 'trigger-sca-scan' | 'restart-agent';
  targetIp?: string;
  processName?: string;
  arguments?: string[];
}

// -------------------------------------------------------------
// EXISTING SOC MODULES (ActivTrak, Incidents, Fusion, etc.)
// -------------------------------------------------------------

export interface ActivTrakSession {
  id: string;
  timestamp: string;
  userId: string;
  userName: string;
  department: string;
  deviceId: string;
  currentApp: string;
  windowTitle: string;
  category: 'productive' | 'risky' | 'neutral' | 'suspicious';
  riskScore: number; // 0-100
  flaggedActivity?: string;
  activeSeconds: number;
  dataTransferredMb: number;
  usbConnected: boolean;
  cloudStorageUpload: boolean;
}

export interface ActivTrakProvenance {
  source: 'LOCAL_IN_MEMORY';
  persistent: false;
  externalApiConnected: false;
  message: string;
}

export interface ActivTrakSessionsResponse {
  total: number;
  sessions: ActivTrakSession[];
  provenance: ActivTrakProvenance;
}

export interface ActivTrakRiskyUsersResponse {
  count: number;
  users: ActivTrakSession[];
  provenance: ActivTrakProvenance;
}

export interface Incident {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  category: string;
  assignedTo: string;
  createdAt: string;
  updatedAt: string;
  mitreTactic: string;
  mitreTechnique: string;
  rootCause: string;
  affectedAssets: string[];
  correlatedAlertIds: string[];
  timeline: Array<{
    time: string;
    source: string;
    event: string;
    severity?: string;
  }>;
  aiSummary?: string;
  playbookSteps: Array<{
    step: number;
    title: string;
    status: 'pending' | 'completed' | 'in_progress';
    actionType: string;
  }>;
}

export interface TargetAllowlistEntry {
  id: string;
  hostname: string;
  ipRange: string;
  ownerDepartment: string;
  authorizedBy: string;
  authorizationDate: string;
  status: 'AUTHORIZED' | 'PENDING_REVIEW' | 'REVOKED';
  notes: string;
  scanCount: number;
  lastScanned?: string;
}

export interface ErrowFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cve?: string;
  cvss?: number;
  port?: number;
  endpoint?: string;
  description: string;
  remediation: string;
}

export interface ErrowTask {
  id: string;
  targetId: string;
  targetHost: string;
  tool: 'nmap_scan' | 'nuclei_scan' | 'gobuster_scan' | 'subfinder_scan';
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  startedAt: string;
  completedAt?: string;
  triggeredBy: string;
  findingsCount: number;
  rawOutput: string;
  findings: ErrowFinding[];
  /** Every result originates from the remote Errow connector; nothing is generated locally. */
  source: 'ERROW_REMOTE';
  remoteTaskId?: string;
  /** Present when the connector call failed (status FAILED). */
  error?: string;
}

export interface ErrowMemoryPersistence {
  storage: 'IN_MEMORY';
  durable: false;
  scopes: readonly ['ALLOWLIST', 'JOBS'];
  message: string;
}

export interface ErrowStatus {
  mode: 'UNCONFIGURED' | 'CONFIGURED';
  configured: boolean;
  credentialConfigured: boolean;
  reachability: 'UNVERIFIED';
  verified: false;
  baseUrl?: string;
  message: string;
  activeScanCount: number;
  availableTools: readonly string[];
  agentMode: string;
  sandboxRuntime: string;
  integrations: {
    caido: boolean;
    projectdiscovery: boolean;
  };
  persistence: ErrowMemoryPersistence;
}

export interface ErrowAllowlistResponse {
  targets: TargetAllowlistEntry[];
  persistence: ErrowMemoryPersistence;
}

export interface ErrowJobsResponse {
  jobs: ErrowTask[];
  persistence: ErrowMemoryPersistence;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actorId: string;
  actorUsername: string;
  actorRole: UserRole;
  action: string;
  panel: string;
  targetResource?: string;
  ipAddress: string;
  status: 'ALLOW' | 'DENY_403' | 'SUCCESS' | 'ERROR';
  details: string;
  nistControls?: string[]; // e.g., ["AU-2", "AU-3", "03.03.01"]
  /** Monotonic ledger sequence. Continues the persisted chain_no after boot hydration. */
  seq?: number;
  /** Hash of the previous link; GENESIS_HASH for the first entry of an empty ledger. */
  prevHash?: string;
  chainHash?: string; // SHA-256 tamper-evident integrity hash (AU-9, 03.03.03)
  /** Digest algorithm revision; entries without it predate recomputable hashing. */
  hashVersion?: number;
  cuiProtected?: boolean; // CUI Enclave Protected
  nonRepudiationVerified?: boolean; // Non-repudiation audit proof (AU-10, 03.03.04)
}

export interface FusionGraphNode {
  id: string;
  label: string;
  type: 'domain_controller' | 'db_cluster' | 'workstation' | 'web_server' | 'firewall' | 'cloud_s3' | 'sensor_tap' | 'server' | 'network_device';
  ip: string;
  zone: 'INTERNAL' | 'DMZ' | 'CLOUD' | 'EDGE';
  threatLevel: 'NOMINAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
  compromised: boolean;
  blastRadius: number; // 0-100
  x?: number;
  y?: number;
  os?: string;
  cpuUsage?: number;
  memoryUsage?: number;
  vulnerabilitiesCount?: { critical: number; high: number; medium: number };
  activeAlertsCount?: number;
  connectedUser?: string;
  services?: string[];
  mitreTechniques?: string[];
  agentId?: string;
  criticality?: 'TIER_0_MISSION_CRITICAL' | 'TIER_1_HIGH' | 'TIER_2_MEDIUM' | 'TIER_3_LOW';
  assetValueUSD?: number;
  complianceTags?: string[];
  linkedIncidentIds?: string[];
  linkedAlertIds?: string[];
  linkedSensorIds?: string[];
  scaScore?: number;
  fimMonitoredFilesCount?: number;
  installedPackagesCount?: number;
  quarantined?: boolean;
  /** Real telemetry coverage for this asset (enrolled agent, syslog events naming it, or none). */
  coverage?: 'agent' | 'syslog' | 'none';
  lastEventAt?: string;
  model?: string;
  location?: string;
}

export interface FusionGraphLink {
  id?: string;
  source: string;
  target: string;
  type: 'traffic' | 'auth_flow' | 'lateral_movement' | 'exfiltration_path';
  threat: boolean;
  protocol?: string;
  port?: number;
  bandwidthMbps?: number;
  mitreTechnique?: string;
  description?: string;
  activeStatus?: 'ACTIVE' | 'SEVERED' | 'THROTTLED';
  latencyMs?: number;
}

export interface AttackPathStep {
  stepNumber: number;
  title: string;
  stage: 'INITIAL_FOOTHOLD' | 'CREDENTIAL_ACCESS' | 'PRIVILEGE_ESCALATION' | 'LATERAL_PIVOT' | 'DATA_STAGING' | 'EXFILTRATION';
  sourceNodeId: string;
  targetNodeId: string;
  mitreTactic: string;
  mitreTechnique: string;
  description: string;
  protocol: string;
  payloadCommand: string;
  detectionSource: string;
  confidence: number;
  remediationAction: string;
}

export interface AttackPath {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  status: 'ACTIVE_THREAT' | 'CONTAINED';
  associatedIncidentId?: string;
  summary: string;
  steps: AttackPathStep[];
  estimatedTimeMinutes: number;
  potentialImpact: string;
}

export interface FusionGraphData {
  nodes: FusionGraphNode[];
  links: FusionGraphLink[];
  criticalPath: string[];
  attackPaths?: AttackPath[];
  activeAttackPathId?: string;
  /** Path of the inventory CSV that was loaded, and any load error. */
  source?: string | null;
  sourceError?: string;
  metrics?: {
    totalAssets: number;
    compromisedCount: number;
    quarantinedCount: number;
    activeThreatHops: number;
    overallNetworkRiskScore: number;
    zeroTrustCoveragePercent: number;
  };
}

export interface PricingTransaction {
  id: string;
  type: 'subscription' | 'ai_credits' | 'enterprise_quote';
  tierId: string;
  tierName: string;
  amountUSD: number;
  billingCycle: 'MONTHLY' | 'ANNUAL_PREPAID';
  aiCreditsPurchased: number;
  paymentMethod: 'credit_card' | 'procurement_po' | 'ach_transfer';
  billingOrg?: string;
  operatorEmail: string;
  operatorUsername: string;
  operatorRole: string;
  firebaseProjectId: string;
  firestoreDatabaseId: string;
  firestoreDocId?: string;
  status: 'COMPLETED' | 'PENDING' | 'REFUNDED';
  createdAt: string;
}

// -------------------------------------------------------------
// CS3 PUBLIC SHOWCASE & ARCHITECTURE TYPES
// -------------------------------------------------------------

export interface CapabilityBullet {
  text: string;
  isNew?: boolean;
}

export interface CapabilityItem {
  id: string;
  columnNumber: string;
  title: string;
  categoryTag: string;
  description: string;
  sensorFeed: string;
  badge: string;
  bullets: CapabilityBullet[];
}

export interface SectorSolution {
  id: string;
  sectorName: string;
  badge: string;
  description: string;
  protocolNote: string;
  threatSurface: string;
  bullets: string[];
}

export interface LeaderProfile {
  name: string;
  role: string;
  callsign: string;
  experience: string;
  bio: string;
  specialties: string[];
}

export interface ProgramTier {
  id: string;
  name: string;
  cadence: string;
  target: string;
  features: string[];
}

export interface CredentialBadge {
  code: string;
  name: string;
  authority: string;
  standard: string;
  level: string;
}

