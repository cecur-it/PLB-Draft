import {
  CecurAgent,
  CecurAlert,
  CecurLogEvent,
  CecurVulnerability,
  CecurFIMEvent,
  CecurSCAScan,
  CecurComplianceStandard,
  CecurServerStatus,
  CecurScanJob,
} from '../../src/types';
import { getAIStatus } from '../ai/cecurAI';
import { getIndexerStats } from '../integrations/opensearchSink';

export interface CecurDecoder {
  name: string;
  type: string;
  description: string;
  patternSample: string;
  fieldsExtracted: string[];
}

export interface CecurRule {
  id: number;
  level: number; // 1-15
  category: string;
  title: string;
  description: string;
  mitreTactic: string;
  mitreTechnique: string;
  compliance: string[];
  decoder: string;
}

export class CecurEngine {
  public decoders: CecurDecoder[] = [
    {
      name: 'cecur-syslog',
      type: 'rfc5424',
      description: 'Standard Linux RFC 5424 / RFC 3164 system log decoder',
      patternSample: '<34>1 2026-08-21T12:00:00Z web-prod-01 sshd 1248 - - Failed password',
      fieldsExtracted: ['timestamp', 'hostname', 'program_name', 'pid', 'message', 'src_ip', 'user'],
    },
    {
      name: 'cecur-auth-pam',
      type: 'linux_pam',
      description: 'Linux Pluggable Authentication Modules (PAM) & SSH daemon security log parser',
      patternSample: 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.42 user=root',
      fieldsExtracted: ['user', 'src_ip', 'auth_status', 'tty', 'uid'],
    },
    {
      name: 'cecur-auditd',
      type: 'linux_auditd',
      description: 'Linux Kernel Audit Subsystem (Auditd) syscall and file access decoder',
      patternSample: 'type=SYSCALL msg=audit(1787328000.123:456): arch=c000003e syscall=59 success=yes pid=4128 exe="/bin/bash"',
      fieldsExtracted: ['syscall', 'exe', 'pid', 'ppid', 'uid', 'comm', 'success'],
    },
    {
      name: 'cecur-windows-evtx',
      type: 'windows_xml',
      description: 'Microsoft Windows Security Event Log decoder (EventIDs 4624, 4625, 4688, 7045)',
      patternSample: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4688</EventID></System>...</Event>',
      fieldsExtracted: ['EventID', 'ProcessName', 'ParentProcessName', 'TargetUserName', 'LogonType', 'IpAddress'],
    },
    {
      name: 'cecur-k8s-audit',
      type: 'json_k8s',
      description: 'Kubernetes API Server Audit Log & Container Runtime event parser',
      patternSample: '{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","verb":"create","resource":"pods"}',
      fieldsExtracted: ['verb', 'user', 'namespace', 'resource', 'pod', 'container', 'responseStatus'],
    },
    {
      name: 'cecur-cloud-flow',
      type: 'cloud_vpc',
      description: 'CS3 Cloud VPC Flow & AWS CloudTrail JSON network and management event decoder',
      patternSample: '{"jsonPayload":{"connection":{"src_ip":"10.240.0.12","dest_ip":"172.16.20.14","dest_port":443}}}',
      fieldsExtracted: ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'bytes_sent', 'action'],
    },
  ];

  public rulesCatalog: CecurRule[] = [
    {
      id: 10010,
      level: 10,
      category: 'authentication',
      title: 'sshd: Multiple failed authentication attempts (Brute-force attack)',
      description: 'Multiple authentication failures detected in high succession against service account.',
      mitreTactic: 'Credential Access',
      mitreTechnique: 'T1110.001 - Password Guessing',
      compliance: ['PCI_DSS_10.2.4', 'PCI_DSS_10.2.5', 'NIST_800_53_AC_7', 'HIPAA_164.312.a.2.iv'],
      decoder: 'cecur-auth-pam',
    },
    {
      id: 10020,
      level: 14,
      category: 'privilege_escalation',
      title: 'LSASS Memory Dumping / Credential Harvesting Signature',
      description: 'Unauthorized process opened memory read handle to Windows Local Security Authority Subsystem Service (LSASS).',
      mitreTactic: 'Credential Access',
      mitreTechnique: 'T1003.001 - LSASS Memory Dumping',
      compliance: ['NIST_800_53_SI_4', 'PCI_DSS_10.6', 'GDPR_Art_32', 'HIPAA_164.312.b'],
      decoder: 'cecur-windows-evtx',
    },
    {
      id: 10030,
      level: 12,
      category: 'fim',
      title: 'Critical System Binary Tampering (FIM Checksum Deviation)',
      description: 'Cryptographic SHA-256 hash or inode altered on security-sensitive binary in /usr/bin or System32.',
      mitreTactic: 'Persistence',
      mitreTechnique: 'T1565.001 - Stored Data Manipulation',
      compliance: ['PCI_DSS_11.5', 'NIST_800_53_SI_7', 'GDPR_Art_32'],
      decoder: 'cecur-auditd',
    },
    {
      id: 10040,
      level: 9,
      category: 'web_attack',
      title: 'Web Application Attack: SQL Injection probe blocked',
      description: 'Pattern matching UNION SELECT or Boolean-based SQL injection string in URI/POST parameters.',
      mitreTactic: 'Initial Access',
      mitreTechnique: 'T1190 - Exploit Public-Facing Application',
      compliance: ['PCI_DSS_6.5.1', 'NIST_800_53_SI_10', 'OWASP_A03_2021'],
      decoder: 'cecur-syslog',
    },
    {
      id: 10050,
      level: 13,
      category: 'lateral_movement',
      title: 'Remote Service Execution (PsExec / WMI Lateral Movement)',
      description: 'Service installation or remote process invocation originating from workstation subnet targeting Domain Controller.',
      mitreTactic: 'Lateral Movement',
      mitreTechnique: 'T1047 - Windows Management Instrumentation',
      compliance: ['NIST_800_53_AC_6', 'PCI_DSS_10.2.2'],
      decoder: 'cecur-windows-evtx',
    },
    {
      id: 10060,
      level: 11,
      category: 'sca',
      title: 'CIS Benchmark Failure: Insecure SSH Protocol or Weak Cipher Suite Active',
      description: 'Host configuration violates CIS Linux Benchmark requirement for cryptographic key exchange.',
      mitreTactic: 'Defense Evasion',
      mitreTechnique: 'T1562.001 - Disable or Modify Security Tools',
      compliance: ['PCI_DSS_2.2.4', 'NIST_800_53_CM_6', 'HIPAA_164.312.e.1'],
      decoder: 'cecur-syslog',
    },
    {
      id: 10070,
      level: 15,
      category: 'vulnerability',
      title: 'Remote Code Execution Vulnerability Exploitation Vector Detected',
      description: 'High-severity CVE vulnerability in network daemon matched active exploit telemetry stream.',
      mitreTactic: 'Execution',
      mitreTechnique: 'T1203 - Exploitation for Client Execution',
      compliance: ['PCI_DSS_6.2', 'NIST_800_53_RA_5', 'HIPAA_164.308.a.1.ii.B'],
      decoder: 'cecur-k8s-audit',
    },
  ];

  /** Every figure comes from live state: process uptime, ingested events, enrolled agents, and the OpenSearch cluster. */
  public async getStatus(
    agents: CecurAgent[],
    logs: CecurLogEvent[],
    scanJobs: CecurScanJob[]
  ): Promise<CecurServerStatus> {
    const active = agents.filter((a) => a.status === 'active').length;
    const disconnected = agents.filter((a) => a.status === 'disconnected').length;
    const isolated = agents.filter((a) => a.status === 'isolated').length;

    const byWorkload = {
      local: agents.filter((a) => a.workloadType === 'local').length,
      virtual: agents.filter((a) => a.workloadType === 'virtual').length,
      container: agents.filter((a) => a.workloadType === 'container').length,
      cloud: agents.filter((a) => a.workloadType === 'cloud').length,
    };

    const cutoff = Date.now() - 60_000;
    const eventsLastMinute = logs.filter((l) => Date.parse(l.timestamp) >= cutoff).length;
    const lastEventAt = logs.reduce<string | null>(
      (latest, l) => (!latest || Date.parse(l.timestamp) > Date.parse(latest) ? l.timestamp : latest),
      null
    );

    const indexer = await getIndexerStats();
    const ai = getAIStatus();

    const notes: string[] = [];
    if (agents.length === 0) notes.push('No agents enrolled yet.');
    if (logs.length === 0) notes.push('No telemetry received yet.');
    if (!indexer) notes.push('OpenSearch indexer not enabled or unreachable.');
    if (!ai.inferenceActive) notes.push('Inference gateway not configured; deterministic heuristics only.');

    return {
      service: 'CS3 Unified SIEM & XDR Console',
      uptimeSeconds: Math.floor(process.uptime()),
      indexerStatus: indexer,
      ingestion: {
        eps: Math.round((eventsLastMinute / 60) * 100) / 100,
        eventsLastMinute,
        lastEventAt,
        bufferedEvents: logs.length,
      },
      serverStatus: {
        decodersLoaded: this.decoders.length,
        rulesLoaded: this.rulesCatalog.length,
      },
      agentsSummary: {
        total: agents.length,
        active,
        disconnected,
        isolated,
        byWorkload,
      },
      scanQueue: {
        queued: scanJobs.filter((j) => j.status === 'queued').length,
        running: scanJobs.filter((j) => j.status === 'running').length,
      },
      inference: {
        active: Boolean(ai.inferenceActive),
        backend: ai.inferenceBackend,
        profile: ai.inferenceProfile,
        triageModel: ai.ollamaModel,
        forensicModel: ai.ollamaFallbackModel,
      },
      message: notes.length ? notes.join(' ') : 'Telemetry flowing from enrolled agents.',
    };
  }
}

export const cecurEngine = new CecurEngine();
