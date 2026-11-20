import { isIP } from 'node:net';
import type {
  AssetRecord,
  AssetResolution,
  AssetResolutionEvidence,
  AssetResolutionSource,
  CecurAgent,
  ResolvedAssetIdentity,
} from '../../src/types';

export interface AssetResolutionInput {
  logMessage?: string;
  agentId?: string;
  agentName?: string;
  agentIp?: string;
  hostname?: string;
  hostnames?: string[];
  ip?: string;
  ips?: string[];
  fields?: Record<string, unknown>;
}

export interface AssetResolutionOptions {
  inventory: AssetRecord[];
  agents: Array<Pick<CecurAgent, 'id' | 'name' | 'hostname' | 'ip'>>;
  inventorySource?: string | null;
  inventoryError?: string;
}

interface Candidate extends ResolvedAssetIdentity {
  hostnames: Set<string>;
  ips: Set<string>;
}

interface Observation {
  field: string;
  kind: 'agent_id' | 'hostname' | 'ip';
  observedValue: string;
  normalizedValue: string;
  confidence: number;
}

interface RankedCandidate {
  id: string;
  confidence: number;
  method: Observation['kind'];
}

const MAX_OBSERVATIONS = 40;

export function normalizeHostname(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const hostname = value.trim().toLowerCase().replace(/\.+$/, '');
  if (!hostname || hostname.length > 253 || !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(hostname)) return null;
  return hostname;
}

export function normalizeIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let ip = value.trim().toLowerCase();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const zoneIndex = ip.indexOf('%');
  if (zoneIndex >= 0) ip = ip.slice(0, zoneIndex);
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.every((part) => part >= 0 && part <= 255)) ip = parts.join('.');
  }
  return isIP(ip) ? ip : null;
}

function shortHostname(hostname: string): string {
  return hostname.split('.')[0];
}

function addHostname(candidate: Candidate, hostname: string | null): void {
  if (hostname) candidate.hostnames.add(hostname);
}

function addIp(candidate: Candidate, ip: string | null): void {
  if (ip) candidate.ips.add(ip);
}

function uniqueSources(sources: AssetResolutionSource[]): AssetResolutionSource[] {
  return [...new Set(sources)];
}

function publicCandidate(candidate: Candidate): ResolvedAssetIdentity {
  return {
    id: candidate.id,
    hostname: candidate.hostname,
    ip: candidate.ip,
    category: candidate.category,
    criticality: candidate.criticality,
    sources: candidate.sources,
    agentId: candidate.agentId,
    inventoryAssetId: candidate.inventoryAssetId,
  };
}

/**
 * Merge inventory and enrollment identity records without treating a shared IP as unique.
 * An agent with no unambiguous inventory identity remains a separate endpoint candidate.
 */
function buildCandidates(options: AssetResolutionOptions): Candidate[] {
  const candidates: Candidate[] = options.inventory.map((asset) => {
    const hostname = normalizeHostname(asset.hostname);
    const ip = normalizeIp(asset.managementIp);
    return {
      id: asset.id,
      hostname,
      ip,
      category: asset.category,
      criticality: asset.criticality ?? null,
      sources: ['plb_inventory'],
      agentId: null,
      inventoryAssetId: asset.id,
      hostnames: new Set(hostname ? [hostname] : []),
      ips: new Set(ip ? [ip] : []),
    };
  });

  for (const agent of options.agents) {
    const id = agent.id?.trim();
    if (!id) continue;
    const agentHostnames = [normalizeHostname(agent.hostname), normalizeHostname(agent.name)].filter(
      (hostname): hostname is string => Boolean(hostname),
    );
    const agentIp = normalizeIp(agent.ip);
    const inventoryCandidates = candidates.filter((candidate) => candidate.sources.includes('plb_inventory'));
    const hostnameMatches = inventoryCandidates.filter((candidate) =>
      agentHostnames.some((hostname) => candidate.hostnames.has(hostname)),
    );
    const ipMatches = agentIp
      ? inventoryCandidates.filter((candidate) => candidate.ips.has(agentIp))
      : [];

    let target: Candidate | undefined;
    if (hostnameMatches.length === 1) {
      target = hostnameMatches[0];
    } else if (hostnameMatches.length === 0 && ipMatches.length === 1) {
      target = ipMatches[0];
    }
    if (target?.agentId && target.agentId !== id) target = undefined;

    if (target) {
      target.sources = uniqueSources([...target.sources, 'enrolled_agent']);
      target.agentId = id;
      for (const hostname of agentHostnames) addHostname(target, hostname);
      addIp(target, agentIp);
      if (!target.ip) target.ip = agentIp;
      continue;
    }

    const hostname = agentHostnames[0] ?? null;
    candidates.push({
      id: `agent:${id}`,
      hostname,
      ip: agentIp,
      category: 'endpoint',
      criticality: null,
      sources: ['enrolled_agent'],
      agentId: id,
      inventoryAssetId: null,
      hostnames: new Set(agentHostnames),
      ips: new Set(agentIp ? [agentIp] : []),
    });
  }

  return candidates;
}

function hostnameMatch(candidate: Candidate, hostname: string): 'exact' | 'short' | null {
  if (candidate.hostnames.has(hostname)) return 'exact';
  const short = shortHostname(hostname);
  for (const candidateHostname of candidate.hostnames) {
    if (candidateHostname === short || shortHostname(candidateHostname) === short) return 'short';
  }
  return null;
}

function collectObservations(input: AssetResolutionInput): Observation[] {
  const observations: Observation[] = [];
  const seen = new Set<string>();
  const add = (
    field: string,
    kind: Observation['kind'],
    value: unknown,
    confidence: number,
  ): void => {
    if (observations.length >= MAX_OBSERVATIONS) return;
    const normalizedValue = kind === 'hostname' ? normalizeHostname(value) : kind === 'ip' ? normalizeIp(value) : typeof value === 'string' ? value.trim() : null;
    if (!normalizedValue) return;
    const key = `${field}\u0000${kind}\u0000${normalizedValue}`;
    if (seen.has(key)) return;
    seen.add(key);
    observations.push({ field, kind, observedValue: String(value).trim(), normalizedValue, confidence });
  };

  add('agentId', 'agent_id', input.agentId, 100);
  add('agentName', 'hostname', input.agentName, 98);
  add('hostname', 'hostname', input.hostname, 98);
  for (const hostname of input.hostnames ?? []) add('hostnames', 'hostname', hostname, 96);
  add('agentIp', 'ip', input.agentIp, 85);
  add('ip', 'ip', input.ip, 82);
  for (const ip of input.ips ?? []) add('ips', 'ip', ip, 82);

  const fields = input.fields ?? {};
  for (const [field, rawValue] of Object.entries(fields)) {
    if (observations.length >= MAX_OBSERVATIONS) break;
    const value = typeof rawValue === 'string' ? rawValue : null;
    if (!value) continue;
    const key = field.toLowerCase().replace(/[.\-[\]]/g, '_');
    if (/^(?:host(?:name)?|computer(?:name)?|device(?:name)?|source_host|dest(?:ination)?_host)$/.test(key)) {
      add(`fields.${field}`, 'hostname', value, 96);
    } else if (/^(?:agent_ip|host_ip|management_ip)$/.test(key)) {
      add(`fields.${field}`, 'ip', value, 80);
    } else if (/^(?:source_ip|src_ip|destination_ip|dest_ip|dst_ip|target_ip)$/.test(key)) {
      add(`fields.${field}`, 'ip', value, 65);
    }
  }

  const logMessage = input.logMessage ?? '';
  const hostPattern = /\b(?:host(?:name)?|device(?:_name)?)\s*[:=]\s*["']?([a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?)["']?/gi;
  for (const match of logMessage.matchAll(hostPattern)) add('logMessage.hostname', 'hostname', match[1], 90);
  const ipPattern = /(?<![a-z0-9_.:-])(?:\d{1,3}\.){3}\d{1,3}(?![a-z0-9_.:-])/gi;
  for (const match of logMessage.matchAll(ipPattern)) add('logMessage.ip', 'ip', match[0], 55);

  return observations;
}

function rankCandidates(candidates: Candidate[], observations: Observation[]): {
  evidence: AssetResolutionEvidence[];
  ranked: RankedCandidate[];
} {
  const evidence: AssetResolutionEvidence[] = [];
  const bestByCandidate = new Map<string, RankedCandidate>();

  for (const observation of observations) {
    const matches: Array<{ candidate: Candidate; confidence: number }> = [];
    for (const candidate of candidates) {
      if (observation.kind === 'agent_id' && candidate.agentId === observation.normalizedValue) {
        matches.push({ candidate, confidence: observation.confidence });
      } else if (observation.kind === 'ip' && candidate.ips.has(observation.normalizedValue)) {
        matches.push({ candidate, confidence: observation.confidence });
      } else if (observation.kind === 'hostname') {
        const match = hostnameMatch(candidate, observation.normalizedValue);
        if (match) matches.push({ candidate, confidence: observation.confidence - (match === 'short' ? 4 : 0) });
      }
    }

    evidence.push({
      field: observation.field,
      kind: observation.kind,
      observedValue: observation.observedValue,
      normalizedValue: observation.normalizedValue,
      candidateIds: matches.map(({ candidate }) => candidate.id),
    });
    for (const { candidate, confidence } of matches) {
      const previous = bestByCandidate.get(candidate.id);
      if (!previous || confidence > previous.confidence) {
        bestByCandidate.set(candidate.id, {
          id: candidate.id,
          confidence,
          method: observation.kind,
        });
      }
    }
  }

  const ranked = [...bestByCandidate.values()].sort(
    (left, right) => right.confidence - left.confidence || left.id.localeCompare(right.id),
  );
  return { evidence, ranked };
}

/**
 * Resolve only the identity named by the supplied evidence. This does not infer topology,
 * event correlation, asset criticality, or a source/destination network relationship.
 */
export function resolveAsset(
  input: AssetResolutionInput,
  options: AssetResolutionOptions,
): AssetResolution {
  const internalCandidates = buildCandidates(options);
  const observations = collectObservations(input);
  const { evidence, ranked } = rankCandidates(internalCandidates, observations);
  const allCandidates = internalCandidates.map(publicCandidate);
  const best = ranked[0];
  const tied = best ? ranked.filter((candidate) => candidate.confidence === best.confidence) : [];
  const matched = best && tied.length === 1 ? allCandidates.find((candidate) => candidate.id === best.id) ?? null : null;
  const candidates = matched
    ? [matched]
    : tied.map((rankedCandidate) => allCandidates.find((candidate) => candidate.id === rankedCandidate.id))
      .filter((candidate): candidate is ResolvedAssetIdentity => Boolean(candidate));

  let status: AssetResolution['status'] = 'unmatched';
  let reason = observations.length === 0
    ? 'No usable hostname, IP, or enrolled-agent ID evidence was supplied.'
    : 'No supplied evidence matched the PLB inventory or enrolled agents.';
  if (best && tied.length > 1) {
    status = 'ambiguous';
    const ids = tied.map((candidate) => candidate.id).join(', ');
    reason = best.method === 'ip'
      ? `IP evidence maps to multiple equally confident assets (${ids}); no asset was selected.`
      : `Identity evidence maps to multiple equally confident assets (${ids}); no asset was selected.`;
  } else if (matched && best) {
    status = 'matched';
    reason = `Matched ${matched.id} using ${best.method} evidence; identity resolution only.`;
  }

  return {
    resolver: 'plb_inventory_enrolled_agents_v1',
    status,
    scope: 'identity_only',
    asset: matched,
    candidates,
    matchConfidence: matched && best ? best.confidence : 0,
    matchMethod: matched && best ? best.method : null,
    evidence,
    inventorySource: options.inventorySource ?? null,
    ...(options.inventoryError ? { inventoryError: options.inventoryError } : {}),
    reason,
  };
}
