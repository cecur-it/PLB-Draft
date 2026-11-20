import { db } from '../db';
import type { AssetRecord, AssetTelemetryView } from '../../src/types';

const IP_FIELDS = ['host', 'hostname', 'src_ip', 'srcip', 'ip', 'source_ip', 'device', 'device_name'];

const normVersion = (v: string) => v.toLowerCase().replace(/^(mr|v)\s*/, '').replace(/\s+/g, '');

/** True when the installed version equals one of the (possibly "a / b") required versions; undefined when no target is recorded. */
function versionCompliant(current?: string, required?: string): boolean | undefined {
  if (!required || /^[—–-]+$/.test(required.trim())) return undefined;
  if (!current) return false;
  const cur = normVersion(current);
  return required.split('/').some((r) => normVersion(r) === cur);
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Links each inventory row to real telemetry: an enrolled agent with the same hostname/IP, or events in the
 * ingested stream that name the host or its management IP. Nothing is inferred beyond those matches.
 */
export function linkAssetsToTelemetry(assets: AssetRecord[]): AssetTelemetryView[] {
  const ipCounts = new Map<string, number>();
  for (const a of assets) if (a.managementIp) ipCounts.set(a.managementIp, (ipCounts.get(a.managementIp) ?? 0) + 1);

  return assets.map((asset) => {
    const duplicateIp = !!asset.managementIp && (ipCounts.get(asset.managementIp) ?? 0) > 1;
    const host = asset.hostname.toLowerCase();
    // A shared IP cannot identify one device, so only the hostname is used for those rows.
    const ip = duplicateIp ? undefined : asset.managementIp;
    const hostRe = new RegExp(`(^|[^a-z0-9-])${escapeRe(host)}($|[^a-z0-9-])`, 'i');
    const ipRe = ip ? new RegExp(`(^|[^0-9.])${escapeRe(ip)}($|[^0-9])`) : null;

    const agent = db.cecurAgents.find((a) => a.hostname.toLowerCase() === host || a.name.toLowerCase() === host || (!!ip && a.ip === ip));

    let eventCount = 0;
    let lastEventAt: string | undefined;
    for (const log of db.cecurLogs) {
      const fieldHit = IP_FIELDS.some((k) => {
        const v = log.fields?.[k];
        return typeof v === 'string' && (v.toLowerCase() === host || (!!ip && v === ip));
      });
      const hit =
        fieldHit ||
        log.agentName.toLowerCase() === host ||
        hostRe.test(log.message) ||
        (!!ipRe && ipRe.test(log.message));
      if (!hit) continue;
      eventCount++;
      if (!lastEventAt || Date.parse(log.timestamp) > Date.parse(lastEventAt)) lastEventAt = log.timestamp;
    }

    const coverage: AssetTelemetryView['telemetry']['coverage'] = agent ? 'agent' : eventCount > 0 ? 'syslog' : 'none';
    const scanSupport = agent
      ? agent.os.platform === 'linux'
        ? 'Linux agent enrolled: FIM/SCA/vulnerability jobs can be queued; a compatible scan worker must report results.'
        : `${agent.os.name} agent enrolled for forwarding; the CS3 Linux FIM/SCA/vulnerability scan worker is unsupported on this endpoint.`
      : asset.category === 'other'
        ? 'No CS3 agent enrolled for this host; enroll one to enable FIM/SCA/vulnerability scans.'
        : 'Network appliance: cannot run the CS3 agent, so FIM/SCA/vulnerability scans do not apply. Collect via syslog relay; run external checks through Errow once the target is authorized.';

    return {
      ...asset,
      telemetry: { coverage, agentId: agent?.id, eventCount, lastEventAt, scanSupport },
      softwareCompliant: versionCompliant(asset.softwareVersion, asset.requiredSoftwareVersion),
      duplicateIp,
    };
  });
}
