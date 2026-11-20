import type { HotCacheEpsEstimate, SensorHealthSummary } from '../../src/types';

const WINDOW_SECONDS = 60;
const WINDOW_MS = WINDOW_SECONDS * 1000;

/** Estimate EPS only from valid hot-cache events observed inside the trailing 60-second window. */
export function calculateHotCacheEpsEstimate(
  logs: Array<Pick<{ timestamp: string }, 'timestamp'>>,
  now: Date = new Date(),
): HotCacheEpsEstimate {
  const nowMs = now.getTime();
  const windowStartMs = nowMs - WINDOW_MS;
  const timestamps = logs
    .map((log) => Date.parse(log.timestamp))
    .filter((timestamp) => Number.isFinite(timestamp));
  const latestTimestamp = timestamps.length > 0 ? Math.max(...timestamps) : null;
  const eventCount = timestamps.filter(
    (timestamp) => timestamp >= windowStartMs && timestamp <= nowMs,
  ).length;
  const status: HotCacheEpsEstimate['status'] = latestTimestamp === null
    ? 'no_data'
    : latestTimestamp < windowStartMs
      ? 'stale'
      : 'current';

  return {
    name: 'cecur_hot_cache_60s_eps',
    value: Math.round((eventCount / WINDOW_SECONDS) * 100) / 100,
    unit: 'events_per_second',
    source: 'db.cecurLogs',
    cache: 'in_memory_hot_cache',
    windowSeconds: WINDOW_SECONDS,
    windowStart: new Date(windowStartMs).toISOString(),
    windowEnd: new Date(nowMs).toISOString(),
    eventCount,
    cacheEventCount: logs.length,
    latestEventAt: latestTimestamp === null ? null : new Date(latestTimestamp).toISOString(),
    status,
    stale: status === 'stale',
  };
}

export function summarizeSensorHealth(
  sensors: Array<{ status: string }>,
): SensorHealthSummary {
  const total = sensors.length;
  const online = sensors.filter((sensor) => sensor.status.toLowerCase() === 'online').length;
  const degraded = sensors.filter((sensor) => sensor.status.toLowerCase() === 'degraded').length;
  const offline = Math.max(0, total - online - degraded);
  const status: SensorHealthSummary['status'] = total === 0
    ? 'NO_SENSORS'
    : online === 0
      ? 'OFFLINE'
      : offline > 0 || degraded > 0
        ? 'DEGRADED'
        : 'OPERATIONAL';

  return { total, online, degraded, offline, status };
}
