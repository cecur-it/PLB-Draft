import type { InferenceRequest, InferenceResponse } from './types';

/**
 * GPU-second metering (D5): customer-facing gas credits are charged per GPU-second, not per token.
 * Ledger is append-only; the in-memory store is a placeholder until the StateStore (AG-001) lands.
 */
export interface LedgerEntry {
  id: number;
  ts: string;
  kind: 'grant' | 'usage';
  tenantId: string;
  incidentId?: string;
  role?: string;
  model?: string;
  gpuSeconds: number;
  credits: number; // positive for grants, negative for usage
  balanceAfter: number;
  overdraft: boolean;
}

export interface MeterConfig {
  creditsPerGpuSecond: number;
}

export function meterConfig(): MeterConfig {
  const n = Number(process.env.GAS_CREDITS_PER_GPU_SECOND);
  return { creditsPerGpuSecond: Number.isFinite(n) && n > 0 ? n : 1 };
}

/** Round up to 1/1000 credit so tiny requests are never free. */
export function creditsFor(gpuSeconds: number, cfg: MeterConfig = meterConfig()): number {
  if (gpuSeconds <= 0) return 0;
  return Math.ceil(gpuSeconds * cfg.creditsPerGpuSecond * 1000) / 1000;
}

/**
 * GPU-seconds for one request: backend-reported value if present, otherwise wall-clock inference time
 * scaled by the share of the GPU the request occupied (INFERENCE_GPU_SHARE, default 1 = exclusive).
 */
export function computeGpuSeconds(latencyMs: number, reported?: number): number {
  if (typeof reported === 'number' && reported >= 0) return reported;
  const share = Number(process.env.INFERENCE_GPU_SHARE);
  const s = Number.isFinite(share) && share > 0 && share <= 1 ? share : 1;
  return Math.round((latencyMs / 1000) * s * 1000) / 1000;
}

export class GasLedger {
  private entries: LedgerEntry[] = [];
  private balances = new Map<string, number>();

  private append(e: Omit<LedgerEntry, 'id' | 'ts' | 'balanceAfter' | 'overdraft'>): LedgerEntry {
    const balanceAfter = Math.round(((this.balances.get(e.tenantId) ?? 0) + e.credits) * 1000) / 1000;
    this.balances.set(e.tenantId, balanceAfter);
    const entry: LedgerEntry = { ...e, id: this.entries.length + 1, ts: new Date().toISOString(), balanceAfter, overdraft: balanceAfter < 0 };
    this.entries.push(entry);
    return entry;
  }

  grant(tenantId: string, credits: number): LedgerEntry {
    if (!(credits > 0)) throw new Error('grant must be positive');
    return this.append({ kind: 'grant', tenantId, gpuSeconds: 0, credits });
  }

  /** Charges the tenant for the response's usage.gpuSeconds. */
  record(req: InferenceRequest, res: InferenceResponse): LedgerEntry | null {
    if (res.fallback || res.usage.gpuSeconds <= 0) return null; // deterministic engine uses no GPU
    return this.append({
      kind: 'usage',
      tenantId: req.tenantId,
      incidentId: req.incidentId,
      role: req.role,
      model: res.model.name,
      gpuSeconds: res.usage.gpuSeconds,
      credits: -creditsFor(res.usage.gpuSeconds),
    });
  }

  balance(tenantId: string): number {
    return this.balances.get(tenantId) ?? 0;
  }

  usage(tenantId: string): { gpuSeconds: number; credits: number } {
    let gpuSeconds = 0;
    for (const e of this.entries) if (e.kind === 'usage' && e.tenantId === tenantId) gpuSeconds += e.gpuSeconds;
    return { gpuSeconds: Math.round(gpuSeconds * 1000) / 1000, credits: creditsFor(gpuSeconds) };
  }

  list(tenantId?: string): readonly LedgerEntry[] {
    return tenantId ? this.entries.filter((e) => e.tenantId === tenantId) : this.entries;
  }
}

let ledger = new GasLedger();
export const getLedger = (): GasLedger => ledger;
/** Test seam. */
export const setLedger = (l: GasLedger): void => {
  ledger = l;
};
