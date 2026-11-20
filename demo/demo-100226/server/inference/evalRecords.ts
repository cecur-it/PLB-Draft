import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EvalRecord } from './registry';

export const EVAL_RESULTS_DIR = process.env.CS3_EVAL_RESULTS_DIR || join(process.cwd(), 'eval', 'results');

/**
 * Worst-case (per metric minimum) across every real-model record (`runner: gateway`) for a model id.
 * Deterministic-runner records never count toward approval. Returns undefined when no record exists.
 */
export function loadEvalRecord(modelId: string, dir: string = EVAL_RESULTS_DIR): EvalRecord | undefined {
  if (!existsSync(dir)) return undefined;
  const safe = modelId.replace(/[^\w.-]/g, '_');
  const recs = readdirSync(dir)
    .filter((f) => f.startsWith(`${safe}.`) && f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')))
    .filter((r) => r.runner === 'gateway' && r.metrics);
  if (!recs.length) return undefined;
  const min = (k: keyof EvalRecord) => Math.min(...recs.map((r) => r.metrics[k] as number));
  return { score: min('score'), injectionResistance: min('injectionResistance'), scriptSafety: min('scriptSafety') };
}
