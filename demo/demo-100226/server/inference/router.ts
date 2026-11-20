import { getLedger } from './meter';
import { getGateway } from './gateway';
import { backendGuardModel, checkOutput, frameUntrusted, sanitizeUntrusted, type GuardModel } from './guardrails';
import type { DeploymentProfile, InferenceRequest, InferenceResponse } from './types';

/** Thrown when policy forbids the requested path (e.g. CUI to a cloud backend). Never falls back silently. */
export class RoutingPolicyError extends Error {}

let guardOverride: GuardModel | null | undefined;
/** Test seam: inject a guard model (null disables). */
export function setGuardModel(g: GuardModel | null | undefined): void {
  guardOverride = g;
}

const deterministicResponse = (violations: string[] = [], passed = true): InferenceResponse => ({
  output: null,
  model: { name: 'cecur-deterministic', digest: 'n/a', quantization: 'n/a', backend: 'heuristic' },
  usage: { promptTokens: 0, completionTokens: 0, gpuSeconds: 0 },
  guardrail: { passed, violations },
  latencyMs: 0,
  fallback: true,
});

/** CUI/classified data may only be processed on onprem/airgap/edge backends. */
export function assertClassificationAllowed(profile: DeploymentProfile, dataClass: InferenceRequest['dataClassification']): void {
  if ((dataClass === 'cui' || dataClass === 'classified') && profile === 'cloud') {
    throw new RoutingPolicyError(`${dataClass} data may not be processed on the cloud profile`);
  }
}

/**
 * Routes a request. Air-gap uses the deterministic engine as its primary path (D4); only the
 * forensic role may reach a local site-node model, and only when INFERENCE_AIRGAP_FORENSIC=on.
 * In every profile an unavailable/invalid gateway answer yields fallback:true (output === null),
 * which callers must answer from their deterministic engine.
 */
export async function routeInference(req: InferenceRequest): Promise<InferenceResponse> {
  assertClassificationAllowed(req.profile, req.dataClassification);

  if (req.profile === 'airgap') {
    const siteNode = req.role === 'forensic' && process.env.INFERENCE_AIRGAP_FORENSIC === 'on';
    if (!siteNode) return deterministicResponse();
  }

  // Untrusted input is sanitized and framed as data before it reaches any model.
  const clean = sanitizeUntrusted(req.input.user);
  const framed = frameUntrusted(clean.text, req.input.scripts?.map((x) => x.field));
  const guarded: InferenceRequest = { ...req, input: { ...req.input, system: `${req.input.system}\n${framed.system}`, user: framed.user } };

  let res: InferenceResponse;
  try {
    res = await getGateway().infer(guarded);
  } catch (err: any) {
    console.warn('[Cecur AI] Gateway unavailable, deterministic engine answering:', err.message);
    return deterministicResponse();
  }

  // GPU time is consumed even if a guardrail later rejects the answer.
  getLedger().record(req, res);

  const guard = guardOverride === undefined ? backendGuardModel(req.profile) : guardOverride;
  const out = await checkOutput(res.output, req.input.schema, guard, req.input.scripts);
  const violations = [...clean.violations, ...out.violations];
  if (!out.passed) {
    // Reject: never surface the model output; the deterministic engine answers and the violation is escalated.
    console.warn('[Cecur AI] Guardrail rejection:', violations.join('; '));
    return deterministicResponse(violations, false);
  }
  return { ...res, guardrail: { passed: true, violations } };
}
