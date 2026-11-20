import { OllamaBackend } from './backends/ollama';
import { VllmBackend } from './backends/vllm';
import type { ChatBackend } from './backends/base';
import { FairShareScheduler } from './scheduler';
import { validateOutputSchema } from './guardrails';
import { computeGpuSeconds } from './meter';
import type {
  DeploymentProfile,
  GatewayBackendInfo,
  InferenceGateway,
  InferenceRequest,
  InferenceResponse,
  ModelRole,
} from './types';

/**
 * OpenAI-compatible gateway client (LiteLLM, vLLM, Ollama /v1). The backend is chosen by deployment
 * profile; no third-party hosted model provider is ever contacted directly.
 *  - cloud:  INFERENCE_GATEWAY_URL (LiteLLM/vLLM)
 *  - onprem/airgap/edge: OLLAMA_BASE_URL (default local Ollama)
 */
export class InferenceError extends Error {}

function trimUrl(u: string): string {
  return u.replace(/\/+$/, '');
}

export function backendFor(profile: DeploymentProfile): GatewayBackendInfo {
  const env = process.env;
  const primary = env.OLLAMA_PRIMARY_MODEL || 'nemotron-3-nano:30b';
  const fallback = env.OLLAMA_FALLBACK_MODEL || 'gemma4:26b';
  const models: Record<ModelRole, string> = {
    triage: env.INFERENCE_MODEL_TRIAGE || primary,
    forensic: env.INFERENCE_MODEL_FORENSIC || fallback,
    security: env.INFERENCE_MODEL_SECURITY || env.OLLAMA_SECURITY_MODEL || 'nemotron-3-nano:30b',
  };
  if (profile === 'cloud' && env.INFERENCE_GATEWAY_URL) {
    return { backend: 'vllm', baseUrl: trimUrl(env.INFERENCE_GATEWAY_URL), models };
  }
  return { backend: 'ollama', baseUrl: trimUrl(env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434/v1'), models };
}

/** True when a model backend is expected to be reachable for this profile. */
export function isInferenceConfigured(profile: DeploymentProfile): boolean {
  if (profile !== 'cloud') return true;
  return Boolean(process.env.INFERENCE_GATEWAY_URL) || process.env.CS3_LLM_MODE === 'local';
}

export class OpenAICompatGateway implements InferenceGateway {
  private readonly scheduler = new FairShareScheduler(
    Number(process.env.INFERENCE_TENANT_CONCURRENCY) || 2,
    Number(process.env.INFERENCE_GLOBAL_CONCURRENCY) || Number.POSITIVE_INFINITY,
  );

  constructor(private readonly timeoutMs = Number(process.env.INFERENCE_TIMEOUT_MS) || 60_000) {}

  describe(profile: DeploymentProfile): GatewayBackendInfo {
    return backendFor(profile);
  }

  backend(profile: DeploymentProfile, timeoutMs = this.timeoutMs, retries?: number): ChatBackend {
    const info = backendFor(profile);
    const headers: Record<string, string> = {};
    if (process.env.INFERENCE_GATEWAY_KEY && info.backend === 'vllm') headers.Authorization = `Bearer ${process.env.INFERENCE_GATEWAY_KEY}`;
    const opts = { timeoutMs, retries, headers };
    return info.backend === 'vllm' ? new VllmBackend(info.baseUrl, opts) : new OllamaBackend(info.baseUrl, opts);
  }

  async infer(req: InferenceRequest): Promise<InferenceResponse> {
    const info = backendFor(req.profile);
    const model = info.models[req.role];
    const timeoutMs = req.options?.timeoutMs ?? this.timeoutMs;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 86_400_000) {
      throw new InferenceError('inference timeoutMs must be an integer from 1 to 86400000');
    }
    const retries = req.options?.retries;
    if (retries !== undefined && (!Number.isInteger(retries) || retries < 0 || retries > 2)) {
      throw new InferenceError('inference retries must be an integer from 0 to 2');
    }
    const backend = this.backend(req.profile, timeoutMs, retries);
    const started = Date.now();
    const body = {
      model,
      messages: [
        { role: 'system', content: req.input.system },
        { role: 'user', content: req.input.user },
      ],
      response_format: { type: 'json_object' },
      temperature: req.options?.temperature ?? 0.2,
      ...(req.options?.maxTokens ? { max_tokens: req.options.maxTokens } : {}),
      ...(info.backend === 'ollama' ? { reasoning_effort: process.env.INFERENCE_REASONING_EFFORT || 'none' } : {}),
      stream: false,
    };
    const call = async () => {
      try {
        return await backend.chat(body);
      } catch (e: any) {
        throw new InferenceError(e.message);
      }
    };
    // Fair-share queue applies to the shared cloud pool only.
    const data: any = req.profile === 'cloud' ? await this.scheduler.run(req.tenantId, call) : await call();
    const content: unknown = data.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content) throw new InferenceError('empty completion');

    let output: unknown;
    try {
      output = JSON.parse(content);
    } catch {
      throw new InferenceError('completion is not valid JSON');
    }
    const schemaErrors = validateOutputSchema(output, req.input.schema);
    if (schemaErrors.length) throw new InferenceError(`output violates schema: ${schemaErrors[0]}`);

    const latencyMs = Date.now() - started;
    return {
      output,
      model: { name: data.model || model, digest: 'unverified', quantization: 'unknown', backend: info.backend },
      usage: {
        promptTokens: data.usage?.prompt_tokens ?? 0,
        completionTokens: data.usage?.completion_tokens ?? 0,
        gpuSeconds: computeGpuSeconds(latencyMs, data.usage?.gpu_seconds),
      },
      guardrail: { passed: true, violations: [] }, // populated by INF-005
      latencyMs,
      fallback: false,
    };
  }
}

let singleton: InferenceGateway | null = null;
export function getGateway(): InferenceGateway {
  return (singleton ??= new OpenAICompatGateway());
}
/** Test seam: inject a mock gateway. */
export function setGateway(g: InferenceGateway | null): void {
  singleton = g;
}
