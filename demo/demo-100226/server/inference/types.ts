// Contract: changes require a "Contract Changes" entry in the PR description.
export type ModelRole = 'triage' | 'forensic' | 'security';
export type DeploymentProfile = 'cloud' | 'onprem' | 'airgap' | 'edge';
export type DataClass = 'public' | 'internal' | 'cui' | 'classified';

/** Top-level output field the model is asked to author as a script; validated separately from the blanket output scan. */
export interface ScriptField {
  field: string;
  kind: 'bash' | 'powershell' | 'ansible';
}

export interface InferenceRequest {
  role: ModelRole;
  profile: DeploymentProfile;
  tenantId: string;
  incidentId: string;
  dataClassification: DataClass;
  input: { system: string; user: string; schema?: object; scripts?: ScriptField[] }; // JSON Schema for output
  options?: {
    maxTokens?: number;
    temperature?: number;
    grammar?: string;
    /** Total per-request deadline in milliseconds, including backend retries. */
    timeoutMs?: number;
    /** Additional attempts after the first; zero disables retry for non-idempotent generation. */
    retries?: number;
  };
}

export interface InferenceResponse {
  output: unknown; // validated against input.schema
  model: { name: string; digest: string; quantization: string; backend: string };
  usage: { promptTokens: number; completionTokens: number; gpuSeconds: number };
  guardrail: { passed: boolean; violations: string[] };
  latencyMs: number;
  fallback: boolean; // true when deterministic engine answered
}

export interface InferenceGateway {
  infer(req: InferenceRequest): Promise<InferenceResponse>;
  describe(profile: DeploymentProfile): GatewayBackendInfo;
}

export interface GatewayBackendInfo {
  backend: string;
  baseUrl: string;
  models: Record<ModelRole, string>;
}
