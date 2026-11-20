import { OpenAICompatBackend } from './base';

/** vLLM / LiteLLM gateway (cloud). baseUrl is the OpenAI-compatible root. */
export class VllmBackend extends OpenAICompatBackend {
  readonly name = 'vllm' as const;
  protected healthUrl(): string {
    return `${this.baseUrl}/models`;
  }
}
