import { OpenAICompatBackend } from './base';

/** Ollama (edge/onprem/airgap). baseUrl is its OpenAI-compatible /v1 root. */
export class OllamaBackend extends OpenAICompatBackend {
  readonly name = 'ollama' as const;
  protected healthUrl(): string {
    return `${this.baseUrl.replace(/\/v1$/, '')}/api/tags`;
  }
}
