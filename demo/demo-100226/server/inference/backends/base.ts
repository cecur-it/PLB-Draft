import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export interface ChatBackend {
  readonly name: 'ollama' | 'vllm';
  readonly baseUrl: string;
  health(): Promise<boolean>;
  chat(body: Record<string, unknown>): Promise<any>;
}

export class BackendError extends Error {
  constructor(message: string, readonly retryable: boolean) {
    super(message);
  }
}

export interface BackendOptions {
  timeoutMs?: number;
  retries?: number; // additional attempts after the first
  retryDelayMs?: number;
  headers?: Record<string, string>;
}

type FetchImplementation = (url: string, init?: any) => Promise<any>;

// Core HTTP has no independent response-header deadline; the caller's AbortSignal is authoritative.
const coreFetch: FetchImplementation = (url, init = {}) => new Promise((resolve, reject) => {
  const target = new URL(url);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    reject(new Error(`unsupported inference URL protocol: ${target.protocol}`));
    return;
  }
  const payload = init.body == null ? null : String(init.body);
  const headers = { ...(init.headers ?? {}) };
  if (payload !== null) headers['Content-Length'] = Buffer.byteLength(payload);
  const request = (target.protocol === 'https:' ? httpsRequest : httpRequest)(target, {
    method: init.method || 'GET',
    headers,
    signal: init.signal,
  }, (response) => {
    const chunks: Buffer[] = [];
    response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    response.on('error', reject);
    response.on('end', () => {
      const responseBody = Buffer.concat(chunks);
      resolve(new Response(responseBody.length ? responseBody : null, { status: response.statusCode ?? 500 }));
    });
  });
  request.on('error', reject);
  request.end(payload ?? undefined);
});

let fetchImplementation: FetchImplementation = coreFetch;
/** Test seam: replace the HTTP transport without changing production timeout handling. */
export function setBackendFetchForTests(fetchOverride?: typeof fetch): void {
  fetchImplementation = (fetchOverride ?? coreFetch) as FetchImplementation;
}

/** Shared OpenAI-compatible /chat/completions client with timeouts and bounded retries (5xx/429/network only). */
export abstract class OpenAICompatBackend implements ChatBackend {
  abstract readonly name: 'ollama' | 'vllm';
  protected abstract healthUrl(): string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly retryDelayMs: number;
  private readonly headers: Record<string, string>;

  constructor(readonly baseUrl: string, opts: BackendOptions = {}) {
    this.timeoutMs = opts.timeoutMs ?? 60_000;
    this.retries = opts.retries ?? 2;
    this.retryDelayMs = opts.retryDelayMs ?? 250;
    this.headers = { 'Content-Type': 'application/json', ...(opts.headers ?? {}) };
  }

  async health(): Promise<boolean> {
    try {
      const res = await fetchImplementation(this.healthUrl(), { headers: this.headers, signal: AbortSignal.timeout(Math.min(this.timeoutMs, 5000)) });
      return res.ok;
    } catch {
      return false;
    }
  }

  async chat(body: Record<string, unknown>): Promise<any> {
    let last: BackendError = new BackendError('no attempt made', false);
    const deadline = Date.now() + this.timeoutMs;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt) {
        const delay = Math.min(this.retryDelayMs * 2 ** (attempt - 1), Math.max(0, deadline - Date.now()));
        await new Promise((r) => setTimeout(r, delay));
      }
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        last = new BackendError(`${this.name} request exceeded the ${this.timeoutMs} ms total deadline`, true);
        break;
      }
      try {
        const res = await fetchImplementation(`${this.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: this.headers,
          signal: AbortSignal.timeout(remainingMs),
          body: JSON.stringify(body),
        });
        if (res.ok) return await res.json();
        await res.body?.cancel();
        last = new BackendError(`${this.name} returned HTTP ${res.status}`, res.status >= 500 || res.status === 429);
      } catch (e: any) {
        last = new BackendError(`${this.name} request failed: ${e.message}`, true);
      }
      if (!last.retryable || deadline - Date.now() <= 0) break;
    }
    throw last;
  }
}
