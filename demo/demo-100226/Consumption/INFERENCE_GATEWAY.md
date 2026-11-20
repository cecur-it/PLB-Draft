# Inference Gateway (INF-001)

All AI calls go through `server/inference/gateway.ts` (`InferenceGateway`, OpenAI-compatible). Gemini and DeepSeek clients and keys have been removed.

| Profile | Backend | Config |
|---|---|---|
| `cloud` | vLLM/LiteLLM | `INFERENCE_GATEWAY_URL`, optional `INFERENCE_GATEWAY_KEY` |
| `onprem` / `airgap` / `edge` | Ollama | `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434/v1`) |

Models are selected per role (`triage`, `forensic`) via `INFERENCE_MODEL_TRIAGE` / `INFERENCE_MODEL_FORENSIC` (default `OLLAMA_PRIMARY_MODEL` / `OLLAMA_FALLBACK_MODEL`). When no backend is reachable or configured, `cecurAI.ts` answers with its deterministic engine.

Not yet implemented (later tasks): registry/digest pinning (INF-002), guardrails (INF-005), GPU-second metering (INF-006; `gpuSeconds` is currently wall-clock).

## Backends & scheduler (INF-003)
`backends/ollama.ts` and `backends/vllm.ts` share an OpenAI-compatible client (`backends/base.ts`) with a total request deadline (`INFERENCE_TIMEOUT_MS`, default 60 s) spanning up to 2 retries with exponential backoff on 5xx/429/network errors only. Its core HTTP/HTTPS transport has no independent response-header timer, so the remaining-time abort signal stays authoritative beyond the native fetch 300 s ceiling; `health()` uses `/api/tags` for Ollama or `/models` for vLLM. Keep the total deadline below the outer HTTPS proxy timeout so deterministic fallback can reach the browser. Ollama structured JSON requests set `reasoning_effort` from `INFERENCE_REASONING_EFFORT` (default `none`) to prevent hidden reasoning from consuming the completion budget; use a value supported by the selected model to override it. On the `cloud` profile requests pass through `FairShareScheduler`: `INFERENCE_TENANT_CONCURRENCY` (default 2) per tenant, optional `INFERENCE_GLOBAL_CONCURRENCY`, round-robin across tenants. Health is not yet consulted for routing/failover.

## Guardrails (INF-005)
`server/inference/guardrails.ts`, applied in the router for every request: (1) untrusted input is stripped of control/bidi characters, chat-template tokens, code fences and our own delimiter, truncated to 8000 chars, flagged by an injection-pattern list, and framed in `<untrusted_data>` with a system rule to treat it as data; (2) output must satisfy the request's JSON Schema (Ajv); (3) output strings outside declared script fields are scanned for executable constructs (rm -rf, pipe-to-shell, encoded PowerShell, shebangs, etc.); (3b) fields the caller declares in `input.scripts` (`{field, kind: bash|powershell|ansible}`, e.g. the remediation `bashScript`) skip the blanket scan and are validated by `validateScript`: bash may start with an allow-listed interpreter header (`#!/bin/bash`, `#!/usr/bin/bash`, `#!/usr/bin/env bash`, `#!/bin/sh`, `#!/usr/bin/env sh`), any other interpreter or an embedded shebang is rejected, a rollback section is required, size is capped at 20,000 chars, Ansible must be valid YAML, and every other dangerous pattern still applies; (4) optional Llama-Guard-style model (`INFERENCE_MODEL_GUARD`) whose unsafe verdict or outage fails closed. A failed output check discards the model answer, returns `fallback: true` with `guardrail.passed: false` and the violation list. Input injection markers are recorded in `guardrail.violations` but do not by themselves reject (legitimate logs can contain such text); the output checks are the enforcement point. Pattern lists are heuristics, not proof; OT-003 re-validates any script downstream.

## GPU-second metering (INF-006)
`server/inference/meter.ts`. `usage.gpuSeconds` is the backend-reported value (`usage.gpu_seconds`) if present, else wall-clock inference time x `INFERENCE_GPU_SHARE` (default 1). Gas credits = `ceil(gpuSeconds x GAS_CREDITS_PER_GPU_SECOND x 1000)/1000` (default 1 credit per GPU-second; tokens are reported but never billed). The router records every non-fallback response in the append-only `GasLedger` (usage entries are negative, grants positive, overdraft flagged), including answers later rejected by a guardrail since the GPU time was spent. The ledger is in-memory for now; persistence moves to the StateStore (AG-001) and hard caps/alerts come with ENT-005. The tenant is still `default` in `cecurAI.ts` until tenant context is plumbed through.

## Routing (INF-007, AG-004)
`server/inference/router.ts` fronts the gateway. `airgap` answers from the deterministic engine (`fallback: true`); its forensic role may reach a local site-node model only with `INFERENCE_AIRGAP_FORENSIC=on`. Any gateway failure also yields `fallback: true`. `cui`/`classified` requests on the `cloud` profile are rejected with `RoutingPolicyError` (no silent fallback).

## Durable vulnerability remediation

`POST /api/cecur/ai/remediate-vuln` accepts `{ "vulnerability": ... }` and returns HTTP 202 with an owner-scoped job. Repeating an active owner/vulnerability fingerprint returns the same job. Poll `GET /api/cecur/ai/remediate-vuln/jobs/:id`; `GET /api/cecur/ai/remediate-vuln/jobs/active?vulnerabilityId=...` recovers active work. All responses use `Cache-Control: no-store`, and another owner receives the same 404 as a missing job.

Jobs persist in `cs3.remediation_jobs` (migration `006_remediation_jobs.sql`). One console worker generates sequentially. `queued` jobs were never dispatched and can resume after restart. A persisted `running` job has an uncertain dispatch/outcome and becomes `interrupted`; it is never retried automatically. Terminal states are `completed`, `fallback`, `failed`, and `interrupted`. This recovery model requires one console worker; multiple replicas need worker ownership/leases before being enabled.

`INFERENCE_REMEDIATION_TIMEOUT_MS` (default 3,600,000 ms; allowed 1,000–7,200,000) applies only to remediation. Each job makes one backend attempt (`retries: 0`) with at most 4,096 completion tokens. Other inference routes retain `INFERENCE_TIMEOUT_MS`. The Docker Ollama NGINX completion path permits 3,900-second upstream operations and sets `proxy_next_upstream off`; its HAProxy alternative uses a dedicated non-retrying completion backend. Values above 3,600,000 ms require a corresponding proxy-timeout increase. Apply migration 006 explicitly on an existing database because PostgreSQL init scripts only run automatically on an empty volume.

A result has explicit `source: "ai" | "deterministic"` provenance. All six fields—executive summary, patch steps, Bash, PowerShell, Ansible, and mitigation/workaround—are required for AI output. Partial, invalid, or unsafe model output becomes an explicitly labeled deterministic fallback; heuristic snippets are never presented as model-authored work. The UI displays every field and never executes a script automatically. Closing its modal stops browser polling but does not cancel Host generation; submitting the same active finding recovers the job.

## Contract Changes
* New `server/inference/types.ts` (as specified in the build plan).
* `GET /api/system/environment-status` adds `inference`; the legacy `gemini`/`deepseek` keys have been removed.
* `AIProviderStatus` exposes `inference*` fields only; the Gemini/DeepSeek fields have been removed.
* Cloud profile no longer reads `GEMINI_API_KEY`/`DEEPSEEK_API_KEY`; cloud needs `INFERENCE_GATEWAY_URL`.
* `InferenceRequest.options` adds per-request `timeoutMs` and `retries`; zero retries disables additional backend attempts without changing synchronous defaults.
* Vulnerability remediation is asynchronous (202 submission plus authenticated job polling), adds durable job types/states, and returns remediation results with explicit `source` provenance.
