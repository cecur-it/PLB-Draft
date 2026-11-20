# llm-gateway

Traces: PROMPT §1 Tier 4 (sovereign LLM tier), §2.3 (fail-closed / failover), §2.5 (guardrails, audit); CONTRACT §4.2–§4.5, §8, §11.

An async Python 3.12 service (aiohttp, jsonschema, PyYAML, prometheus-client) that sits between the pipeline/Errow and the node-local Ollama tier:

- **Triage / forensic analysis** of Vendetta alerts and Errow findings → strict `AIIncidentAnalysis` JSON, with a 3-tier cascade that can never fail.
- **Two-stage guardrails**: untrusted-data framing and injection screening on the way in; schema and executable-content validation on the way out.
- **MCP tool-call policy gate** in front of `errow-mcp` (deny-first, rate-limited, dry-run unless `MCP_LIVE=true`).
- **Metered OpenAI-compatible passthrough** for allow-listed local models.
- **Hash-chained audit trail** (`cs3.ai.*` events) with a durable spool, so an outage of Fluent Bit never loses or silently reorders evidence.

Exact container/runtime facts (ports, mounts, healthcheck, K8s) are in [`RUNTIME.md`](RUNTIME.md).

## Architecture

```
 Fluentd (http-llm-triage)           errow agents / MCP bridge
        │  POST /triage (json | array | ndjson)        │ POST /mcp/tool_call
        ▼                                              ▼
 ┌────────────────────────── llm-gateway :9101 (TLS, optional mTLS, bearer) ──────────────────────────┐
 │ server.py ── auth ── body cap ── request timeout ── telemetry-loop guard (cs3.ai.* ⇒ 400)         │
 │    │                                                                                               │
 │    ├─ records.py   parse/derive alert_id ─ guardrails.py  sanitize + redact + frame <untrusted_data>│
 │    ├─ failover.py  ConcurrencyGate ─► tier1 triage model ─► tier2 forensic model ─► tier3 heuristics│
 │    │                        │  backend.py (Ollama OpenAI-compat, 127.0.0.1:11434 via ollama-lb)     │
 │    │                        └─ schema.py (JSON Schema) + guardrails.py (output scan) + severity floor│
 │    ├─ mcp.py + policy.py   mcp_policy.yaml ─► allow/deny ─► rate limits ─► dry-run | live JSON-RPC  │
 │    ├─ meter.py     Prometheus /metrics, gpu_seconds, tokens                                         │
 │    └─ audit.py     hash chain ─► spool (fsync) ─► POST fluent-bit:9880/<tag>  (retry + backoff)     │
 └──────────────────────────────────────────────────────────────────────────────────────────────────────┘
        │ cs3.ai.inference | cs3.ai.tool_call | cs3.ai.enrichment            │ mTLS tools/call
        ▼                                                                    ▼
    Fluent Bit :9880  →  Fluentd  →  cs3-ai-audit-* / vendetta-alerts     errow-mcp :9103
```

### Two-stage guardrails

```
 raw telemetry ─► STAGE 1 (edge, Fluent Bit Lua: cs3-otlp-normalize.lua)        STAGE 2 (this service)
                  credential redaction (`Bearer <token>`, key=value and     ─►   sanitize: strip control / zero-width /
                  key: value secrets such as password/token/api_key),            bidi chars, <|token|> → [token],
                  field normalisation — runs before data leaves the host         <untrusted_data> tags neutralised,
                                                                                  ``` → ''' ; cap CS3_MESSAGE_MAX_CHARS
                                                                                  (default 8000, UTF-8 safe)
                                                                                  redaction again (identical algorithm)
                                                                                  injection screen ⇒ flag, never obey
                                                                                  frame inside <untrusted_data>…</…>
                                                                              ─► model (temperature 0.2, JSON mode)
                                                                              ─► parse (fenced ```json tolerated)
                                                                                  JSON Schema, additionalProperties:false
                                                                                  dangerous-output scan (rm -rf, curl|sh…)
                                                                                  severity floor if injection flagged
                                                                              ─► analysis + meta.guardrail{passed,violations}
```

An injection-flagged record is still analysed, but its severity can never fall below the deterministic heuristic severity (`output:severity_floor`, `needsVerification=true`).

## HTTP API (all but `/health` and `/metrics` require `Authorization: Bearer <llm_gateway_token>`)

| Route | Purpose |
|---|---|
| `GET /health` | Always 200 (liveness); `status` is `ok` or `degraded` (Ollama/Fluent Bit down, chain broken, maintenance). |
| `GET /metrics` | Prometheus text exposition. |
| `POST /triage[?role=triage\|forensic]` | One record, a JSON array, or NDJSON. Returns `{"results":[{request_id, alert_id, analysis, meta}]}`. Any `cs3.ai.*` record/tag/stream (body, query, header) rejects the whole request with 400 `telemetry_loop_rejected`. Model `toolCalls` are returned, **never executed here**. |
| `POST /forensic` | Same as `/triage?role=forensic`; analysis also carries `proposedDetectionRule` and `proposedRemediation`. |
| `POST /security[?role=security\|errow]` | Chat-mode security/Errow analysis (`{"input": …}` in, chain + `meta.role` out) with the same guardrails and the human-approval gate on mutating tool calls. |
| `POST /mcp/tool_call` | Envelope `{tenant_id, incident_id, role, tool, args, rationale}` → 200 `dry_run`/`executed`, 403 `policy_violation` (`violations[]`), 429 `rate_limited` (`limited_by`, `Retry-After`), 502 `error`. |
| `POST /v1/chat/completions` | Metered passthrough: model must be in the allow-list, `stream:false` only (else 400), temperature clamped to ≤ 0.2, `top_p` ≤ 0.9, `n=1`. `GET /v1/models` lists the allow-list. |
| `model` aliases on `/v1/chat/completions` | `cs3-security`/`cs3-vuln-analysis` → `security`, `cs3-errow-security`/`cs3-errow` → `errow`, `cs3-deep`/`cs3-reasoning-deep` → `deep`; everything else stays passthrough. Aliases let Errow pin `errow_LLM=openai/cs3-errow-security` instead of a raw tag. |
| Agentic calls | On `errow`, and on any alias call that carries `tools[]`, the caller owns the conversation: `messages` (including `tool` results and assistant `tool_calls` turns), `tools` and `tool_choice:auto` are forwarded untouched and `response_format` is dropped so the model can answer with native `tool_calls` (`finish_reason:tool_calls`). Analysis calls without tools keep the strict-JSON framing, so they never invent fields. Without this, an agent loop got JSON prose back, logged "ended a turn without a lifecycle tool call", and burned hundreds of forced continuations per scan. A one-line gateway system preface asks for bare schema arguments; without it the model writes the tool name back into the command (`"cmd": "exec_command cmd=\"curl …\""`) and every sandbox call exits 127. The approval gate still sits on top of the loop: the first turn of an agentic call that proposes `execute_command`/`isolate_host`/`modify_firewall` answers 403 `approval_required` unless the request carries `X-CS3-Approval` (or `approval_token`); Errow sends it from `CS3_APPROVAL_TOKEN[_FILE]`, so an operator approves the run once at launch instead of once per turn. |

Errors: `{"error": code, "message", "request_id"}`; on `/v1/*` the OpenAI shape `{"error": {message,type,code,param}}`.

### Failover cascade

Every task class owns a chain (config: `chain_for()`); the response header `x-cs3-model` names the model that answered and `meta.fallback`/`degraded_model_fallback` say how it was reached:

| Task class | Chain |
|---|---|
| `triage` | `INFERENCE_MODEL_TRIAGE` (nemotron) → `_FORENSIC` (gemma4:26b) → heuristics |
| `forensic` | `_FORENSIC` → `_TRIAGE` (nemotron) → heuristics |
| `deep` | `_DEEP` → `_FORENSIC` → `_TRIAGE` → heuristics |
| `security` | `_SECURITY` (nemotron-3-nano:30b) → `_DEEP` (gemma4:31b) only (never `_TRIAGE` or the 26B forensic model) |
| `errow` | `_ERROW_SECURITY` (nemotron-3-nano:30b) → `_DEEP` (gemma4:31b) only (never the 26B forensic model) |

Invalid JSON, schema violation, dangerous output, HTTP 5xx, connection failure or `INFERENCE_TIMEOUT_MS` ⇒ next tier; reasons are `backend_unavailable`, `schema_violation`, `guardrail_rejected`, `timeout`, `gpu_maintenance`. Triage ends in deterministic heuristics (`heuristics.py`, `engineUsed:"Cecur Heuristics"`, role `heuristic`): pure code that cannot fail. `security`/`errow` are chat-mode and answer a typed error instead — a degraded Errow run is `degraded_model_fallback: true` and must be reviewed by an analyst. Rationale and the ISSO acceptance log: [`docs/qwensploit-routing-rationale.md`](../docs/qwensploit-routing-rationale.md). Concurrency is bounded (`GATEWAY_MAX_CONCURRENCY`, queue `GATEWAY_MAX_QUEUE`, `llm_gateway_queue_depth`) so alert storms cannot thrash the KV cache; a full queue answers 429 + `Retry-After`.

### MCP policy

`mcp_policy.yaml` (byte-identical copy of `errow/mcp/policy.yaml`; kept in sync by `scripts/sync-mcp-policy.sh --check`) is loaded exactly as written and never edited by this service. Evaluation is deny-first: envelope → tool known → role permitted → per-argument schema (`required`, enums, maxima, patterns) → forbidden args/tags → target extraction by `target_kind` → denied hostnames/CIDRs/ports (including every DNS-resolved address) → allow-list → rate limits (tenant, cluster, tool, target, tool+target; token buckets) → concurrency semaphore. `MCP_TARGETS_FILE` can only **add** allow-list entries. Every outcome (`allowed|denied|rate_limited|dry_run|executed|error`) emits `cs3.ai.tool_call`. With `MCP_LIVE=true` the validated args go to `ERROW_MCP_URL` as an mTLS JSON-RPC 2.0 `tools/call`; output is redacted, sanitised and truncated.

### Audit chain

Events (`cs3.ai.inference`, `cs3.ai.tool_call`; `cs3.ai.enrichment` is unchained) carry `chain_id` (per replica), `seq`, `prev_hash`, `hash = sha256(prev_hash + canonical_json(event without hash))` (sorted keys, no whitespace, genesis = 64 zeros). State lives in the spool volume so restarts continue the chain. Events never contain raw telemetry — only `input_sha256` and `input_chars`. Verify an export of `cs3-ai-audit-*`:

```
python tools/verify_audit_chain.py export.ndjson            # exit 0 verified, 1 broken chain, 2 usage/IO error
python tools/verify_audit_chain.py --require-genesis --chain-id <id> export.ndjson.gz
```

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `CS3_PROFILE` | `onprem` | `onprem`/`airgap` are fail-closed (exit 3 on any hosted-LLM key, `CS3_LLM_MODE`≠`local`, non-loopback `OLLAMA_BASE_URL`, or TLS off) |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434/v1` | node-local ollama-lb |
| `INFERENCE_MODEL_TRIAGE` / `_FORENSIC` / `_DEEP` | `nemotron-3-nano:30b` / `gemma4:26b` / `gemma4:31b` | tier 1 / tier 2 / long-context tags |
| `INFERENCE_MODEL_SECURITY` / `_ERROW_SECURITY` | `nemotron-3-nano:30b` | `security` / `errow` primary tag (must differ from `INFERENCE_MODEL_GUARD`; `OLLAMA_SECURITY_MODEL` accepted as a deprecated alias). Both chains fall back to `_DEEP` (`gemma4:31b`) only |
| `INFERENCE_TIMEOUT_MS` | `60000` | per model attempt, all roles |
| `INFERENCE_TIMEOUT_MS_<ROLE>` | `120000` for `SECURITY`/`ERROW_SECURITY`/`DEEP`, else `INFERENCE_TIMEOUT_MS` | per role override: an agentic security/Errow turn answers over a large tool+findings context and 60 s timed out on real scan loops, silently pushing every turn onto the fallback |
| `INFERENCE_GPU_SHARE` | `1.0` | `gpu_seconds = latency_s × share`; 0 for heuristics |
| `CS3_MESSAGE_MAX_CHARS` | `8000` | untrusted-input cap |
| `GATEWAY_MAX_CONCURRENCY` / `GATEWAY_MAX_QUEUE` | `4` / `512` | inference slots / waiting records |
| `GATEWAY_MAX_BODY_BYTES` / `GATEWAY_MAX_RECORDS` / `GATEWAY_REQUEST_TIMEOUT_S` | `1048576` / `100` / `300` | request limits |
| `GATEWAY_HOST` / `GATEWAY_PORT` | `0.0.0.0` / `9101` | listen address |
| `GATEWAY_TLS` / `GATEWAY_MTLS` | `on` / `optional` | `required\|optional\|off`; CA `/pki/ca.crt`, cert `/pki/llm-gateway.crt\|key` |
| `LLM_GATEWAY_TOKEN_FILE` | `/run/secrets/llm_gateway_token` | bearer token (≥16 chars, constant-time compare) |
| `FLUENT_BIT_HTTP_URL` | `http://fluent-bit:9880` | audit sink (`POST /<tag>`) |
| `GATEWAY_SPOOL_DIR` / `GATEWAY_SPOOL_MAX_EVENTS` | `/var/lib/llm-gateway/spool` / `100000` | durable spool + chain state |
| `MCP_LIVE` | `false` | `true` ⇒ execute against `ERROW_MCP_URL` (default `https://errow-mcp:9103/mcp`) |
| `MCP_POLICY_PATH` / `MCP_TARGETS_FILE` / `MCP_OUTPUT_MAX_CHARS` / `MCP_DNS_TIMEOUT_S` | baked-in policy / unset / `8000` / `2` | policy source, additive allow-list, output cap, resolver timeout |
| `MODELS_JSON_PATH` | `/etc/llm-gateway/models.json` | passthrough model allow-list |
| `OLLAMA_GPU_UTIL_FILE` | unset | source for `ollama_gpu_memory_util` (else `nvidia-smi`, else 0) |
| `GATEWAY_MAINTENANCE_FILE` | `/var/lib/llm-gateway/maintenance` | present ⇒ `gpu_maintenance` failover reason |
| `LOG_LEVEL`, `STACK_VERSION` | `INFO`, `1.0.0` | JSON logs to stdout (never telemetry or secrets) |

## Metrics

`llm_gateway_requests_total{role,engine,fallback}`, `llm_gateway_triage_latency_seconds`, `llm_gateway_failover_total{from,to,reason}`, `llm_gateway_queue_depth`, `llm_gateway_output_schema_violations_total`, `llm_gateway_prompt_injection_blocked_total`, `llm_gateway_gpu_seconds_total{role,model}`, `llm_gateway_tokens_total{direction,role,model}`, `llm_gateway_mcp_tool_calls_total{tool,decision}`, `llm_gateway_audit_chain_ok`, `llm_gateway_spool_depth`, `ollama_gpu_memory_util`; plus `llm_gateway_guardrail_rejections_total{kind}`, `llm_gateway_audit_events_total|dropped_total|quarantined_total{tag}` and `llm_gateway_build_info`.

## TS ↔ Python equivalence (for the lead engineer)

| CS3 TypeScript (`demo/demo-100226/server/…`) | This service | Notes |
|---|---|---|
| `inference/guardrails.ts` | `guardrails.py`, `records.py` | Same `INJECTION_PATTERNS`, `DANGEROUS_OUTPUT`, sanitize rules, 8000-char cap, `<untrusted_data>` framing. Deliberate fail-safe supersets: NFKC / invisible-char-normalised injection matching, C1 controls, `<untrusted_data>` tag variants. Credential redaction is the Lua edge algorithm. |
| `inference/gateway.ts` | `server.py`, `failover.py`, `backend.py` | HTTP surface, bounded concurrency, Ollama OpenAI-compat call (`temperature 0.2, top_p 0.9, top_k 40`, JSON mode). |
| `inference/router.ts` | `failover.py` | Cascade/failover reasons; forensic requests fall back to the triage model before heuristics. |
| `inference/meter.ts` | `meter.py` | `gpu_seconds`, token counters, Prometheus series. |
| `inference/types.ts` | `schema.py`, `schemas/ai_incident_analysis.schema.json` | `AIIncidentAnalysis` as strict JSON Schema (`additionalProperties:false`). |
| `ai/cecurAI.ts` | `heuristics.py`, `prompts.py` | Deterministic MITRE/anomaly map (tier 3) and the system/user prompts (`Ensure output is strictly valid JSON.`). |
| *(new)* | `mcp.py`, `policy.py`, `audit.py`, `config.py`, `tlsutil.py`, `selftest.py` | MCP gate, hash-chained audit, env/fail-closed parsing, TLS contexts, `--selftest`. |

## Development

```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/pytest -q          # fake Ollama / errow-mcp / Fluent Bit backends; no network, no GPU
docker build -t vendetta-stack/llm-gateway:1.0.0 .
docker run --rm vendetta-stack/llm-gateway:1.0.0 --selftest
```
