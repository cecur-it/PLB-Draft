# llm-gateway — RUNTIME (CONTRACT §11)

Traces: PROMPT §1 Tier 4 / §2.3 / §2.5. Python 3.12 aiohttp service; guardrails + Ollama cascade + MCP policy + hash-chained audit.

## Image / build
- Build context `llm-gateway/`, Dockerfile `llm-gateway/Dockerfile` (base pinned by digest, deps `requirements.txt` `==`).
- Tag `vendetta-stack/llm-gateway:${STACK_VERSION:-1.0.0}` (`--build-arg STACK_VERSION=...`). `mcp_policy.yaml` is baked in at `/app/mcp_policy.yaml`.
- `ENTRYPOINT ["python","/app/server.py"]`, no CMD. Flags: `--help`, `--version`, `--selftest` (offline), `--healthcheck`. Exit codes: 0 ok, 1 selftest/healthcheck failed, 2 bad config, 3 FailClosedError (do NOT auto-restart on 3).

## Ports
- `9101/tcp` HTTPS (`GATEWAY_TLS=on`, default). `/health` + `/metrics` need no token; everything else needs `Authorization: Bearer <token>`.
- Sidecar `ollama-lb` shares this netns (`network_mode: service:llm-gateway`) and owns `127.0.0.1:11434` — never publish/bind it here.

## Secrets / PKI (read at start)
- `/run/secrets/llm_gateway_token` (`LLM_GATEWAY_TOKEN_FILE`, ≥16 chars; shared with fluentd/errow/prometheus callers; re-read when the file's mtime changes, so rotation needs no restart).
- `/pki/llm-gateway.crt|key` (server cert, and mTLS client cert towards errow-mcp), `/pki/ca.crt`.
- `/etc/llm-gateway/models.json` (ro, optional; mount `ollama/models.json`; `/v1/chat/completions` model allow-list, plus the two configured tags).

## Volumes
- `/var/lib/llm-gateway/spool` **rw**, owned by uid 10001: audit hash-chain state + durable spool. ONE VOLUME PER REPLICA (flock-guarded; two replicas on one dir refuse to start). Losing it breaks continuity of that replica's chain, not security.
- `/pki` ro, `/etc/llm-gateway` ro, optional `MCP_TARGETS_FILE` (ro, may only ADD allow-list hosts/cidrs/domains/repo_paths). Nothing else is written.

## Environment (name = default — meaning)
- `CS3_PROFILE` = `onprem` (`cloud|onprem|airgap|edge`). onprem/airgap are FAIL-CLOSED: exit 3 if any of `GEMINI_API_KEY DEEPSEEK_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY LLM_API_KEY` (or `*_FILE`) is set, `CS3_LLM_MODE`≠`local`, or `OLLAMA_BASE_URL` is non-loopback; `GATEWAY_TLS=off` is refused.
- `OLLAMA_BASE_URL` = `http://127.0.0.1:11434/v1` — the node-local ollama-lb. `INFERENCE_MODEL_TRIAGE` = `nemotron-3-nano:30b`; `INFERENCE_MODEL_FORENSIC` = `gemma4:26b`; `INFERENCE_MODEL_DEEP` = `gemma4:31b`; `INFERENCE_MODEL_SECURITY` = `INFERENCE_MODEL_ERROW_SECURITY` = `nemotron-3-nano:30b` (the same agentic tag as triage, with its own chain/budget/no-cache flag; each security chain falls back to `_DEEP` = `gemma4:31b` only; the `OLLAMA_*_MODEL` names are accepted as deprecated aliases; the guard must differ from the security models, which config enforces); `INFERENCE_TIMEOUT_MS` = `60000` (per model attempt); `INFERENCE_GPU_SHARE` = `1.0` (`gpu_seconds = latency × share`, 0 for heuristics).
- `GATEWAY_HOST` `0.0.0.0`; `GATEWAY_PORT` `9101`; `GATEWAY_TLS` `on`; `GATEWAY_MTLS` `optional` (`required|optional|off`; the HEALTHCHECK and Prometheus then need a client cert when `required`); `PKI_DIR` `/pki`.
- `GATEWAY_MAX_CONCURRENCY` `4` (concurrent inferences), `GATEWAY_MAX_QUEUE` `512` (waiting records, else 429), `GATEWAY_MAX_BODY_BYTES` `1048576`, `GATEWAY_MAX_RECORDS` `100`, `GATEWAY_REQUEST_TIMEOUT_S` `300` (keep < Fluentd `read_timeout`), `CS3_MESSAGE_MAX_CHARS` `8000`.
- `FLUENT_BIT_HTTP_URL` `http://fluent-bit:9880` (events POSTed to `/<tag>`: `cs3.ai.inference|tool_call|enrichment`), `GATEWAY_SPOOL_DIR` `/var/lib/llm-gateway/spool`, `GATEWAY_SPOOL_MAX_EVENTS` `100000` (full ⇒ 503 `audit_unavailable`, never silent loss).
- `MCP_LIVE` `false` (`true` ⇒ real calls; otherwise dry-run), `ERROW_MCP_URL` `https://errow-mcp:9103/mcp`, `MCP_POLICY_PATH` `/app/mcp_policy.yaml`, `MCP_TARGETS_FILE` unset, `MCP_OUTPUT_MAX_CHARS` `8000`, `MCP_DNS_TIMEOUT_S` `2`.
- `OLLAMA_GPU_UTIL_FILE` unset (file with 0-1 or %; else `nvidia-smi` if present, else 0), `GATEWAY_MAINTENANCE_FILE` `/var/lib/llm-gateway/maintenance` (exists ⇒ triage reports `gpu_maintenance`), `MODELS_JSON_PATH` `/etc/llm-gateway/models.json`, `LOG_LEVEL` `INFO`, `STACK_VERSION` `1.0.0`.

## Healthcheck (no curl)
`["python","/app/server.py","--healthcheck"]` — GETs `https://127.0.0.1:9101/health` (CA `/pki/ca.crt`, client cert when mTLS≠off). `/health` is 200 even when degraded (Ollama or Fluent Bit down); read `.status`. Suggested `interval 15s, timeout 5s, start_period 20s, retries 3`.

## Hardening
`user: "10001:10001"`, `read_only: true` (+ no tmpfs needed), `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, mount only the spool rw. Networks: `inference` (Ollama workers via ollama-lb), `pipeline` (fluent-bit), `errow` (errow-mcp). Start order: fluent-bit and errow-mcp are NOT hard dependencies (spool + dry-run/502 handle absence); `bootstrap-pki` and the token secret are.

## Kubernetes
- Probes: liveness+readiness `httpGet /health` scheme HTTPS port 9101 (mTLS `required` ⇒ use `exec` with `--healthcheck`); readiness may additionally gate on `.status == "ok"` via exec only if you want to shed traffic while degraded.
- Pod = gateway + `ollama-lb` sidecar (shared netns). `securityContext: runAsUser/runAsGroup/fsGroup 10001`, `readOnlyRootFilesystem: true`.
- StatefulSet with a `volumeClaimTemplate` (or per-pod emptyDir) for the spool — one per replica. `terminationGracePeriodSeconds: 20`.
- Prometheus: scrape `https://<pod>:9101/metrics` (client cert if mTLS required). Alerts key off `llm_gateway_audit_chain_ok`, `llm_gateway_spool_depth`, `llm_gateway_failover_total`.
