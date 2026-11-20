# Runbooks

Every `runbook:` annotation in `prometheus/alerts.yml` points at a heading in this file
(`prometheus/tests/validate.sh --strict-docs` fails when an anchor is missing).
Commands assume the Compose deployment from `$STACK`; on Kubernetes replace `docker compose exec <svc>` with
`kubectl -n vendetta exec deploy/<svc> --` (DaemonSet: `ds/fluent-bit`).

General rules: never delete buffer/spool chunks to "make an alert go away"; `scripts/healthcheck.sh` is the first command
for every runbook; all outbound offensive actions stay `dry-run` unless `MCP_LIVE` / `ERROW_FEEDBACK_LIVE` were
deliberately enabled.

## Fluent Bit down
**Impact:** edge records stop flowing; sources keep their files, tail DB offsets resume on restart (no loss for `tail` inputs; `http`/`forward` senders retry or spool).
1. `docker compose ps fluent-bit && docker compose logs --tail 100 fluent-bit`
2. Check free space on `fluentbit-storage` (`/var/log/fluent-bit`); a full disk is the usual cause.
3. `docker compose up -d fluent-bit` and confirm `curl -fsS http://127.0.0.1:2020/api/v1/health` (inside the container).

## Fluent Bit output retrying
**Impact:** one output (named in the alert) cannot deliver; records queue in the filesystem buffer.
1. Identify the output from the alert label; test its destination from the container (`docker compose exec fluent-bit ...`).
2. Check certificate expiry (`scripts/rotate-certs.sh --only-expiring --dry-run`) and the token files in `/run/secrets`.
3. Fix the destination; the queue drains automatically (`Retry_Limit False`).

## Fluent Bit data loss
**Impact:** chunks were dropped after `Retry_Limit` or a storage overflow. Should not occur for the forward output (`Retry_Limit False`).
1. `docker compose logs fluent-bit | grep -Ei 'drop|discard|failed to flush'` and note the time window.
2. Restore the destination, then re-ship from the sources if retention allows (tail inputs: remove the matching row from the tail DB; Errow: `errow-shipper` state file `/var/lib/errow-shipper/state.json`).
3. Record the gap window for the audit trail when the lost stream was `cs3.ai.*`.

## Fluent Bit backpressure
**Impact:** inputs are paused (`storage.pause_on_chunks_overlimit on`); nothing is dropped but latency grows.
1. Check Fluentd health (see "Fluentd node down") and disk space under `/var/log/fluent-bit/storage`.
2. Look at which input is paused (`/api/v1/storage`), and `FLB_FORWARD_STORAGE_LIMIT`.
3. Do not raise limits without matching disk.

## Fluentd node down
**Impact:** the surviving aggregator serves the whole edge (`upstream.conf` is active-active, `phi_threshold` failure detection).
1. `docker compose ps fluentd-1 fluentd-2`; restart the failed node (`docker compose up -d fluentd-N`).
2. Its file buffer (`fluentd-buffer-N`) is replayed on start; verify `fluentd_output_status_buffer_queue_length` falls.
3. If both are down the edge buffers on disk; bring one up first, then the other.

## Fluentd buffer backlog
**Impact:** an output is slower than the input; buffer queue length is growing.
1. Read `plugin_id` from the alert (`opensearch`, `opensearch-errow`, `opensearch-llm-audit`, `http-llm-triage`, `http-feedback-loop`, ...).
2. Test the destination; check `GET _cluster/health` and index write blocks on OpenSearch.
3. For `http-llm-triage` see "LLM queue saturated".

## Fluentd buffer nearly full
**Impact:** `overflow_action block` will back-pressure Fluent Bit once `total_limit_size` is reached.
1. Restore the destination first.
2. Raise `FLUENTD_OS_BUFFER_LIMIT` only together with disk on `fluentd-buffer-N`.
3. Never delete buffer chunks; losing them loses audit records.

## Fluentd output retrying
1. `docker compose logs fluentd-1 | grep -E 'retry|error'` for the `plugin_id`.
2. 401/403: token or client certificate; 429: destination busy; red index or `index read-only`: see "Fluentd buffer backlog".
3. After the fix the exponential backoff (`retry_max_interval`) clears on its own.

## Fluentd output errors
**Impact:** bulk items are rejected (mapping conflicts, ingest pipeline failures).
1. Search the log for `bulk item` errors; inspect the dead-letter files in `/var/log/fluentd/dead-letter/`.
2. Fix the mapping (`opensearch/index-templates/`) or the producer; re-run `opensearch/apply.sh` (idempotent).
3. Replay the rejected documents from the dead-letter file.

## Fluentd emit stall
**Impact:** records enter Fluentd but are not emitted by any output.
1. Verify the forward path (mTLS CN `fluent-bit`), then `fluentd/tests` routing tests.
2. Inspect the label wiring in `fluentd/conf.d/15-routing.conf` and the `unrouted` dead-letter file.

## Pipeline dead letter
**Impact:** a tag had no route or a record could not be indexed.
1. Read `/var/log/fluentd/dead-letter/{error,unrouted}*`.
2. Fix the producer tag or the mapping; replay by copying records to Fluent Bit `:9880/<tag>`.

## LLM gateway down
**Impact:** no AI enrichment; Vendetta alerts continue to be indexed unmodified; MCP tool calls are refused.
1. `docker compose ps llm-gateway ollama-lb`. `ollama-lb` shares the gateway's network namespace: **always restart `ollama-lb` right after the gateway**.
2. Exit code 3 means `FailClosedError` (a hosted-LLM key or non-loopback Ollama URL in an onprem/airgap profile): fix the configuration, do not auto-restart.
3. `docker compose exec llm-gateway python /app/server.py --healthcheck` (see `llm-gateway/RUNTIME.md`).

## LLM failover
**Impact:** the primary triage model is failing; answers come from the forensic model or from `Cecur Heuristics` (flagged `ai.fallback=true`).
1. Check Ollama worker health (`/api/tags` through `ollama-lb`) and GPU state (`nvidia-smi`).
2. Check primary model load time and eviction (`OLLAMA_KEEP_ALIVE`, `OLLAMA_MAX_LOADED_MODELS`).
3. The SOC is never stalled: tier 3 is deterministic and needs no GPU.

## LLM triage latency
1. Check `llm_gateway_queue_depth`, GPU memory (`ollama_gpu_memory_util`) and model eviction.
2. Tune `GATEWAY_MAX_CONCURRENCY` and `OLLAMA_NUM_PARALLEL` together (HAProxy `maxconn` per server must match).

## LLM queue saturated
**Impact:** alert storm exceeds inference capacity; HAProxy queue (30 s) then heuristics absorb the overflow.
1. Add a worker behind `ollama-lb` (`scripts/enroll-ollama.sh`), or raise concurrency within VRAM limits.
2. Narrow `LLM_TRIAGE_VENDETTA_SEVERITY_REGEX` to shed load (low-severity alerts are enriched by heuristics anyway).

## LLM prompt injection burst
**Impact:** many inputs matched injection signatures. They are still triaged defensively (framed, severity floor), but the source deserves attention.
1. Find the source host in `cs3-ai-inference-*` (`guardrail.violations` starting with `input:`).
2. Isolate the host; keep blocking on. Do **not** disable the guardrails to silence the alert.

## LLM schema violations
**Impact:** models return output that fails the `AIIncidentAnalysis` schema; the cascade falls back safely.
1. Compare model tag/digest and prompt version; re-run `scripts/enroll-ollama.sh --node <name> --container <ollama-1> --release` (verifies the SHA-256 pins).
2. A sudden burst may indicate model drift or an attack; check the guardrail logs.

## LLM audit chain broken
**Impact:** AU-9 integrity failure — `llm_gateway_audit_chain_ok == 0`. Treat as a security incident.
1. Freeze: stop the gateway replica, preserve `cs3-ai-audit-*` snapshots and the spool directory.
2. Verify offline: `python llm-gateway/tools/verify_audit_chain.py <export.ndjson>`; identify the first broken `seq`.
3. Open an AU-9 incident; do not repair or rewrite events.

## LLM audit spool backlog
**Impact:** audit events cannot reach Fluent Bit and are spooled on disk (no loss while the disk lasts).
1. Check Fluent Bit `:9880` reachability from the gateway and the free space on `llm-gateway-spool`.
2. Delivery resumes automatically in order.

## LLM audit data loss
**Impact:** audit events were dropped (spool exhausted). Reportable.
1. Record the gap window (`seq` range per `chain_id`).
2. Restore delivery; reconcile from gateway logs; report per the audit policy.

## Ollama GPU memory
1. Lower `GATEWAY_MAX_CONCURRENCY`, unload the idle model (`OLLAMA_KEEP_ALIVE`) or add a GPU worker.
2. On 16 GB cards use `gemma4:26b` as the forensic model rather than `gemma4:31b`.

## LLM no inference traffic
1. Confirm Vendetta is producing alerts (`vendetta-alerts-*`).
2. Check the Fluentd `http-llm-triage` output and its severity regex; confirm the gateway token file is mounted.

## Errow MCP down
**Impact:** AI-initiated tool calls are refused (fail-closed); scans can still be started by analysts.
1. `docker compose ps errow-mcp`; check its certificate (`/pki/errow-mcp.crt`) and that `scan-target.vendetta.lab` (or `MCP_TARGETS_FILE` targets) resolve.
2. `/health` needs a client certificate; use the container's exec healthcheck.

## Errow MCP denied burst
**Impact:** many tool calls were denied by policy — either a misbehaving model or a probing attempt.
1. Query `cs3.ai.tool_call` audit events (`decision: denied`) in `errow-mcp-*`; identify the incident and requested targets.
2. Do not widen `mcp_policy.yaml`; fix the plan. Policy edits go through `scripts/sync-mcp-policy.sh`.

## Observability self monitoring
**Impact:** Prometheus or Alertmanager itself is unhealthy; alerts may not fire.
1. Check both containers and the config validation output (`promtool check config`, `promtool check rules`).
2. Check the rule-evaluation log.
