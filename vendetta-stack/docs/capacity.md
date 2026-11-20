# Capacity test plan

The throughput figures in [`PHASE1-GAP-ANALYSIS.md`](PHASE1-GAP-ANALYSIS.md) §4.3 are **planning numbers, not measurements**.
They were derived from the Vendetta `events_per_second: 500` limit, the Ollama/Nemotron/Gemma published characteristics
and the configured concurrency caps. This plan turns each into a pass/fail experiment you run on **your** hardware before
sizing production. Nothing here needs external services; the load generator is `tests/loadgen.py` (stdlib only).

## 1. Budgets under test

| ID | Path | Target (sustained) | Burst | Pass criterion |
|---|---|---|---|---|
| C1 | agent/edge → Fluent Bit → Fluentd → OpenSearch | 500 events/s | 5,000 events/s for 60 s | 0 lost documents, p95 end-to-end < 15 s, `fluentbit_storage_fs_chunks_down` returns to 0 within 5 min after the burst |
| C2 | Errow artifact → shipper → pipeline | 50 rec/s per scan | 1,000 rec/s at scan end | no duplicates (stable ids), shipper lag < 30 s |
| C3 | Fluentd → `/triage` (medium+ only) | 1.5-3 req/s per Nemotron worker | storm 10× | gateway concurrency cap holds, queue ≤ 30 s, overflow answered by heuristics (never 5xx), SOC path never stalls |
| C4 | `/forensic` (findings ≥ high) | 0.3-1 req/s (26b), 0.1-0.3 req/s (31b) | n/a | p95 < 120 s (26b), < 300 s (31b) |
| C5 | `mcp_tool_calls_per_sec` | 10/min/tenant, 100/min/replica, 4 concurrent | hard cap | excess is **rejected** (429), never queued unbounded |
| C6 | failover cascade | n/a | worker killed mid-load | Nemotron down ⇒ forensic model answers; all down ⇒ `Cecur Heuristics`; zero client-visible failures |
| C7 | sustained 24 h soak | C1 + C3 at 50% | — | no RSS growth > 10%, buffers bounded, audit hash-chain verifies end to end |

## 2. Procedure (Compose on the target hardware)

```bash
cd cecur-it-cs3-v1.1.0/vendetta-stack
scripts/bootstrap.sh --dev-readable-keys                       # secrets + PKI (production: scripts/bootstrap.sh --key-group <gid>)
docker compose --env-file .env.smoke --profile test up -d --wait   # smoke topology; swap --profile mock-llm for --profile llm on a GPU host
```

C1 — pipeline throughput (uses the Fluent Bit HTTP hook; run from a container on the `edge` network):

```bash
docker compose --env-file .env.smoke --profile test run --rm --no-deps smoke-runner \
  python3 /tests/loadgen.py fluentbit --url http://fluent-bit:9880 --tag vendetta.alerts --rate 500 --seconds 600
docker compose --env-file .env.smoke --profile test run --rm --no-deps smoke-runner \
  python3 /tests/loadgen.py fluentbit --url http://fluent-bit:9880 --tag vendetta.alerts --rate 5000 --seconds 60 --workers 64
```

While it runs, watch (Prometheus/Grafana "pipeline-health"): `fluentbit_output_retries_total`, `fluentbit_storage_fs_chunks_down`, `fluentbit_input_storage_overlimit`,
`fluentd_output_status_buffer_queue_length`, `fluentd_output_status_retry_count`. After the burst, reconcile counts:

```bash
curl -sk --cacert pki/ca.crt -u "admin:$(cat secrets/opensearch_admin_password)" \
  'https://localhost:9200/vendetta-alerts-*/_count?q=id:loadgen-*'    # must equal the scheduled count printed by loadgen
```

C3/C4 — LLM paths (real GPU host, `--profile llm`):

```bash
docker compose --profile test run --rm --no-deps smoke-runner python3 /tests/loadgen.py triage \
  --url https://llm-gateway:9101 --token-file /run/secrets/llm_gateway_token --cafile /pki/ca.crt --rate 2 --seconds 300
```

Record `llm_gateway_requests_total`, `llm_gateway_queue_depth`, `llm_gateway_failover_total`, GPU-seconds from `cs3-ai-inference-*`
and `nvidia-smi dmon`. Raise `--rate` until `llm_gateway_failover_total{reason="timeout"}` starts to climb: that rate is the
sustainable per-worker capacity; set HAProxy `maxconn` and `GATEWAY_MAX_CONCURRENCY` to it.

C6 — failover under load: while C3 runs, `docker compose stop ollama-1` (or `scripts/enroll-ollama.sh --node ollama-1 --container … --release` to drain), then stop the last worker. Expected: `engine` shifts nemotron → gemma → `Cecur Heuristics`; `/triage` error rate stays 0.

C7 — soak: run C1 at 250 events/s and C3 at 1 req/s for 24 h; at the end run `llm-gateway/tools/verify_audit_chain.py` over the exported `cs3-ai-audit-*` NDJSON.

## 3. Sizing rules to apply to the results

| Resource | Rule of thumb (validate against C1-C7) |
|---|---|
| Fluent Bit | 1 vCPU / 256 MB per 2,000 events/s; disk buffer = 10 min × peak rate × avg record size |
| Fluentd (per node) | 1 vCPU / 1 GB per 1,000 events/s; `total_limit_size` ≥ outage window × rate; run ≥ 2 nodes so one can fail |
| OpenSearch | ≈ 1 KB/event indexed, × replicas; shards 20-40 GB (rollover-40gb); heap ≤ 50% RAM, ≤ 31 GB |
| Ollama (Nemotron 30b) | 24 GB+ VRAM per worker; `OLLAMA_NUM_PARALLEL=4`; one model resident per worker |
| Ollama (Gemma 26b) | 16 GB VRAM; 31b needs 24 GB+; keep forensic workers separate from triage workers during storms |
| Gateway | 0.5 vCPU / 256 MB per replica; the model is the bottleneck, not the gateway |

Record the measured numbers in your change ticket and update `PHASE1-GAP-ANALYSIS.md` §4.3 only after they are measured on production-class hardware.
