# Fluent telemetry fabric: edge to core

How CS3 uses Fluent to move logs, metrics and traces from every sensor to the console, the central ESOC/XDR core and a customer SIEM, and how that telemetry feeds the AI/agentic tier (Ollama: Nemotron-3-Nano for triage, Gemma-4 for forensics).

> **Tooling decision.** The two plugins that inspired this design, [`fluent-plugin-opentelemetry`](https://github.com/fluent-plugins-nursery/fluent-plugin-opentelemetry) and [`fluent-plugin-out-http`](https://github.com/fluent-plugins-nursery/fluent-plugin-out-http), are **Fluentd** (Ruby) plugins. CS3 sensors already run **Fluent Bit** (native, small, no Ruby runtime), and Fluent Bit implements every idea below natively. So the **edge tier is Fluent Bit** and the nursery plugins are used only in an **optional Fluentd aggregation tier** ([section 9](#9-optional-fluentd-aggregation-tier)).

Everything here was validated against Fluent Bit v5.1.5 and Fluentd 1.19 (see [section 12](#12-validation-runbook)). Fluent Bit **4.0 or newer** is required: OTLP/gRPC egress arrived in 3.2, but the `tls.min_version TLSv1.3` pin used by the gateway fragments arrived in 4.0. (Optional CRL checks via `tls.crl_file` need 5.1.3+; the fragments do not use it.)

## 1. Tiers and profiles

| Tier | Component | Install | Role |
| --- | --- | --- | --- |
| Edge (default) | Fluent Bit | `install-forwarder.sh` | Tails journald, `auth.log`, `audit.log`; ships to the console. |
| Gateway | Fluent Bit + fragments | `install-forwarder.sh --profile gateway ...` | Adds an OTLP listener, normalisation, heartbeat, self-metrics and OTLP/gRPC (ESOC) and HTTPS (SIEM) egress. |
| AI tier | Gateway + `--ai-tier` | same | Nodes running Ollama; their logs are tagged `cs3.ai.*`. |
| Aggregator (optional) | Fluentd + nursery plugins | `templates/fluentd-aggregator.conf` | Regional relay with mTLS in and fan-out to the XDR core and a SIEM. |

The edge profile is unchanged by default: no listener, no extra egress, same <25 MB RSS budget (`MemoryMax=100M`). `--profile gateway` is opt-in and raises `MemoryMax` to 256M.

## 2. Architecture

```
 CS3 sensor node (--profile gateway)
+-------------------------------------------------------------------------+
| CS3 EDR engine ---OTLP gRPC/HTTP (:4318)--+                              |
| Network probe  ---OTLP gRPC/HTTP ---------+--> Fluent Bit                |
| journald / auth.log / audit.log (host.*) -+     * Lua normalise+redact   |
| heartbeat + Fluent Bit self-metrics ------+     * filesystem buffer      |
+--------------------------------------------------|----------------------+
        | HTTPS + X-API-Key (+mTLS)   | OTLP/gRPC, mTLS, TLS 1.3, gzip | HTTPS NDJSON, Bearer, gzip
        v                             v                               v (optional egress proxy)
  CS3 console                   Central ESOC / XDR core           Customer SIEM / analytics
  /api/cecur/logs/ingest        (or the Fluentd aggregator)       (Splunk / Elastic / Datadog / ...)
        |
        |  events flagged anomalous at ingest
        v
  analyst / UI -> POST /api/cecur/ai/analyze-log -> inference gateway -> Ollama
                                       triage: nemotron-3-nano:30b   forensic: gemma4:26b
```

Each leg has its own disk buffer and retry loop, so an outage on one destination never blocks another and never stalls local detection.

## 3. Concept map: reference plugins to CS3

| Reference concept (Fluentd nursery) | CS3 implementation (Fluent Bit) | Where |
| --- | --- | --- |
| OTLP listeners on gRPC 4317 and HTTP 4318 | One `opentelemetry` input serves **both** gRPC and HTTP on one port (default `4318`, `--otlp-port`) | `gateway.d/10-otlp-input*.conf` |
| `tag cs3.sensor.${type}` splits logs, metrics and traces | The input tags records `v1_logs`, `v1_metrics`, `v1_traces` (same for gRPC and HTTP) | built in |
| Tail `/var/log/cs3/*.log` into the pipeline | Existing `host.*` tail/journald inputs, plus the optional [`70-app-logs.conf.example`](../agents/templates/gateway.d/70-app-logs.conf.example) | `templates/` |
| `<transport tls>`, `client_cert_auth`, `min_version TLS1_3` | `tls.verify_client_cert On`, `tls.min_version TLSv1.3` | `10-otlp-input-mtls.conf`, `40-esoc-otlp.conf` |
| `${SIEM_TOKEN}` in headers | `Header Authorization ${CS3_SIEM_AUTH_SCHEME} ${CS3_SIEM_TOKEN}` from `/etc/cecur/forwarder.env` (0600) | `50-siem-http.conf` |
| `compress gzip` / `compress_request true` | `compress gzip` / `Compress gzip` | all egress fragments |
| `bulk_request true` (NDJSON) | `Format json_lines` (default `CS3_SIEM_FORMAT`) | `50-siem-http.conf` |
| `chunk_limit_size 2m..4m` (413 prevention) | Fluent Bit sizes chunks itself; console limits are in [section 5](#5-network-optimisation) | |
| `buffered true`, `@type file` buffer | `storage.type filesystem` on every input | `install-forwarder.sh` templates |
| `retry_forever true`, `retry_max_interval 30s`, `recoverable_status_codes` | `Retry_Limit False` (unlimited retries with exponential backoff) | egress fragments |
| `opentelemetry_metrics` health input | `fluentbit_metrics` input (`cs3.health.metrics`) plus the `host.heartbeat` event | `30-heartbeat.conf`, `40-esoc-otlp.conf` |
| Multi-destination routing | Per-output `Match` / `Match_Regex` | `40-`, `50-`, console output |

## 4. Tags and routing

| Tag | Source | Console | ESOC (OTLP) | SIEM (HTTP) |
| --- | --- | --- | --- | --- |
| `host.journal`, `host.auth`, `host.audit` | journald and log tails | yes | yes | yes |
| `host.heartbeat` | `30-heartbeat.conf` | yes | yes | yes |
| `v1_logs` | OTLP logs, after normalisation | yes | yes | yes |
| `v1_metrics`, `v1_traces` | OTLP metrics and traces | no | yes | no |
| `cs3.health.metrics` | Fluent Bit self-metrics | no | yes | no |
| `cs3.ai.ollama` | Ollama journal lines (`--ai-tier`) | no | yes | yes |

Why: the console ingest contract is **logs only** (`{ source, message, agentName, severity?, fields }`), and Fluent Bit's `http` output only delivers logs. Metrics and traces therefore go to the OTLP-native ESOC, which understands them. The console output is selected with `Match_Regex ^(host\..*|v1_logs)$`, the SIEM with `^(host\..*|v1_logs|cs3\.ai\..*)$`, and the ESOC takes `*`.

### What OTLP emitters should send

Send OTLP **logs** whose body is a string (becomes `message`) or a key/value map with `message`, `source`, `severity` and any extra keys (extras are moved under `fields`). The normaliser ([`cs3-otlp-normalize.lua`](../agents/templates/gateway.d/cs3-otlp-normalize.lua)):

- strips control characters and truncates to `CS3_MESSAGE_MAX_CHARS` (`...[truncated]`, UTF-8 safe);
- redacts `Bearer` tokens and `password|token|secret|api_key|authorization` pairs;
- maps `severity` to the console enum (`info|low|medium|high|critical`);
- drops blank messages so one empty event cannot turn a whole batch into a `400`;
- stamps `source` (`cs3-otlp` by default) and `agentName` (`CS3_HOSTNAME`).

## 5. Network optimisation

| Capability | Mechanism | Notes |
| --- | --- | --- |
| Compression | `Compress gzip` on console and SIEM, `compress gzip` on OTLP/gRPC | Security text compresses well; expect large savings on narrowband links. Measure your own ratio. |
| Batching | Fluent Bit flushes chunks as one request per flush; SIEM `Format json_lines` is NDJSON | The console accepts a JSON array (`Format json`), not NDJSON. |
| Payload limits | Input `logs_max_size 8M`; console `CS3_JSON_LIMIT` (2mb) and `CS3_INGEST_MAX_BATCH` (1000 events) | See [ingestion-tuning.md](ingestion-tuning.md#console-side-limits). Keep `Flush` low on bursty sensors. |
| Proxy traversal | `--siem-proxy URL` enables `Proxy` on the SIEM output | Console and ESOC legs go direct; permit them in the enclave firewall ([firewall/](firewall/README.md)). |
| Connection reuse | `net.keepalive on`, `net.connect_timeout 10`, `Workers 2` | |

## 6. Zero-trust transport and secrets

- **mTLS in.** A listener bound off-loopback **must** use `10-otlp-input-mtls.conf` (`tls.verify_client_cert On`, `tls.min_version TLSv1.3`); the installer refuses a non-loopback `--otlp-listen` without `--otlp-cert/--otlp-key/--otlp-client-ca`. Verified: a missing client certificate, plaintext and TLS 1.2 are all rejected on both HTTP and gRPC. Only agents holding a certificate from the CA you pass can inject events.
- **mTLS out.** The ESOC leg always uses a client certificate and `tls.min_version TLSv1.3`. The SIEM leg verifies the server (`tls.verify On`, `TLSv1.2` minimum, since customer gateways vary), and `--siem-url` must be `https`.
- **Secrets.** Credentials live only in `/etc/cecur/forwarder.env` (0600, systemd `EnvironmentFile`). The installer reads `CS3_ENROLL_TOKEN` and `CS3_SIEM_TOKEN` from the environment or from `--token-file` / `--siem-token-file`, **never argv**, and rejects tokens with unexpected characters. No secret is baked into templates, images or config maps.
- **Least privilege.** The gateway systemd drop-in only raises `MemoryMax` (100M to 256M) for the listener and Lua; the unit's other hardening is unchanged.

## 7. Buffering and backpressure

- Every input uses `storage.type filesystem`, with `storage.path /var/lib/cecur-forwarder/buffer` and checksums on. The sensor writes to the buffer and is never blocked by egress.
- Every output uses `Retry_Limit False` with exponential backoff and a `storage.total_limit_size` (console and ESOC 2G, SIEM 1G). Delivery is **at-least-once**; make downstream idempotent where it matters.
- Verified outage behaviour: with the ESOC stopped the gateway kept ingesting and retrying; after it returned, buffered telemetry flushed with no crash. The same was verified for the Fluentd aggregator.
- The watchdog warns when the buffer exceeds `CS3_WATCHDOG_BUFFER_WARN_MB` (3072) and, on a gateway, when the ESOC TCP endpoint is unreachable. Reachability is reported, not "fixed" by restarts.

## 8. Anti-tamper observability

| Signal | Produced by | A control plane should alert on |
| --- | --- | --- |
| `host.heartbeat` (every `CS3_HEARTBEAT_SEC`, default 60) | `30-heartbeat.conf` | No heartbeat for several intervals: sensor killed, throttled or cut off. Each delivery refreshes the agent's `lastKeepAlive`. |
| `cs3.health.metrics` (every `CS3_HEALTH_SCRAPE_SEC`, default 30) | `fluentbit_metrics` to the ESOC | Cadence loss (suppression); rising retries or dropped records; storage use near `storage.total_limit_size` (capacity and egress exhaustion). |
| Local Prometheus endpoint | Fluent Bit HTTP server `127.0.0.1:2020` | `GET /api/v2/metrics/prometheus` for a node-local scraper or `node_exporter` textfile job; `/api/v1/health` drives the watchdog. |
| Certificate expiry | watchdog | Warns when any CS3 certificate (including OTLP and ESOC files) expires within `CS3_WATCHDOG_CERT_WARN_DAYS` (14). |

Self-metrics are shipped over the same authenticated channel as detections, so suppressing them is itself a detection.

## 9. Optional Fluentd aggregation tier

[`templates/fluentd-aggregator.conf`](../agents/templates/fluentd-aggregator.conf) is a regional relay built on the nursery plugins: OTLP/gRPC in with mutual TLS, and fan-out to the XDR core (OTLP/gRPC mTLS) and a customer SIEM (OTLP/JSON over HTTPS, bearer auth). Install with `gem install fluent-plugin-opentelemetry fluent-plugin-out-http grpc` (the `grpc` gem is **not** pulled in automatically; Ruby >= 3.2 for `out-http` 1.3.x).

Differences from the reference sample that matter in production:

| Reference sample | Problem | In the shipped config |
| --- | --- | --- |
| `<match cs3.telemetry.engine_logs>` after `<match cs3.telemetry.**>` | Fluentd uses the first match, so the second route never fires. | Distinct tags plus `copy` and `<label>` blocks. |
| `authentication token` | Not a valid value (`none\|basic\|jwt\|bearer`). | `authentication bearer` with `token`. |
| `${CUSTOMER_SIEM_TOKEN}` in `custom_headers` | Fluentd does not expand `${VAR}` in config. | `"#{ENV.fetch('NAME')}"`, which also fails fast when a variable is missing. |
| `endpoint_url` set but no `buffered true` | `out_http` ignores `<buffer>` unless `buffered true`. | `buffered true`. |
| `queue_limit_length` | Deprecated. | `total_limit_size`. |
| Default `chunk_limit_size` of 8M | Can exceed gateway limits (HTTP 413). | 4m (XDR) and 2m (SIEM). |
| Raw tailed JSON to the OTLP output | The OTLP output accepts only OTLP-form events. | Normalise at the edge (Fluent Bit Lua); this tier is a relay. |
| `bind 0.0.0.0` with no client auth | Unauthenticated injection. | `client_cert_auth true` with `ca_path`; default bind is loopback. |
| `min_version TLS1_3` in `<transport tls>` | Ignored for gRPC listeners (only `ca_path`, `cert_path`, `private_key_path`, `private_key_passphrase`, `client_cert_auth` apply). | Enforce TLS 1.3 at the Fluent Bit gateways or a fronting proxy. |

Fluentd logs a harmless warning that `private_key_passphrase` is recommended; set it if your keys are encrypted. The SIEM leg forwards the verbatim OTLP JSON, so the endpoint must speak OTLP/HTTP; for flat-event SIEMs (Splunk HEC, Elastic) ship from the Fluent Bit gateway instead.

## 10. AI and agentic leverage

Telemetry reaches the AI tier on a single, deliberately narrow path.

1. **Ingest and flag.** `POST /api/cecur/logs/ingest` accepts events with a string `message` and `source`. Messages containing `failed`, `error` or `tamper` are flagged anomalous (`isAnomaly`, `anomalyScore`) and stored (and indexed when OpenSearch is enabled).
2. **Triage.** An analyst or the UI submits a flagged event to `POST /api/cecur/ai/analyze-log`, which calls `analyzeLogAnomalyWithAI` in `server/ai/cecurAI.ts` on the **triage** model (`OLLAMA_PRIMARY_MODEL`, default `nemotron-3-nano:30b`). Deeper forensic work uses the **forensic** model (`OLLAMA_FALLBACK_MODEL`, default `gemma4:26b`). Both are selected by `server/inference/gateway.ts` (override with `INFERENCE_MODEL_TRIAGE` / `INFERENCE_MODEL_FORENSIC`).
3. **Guardrails.** Log text is **untrusted data**: `server/inference/guardrails.ts` caps it (`sanitizeUntrusted`, 8000 chars), scans for prompt-injection patterns, frames it as `<untrusted_data>` and validates the model's JSON output against a schema. Remediation remains analyst-in-the-loop.

How the Fluent fabric supports that:

- **Defence in depth.** OTLP is a new, attacker-influenced input. The edge normaliser applies the same truncation (`CS3_MESSAGE_MAX_CHARS`, default 8000 to match the server cap), control-character stripping and redaction before the event travels anywhere. The server stays authoritative.
- **Clean contract.** Structured fields (`source`, `severity`, `fields`) arrive ready for the console, so the model sees consistent inputs rather than raw transport formats.
- **No feedback loop.** On `--ai-tier` nodes, `ollama.service` journal lines are re-tagged `cs3.ai.ollama`. They still reach the ESOC and SIEM but are not sent to the console, so an inference-server `error` line is never flagged and offered to the same model server for triage. GPU-second metering is separate (`server/inference/meter.ts`, `INFERENCE_*`).
- **Quiet heartbeat.** The heartbeat text avoids the anomaly keywords, so healthy sensors never create triage candidates.
- **Agentic ESOC control plane.** Metrics on `cs3.health.metrics` plus the heartbeat give an agent the signals in [section 8](#8-anti-tamper-observability) (suppression, egress exhaustion, capacity) without any custom transport code.

## 11. Install and configure

Prerequisites: Fluent Bit 4.0+, root, and certificates issued by your PKI. Paths for `--*-cert/--*-key/--*-ca` are on the host being installed. Full variable list: [`forwarder.env.example`](../agents/templates/forwarder.env.example).

```bash
# Edge profile: unchanged behaviour
CS3_ENROLL_TOKEN=... ./install-forwarder.sh --console-url https://cs3.example.internal --agent-id <agentId>

# Gateway: loopback OTLP only (plaintext is acceptable on 127.0.0.1), SIEM over an egress proxy
CS3_SIEM_TOKEN=... ./install-forwarder.sh --console-url https://cs3.example.internal --agent-id <agentId> \
  --profile gateway \
  --siem-url https://siem.example.internal/v1/events --siem-proxy http://proxy.example.internal:3128

# Gateway: network listener (mTLS mandatory), ESOC + SIEM egress, AI tier
CS3_SIEM_TOKEN=... ./install-forwarder.sh --console-url https://cs3.example.internal --agent-id <agentId> \
  --profile gateway --otlp-listen 0.0.0.0 --otlp-port 4318 \
  --otlp-cert server.crt --otlp-key server.key --otlp-client-ca sensors-ca.pem \
  --esoc-host esoc-gateway.example.internal --esoc-cert client.crt --esoc-key client.key --esoc-ca esoc-ca.pem \
  --siem-url https://siem.example.internal/v1/events --siem-ca siem-ca.pem --ai-tier
```

Add `--dry-run` to preview. Re-running the installer **re-applies the profile from its flags**: repeat the gateway flags on every run, or the host reverts to the edge profile. The one-time enrollment token is not needed on re-runs, and an existing SIEM credential in `forwarder.env` is kept. The three tuning knobs (`CS3_HEARTBEAT_SEC`, `CS3_HEALTH_SCRAPE_SEC`, `CS3_MESSAGE_MAX_CHARS`) are preserved across re-runs.

Fleet rollout: set `cs3_forwarder_profile: gateway` and the `cs3_otlp_*`, `cs3_esoc_*`, `cs3_siem_*`, `cs3_ai_tier` and `cs3_siem_token` (Vault) variables for `deploy-forwarders.yml` ([agent-fleet-management.md](agent-fleet-management.md)).

Installer behaviour worth knowing:

- Files the installer owns are `/etc/cecur/fluent-bit.d/{10,20,30,40,50,60}-*.conf`, `cs3-otlp-normalize.lua` and the drop-in `cecur-forwarder.service.d/10-gateway.conf`. Any other `*.conf` you add to `fluent-bit.d/` (for example the app-log example) is kept and loaded while the gateway profile is active.
- Validation rejects gateway-only flags under the edge profile, an off-loopback listener without mTLS, an ESOC without a client certificate and key, a non-`https` SIEM URL, a missing SIEM credential and invalid ports.

Sensors then point their OpenTelemetry SDK or exporter at the node. One port serves both protocols: `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318` with `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` or `grpc`.

## 12. Validation runbook

1. **Static.** `shellcheck deployment/agents/*.sh`, `node --test scripts/*.test.mjs` (from `cecur-it-cs3-v1/`) and `ansible-playbook --syntax-check deployment/ansible/playbooks/deploy-forwarders.yml`.
2. **Config.** Render a gateway config and run `fluent-bit --dry-run -c /etc/cecur/fluent-bit.conf` (the `forwarder.env` variables must be exported, because Fluent Bit has no `${VAR:-default}`). For Fluentd: `fluentd --dry-run -c fluentd-aggregator.conf`.
3. **Functional.** Send a test OTLP log with the OpenTelemetry SDK to `localhost:4318`, then confirm it reaches the console (`POST /api/cecur/logs/ingest` returns 201), the ESOC and the SIEM. Look for `message`, `source`, `agentName`, and redacted secrets.
4. **mTLS.** From an off-host client, confirm a connection with no client certificate, and one using TLS 1.2, both fail.
5. **Outage.** Stop the ESOC (or block it), send events, confirm `/var/lib/cecur-forwarder/buffer` grows and the sensor is unaffected, then restore the ESOC and confirm delivery.
6. **Tamper drill.** Stop the forwarder and confirm the heartbeat gap alert fires within your threshold.

## 13. Troubleshooting and limits

| Symptom | Likely cause |
| --- | --- |
| `no match ... configuration file contains errors` | The `@INCLUDE` glob matches nothing. The installer un-comments it only for the gateway profile and installs the fragments in the same run; do not un-comment it by hand on an edge host. |
| Installer: "off-loopback OTLP requires mTLS" | Add `--otlp-cert`, `--otlp-key`, `--otlp-client-ca`, or bind `127.0.0.1`. |
| Metrics/traces missing in the console | By design: the console is logs-only. Use the ESOC leg. |
| Service restarts with OOM | Gateway `MemoryMax` is 256M; raise it in the drop-in for large OTLP bursts. |
| HTTP 413 from the console | A flush exceeded `CS3_INGEST_MAX_BATCH` (1000) or `CS3_JSON_LIMIT`; lower `Flush` or raise the limits ([ingestion-tuning.md](ingestion-tuning.md)). |

Known limits and follow-ups:

- The gateway profile is **Linux only**; a Windows gateway template and installer path are a follow-up.
- Parsers: `[SERVICE] Parsers_File` is the absolute path `/etc/cecur/parsers.conf`, installed from [`templates/parsers.conf`](../agents/templates/parsers.conf) on every run. (Previously it was the relative `parsers.conf`, which resolves under `/etc/cecur/` where nothing installed it, so Fluent Bit aborted at startup with `could not configure service property 'parsers_file'`.) The file is installer-owned and is overwritten on re-run; to add a parser, edit the template in your deployment bundle, because Fluent Bit rejects `[PARSER]` sections inside `fluent-bit.d` fragments. Only the optional JSON-lines tail example uses a parser (`json`).
- Delivery is at-least-once, so duplicates are possible after retries.

See also: [mtls-certificate-pinning.md](mtls-certificate-pinning.md), [certificate-rotation.md](certificate-rotation.md), [monitoring.md](monitoring.md), [ingestion-tuning.md](ingestion-tuning.md), [agents/README.md](../agents/README.md).
