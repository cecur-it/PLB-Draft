# Fluent Bit edge collector — RUNTIME

**Image** `${FLUENT_BIT_IMAGE}` = `fluent/fluent-bit:3.2.10-debug@sha256:ddc7932e…3cda` (CONTRACT §1; the debug image is required: bash, gzip, stat for `entrypoint.sh`). No build; mount this directory read-only at `/etc/fluent-bit`.
**Entrypoint** `/etc/fluent-bit/entrypoint.sh` (compose `entrypoint:`; `command` empty). Modes: *(none)* run · `--validate` (`fluent-bit -D`) · `--render-only <dir>` (K8s initContainer) · `--healthcheck` · `--help`. Exit 0 ok · 2 usage · 3 bad env · 4 config rejected.
**What it does** reads `*_FILE` secrets into env → exports defaults → renders `legs/*.conf` (+ `inputs/*.conf`) into `enabled.d/` (always `00-noop.conf`) → `fluent-bit -D` → size-rotates `cs3-ai-ollama.ndjson` → `exec fluent-bit`.

## Ports
`2020` HTTP: `/api/v1/health` (probe), `/api/v2/metrics/prometheus` · `9880` `http` input (gateway events `POST /cs3.ai.inference|tool_call|enrichment`, test hook `POST /host.journal`, `/vendetta.alerts`; **`Content-Type: application/json` required**, answers 201) · `24224` `forward` in (agents/edge nodes; optional TLS) · `${ERROW_TUI_PORT}` (24225) Errow TUI forward in · `${FLB_SYSLOG_PORT}` (5140 udp+tcp, only if `FLB_SYSLOG_ENABLED=true`).

## Env (default)
- Legs: `CS3_CONSOLE_ENABLED|CS3_ESOC_ENABLED|CS3_SIEM_ENABLED` (false). Console: `CS3_HOST` (required), `CS3_PORT` (443), `CS3_TLS` (On), `CS3_CA_FILE` (/pki/ca.crt). ESOC: `CS3_ESOC_HOST` (required), `CS3_ESOC_PORT` (4317), `CS3_ESOC_GRPC` (On), `CS3_ESOC_TLS` (On), `CS3_ESOC_{CA,CERT,KEY}_FILE` (/pki/ca.crt, fluent-bit.crt, fluent-bit.key), `CS3_HEALTH_SCRAPE_SEC` (30). SIEM: `CS3_SIEM_HOST` (required), `CS3_SIEM_PORT` (443), `CS3_SIEM_URI` (/v1/events), `CS3_SIEM_TLS` (On), `CS3_SIEM_CA_FILE`, `CS3_SIEM_FORMAT` (json_lines), `CS3_SIEM_AUTH_SCHEME` (Bearer).
- Secrets (files, mounted `ro`): `CS3_INGEST_KEY_FILE` (required with Console leg) → `X-API-Key`; `CS3_SIEM_TOKEN_FILE` (required with SIEM leg). Plain `CS3_INGEST_KEY`/`CS3_SIEM_TOKEN` env only for tests.
- Pipeline: `CS3_EPS_LIMIT` (500; leaky bucket on noisy tags), `CS3_MESSAGE_MAX_CHARS` (8000), `CS3_HOSTNAME`, `CS3_AGENT_ID`, `FLB_LOG_LEVEL` (info), `FLB_FORWARD_STORAGE_LIMIT` (2G), `FLB_SAFETY_MAX_BYTES` (67108864) / `FLB_SAFETY_KEEP` (7) / `FLB_ROTATE_INTERVAL` (60 s) for the ollama safety file.
- Forward in 24224: `FLB_FORWARD_TLS` (off), `FLB_FORWARD_TLS_VERIFY` (on), `FLB_FORWARD_TLS_{CA,CRT,KEY}_FILE` (/pki/ca.crt, fluent-bit.crt, fluent-bit.key).
- Inputs: `ERROW_TUI_PORT` (24225), `ERROW_SHIPPER_STATUS_FILE` (/var/lib/errow-shipper/status.json), `ERROW_REPORTS_DIR` (/var/log/errow/reports; tails rendered only if the dir exists), `CAIDO_LOG_GLOB` (/var/log/errow/caido/*.log; same rule), `CFGAUDIT_ENABLED` (false) / `CFGAUDIT_REPORTS_DIR` (/var/log/cfgaudit; opt-in finding/run tails, directory must be readable), `FLB_JOURNAL_PATH` (auto: /var/log/journal or /run/log/journal), `CS3_JOURNAL_ALL` (false = only ollama units), `CS3_HOST_LOGS` (true: /var/log/auth.log|secure, /var/log/audit/audit.log when present), `FLB_SYSLOG_ENABLED` (false).

## PKI / volumes
`/pki:ro` — `ca.crt`; `fluent-bit.crt|key` (client cert to Fluentd `upstream.conf`, also ESOC mTLS and the optional forward-in server cert). Upstream = `fluentd-1:24224`, `fluentd-2:24224` (mTLS, round-robin, one node down is tolerated).
`/etc/fluent-bit:ro` config · **`/etc/fluent-bit/enabled.d` tmpfs/emptyDir rw** (rendered legs; required with `read_only`) · `/var/log/fluent-bit` **rw persistent** (`storage/` chunks, `db/` tail offsets, `cs3-ai-ollama.ndjson` safety file) · `/var/log/errow:ro` (shipper NDJSON, `cli.log`, `proxy.ndjson`, …) · `/var/log/cfgaudit:ro` (optional adapter-generated findings/run NDJSON only, never raw configs) · `/var/vendetta/logs:ro` (`alerts/alerts.json`) · `/var/lib/errow-shipper:ro` (`status.json`) · `/var/log/journal:ro` or `/run/log/journal:ro` (optional).

## Routing summary (CONTRACT §8.3)
Console: `host.*|v1_logs|vendetta.{alerts,fim,vulnerability,sca}` · ESOC OTLP + SIEM NDJSON: `host.*|v1_logs|cs3.ai.*` · Fluentd forward: `vendetta.*|errow.*|cfgaudit.{findings,runs}|cs3.ai.{inference,tool_call,enrichment}|cs3.sp.*` · safety file: `cs3.ai.ollama` (never Console, never Fluentd/OpenSearch). `errow.tui_events` goes only to Fluentd. Cfgaudit streams go only to Fluentd and use their own storage-only routes; see `cfgaudit/README.md`. Hash-chained `cs3.ai.inference|tool_call` are never rewritten (nulls must survive).

## Healthcheck / hardening
`["CMD","/etc/fluent-bit/entrypoint.sh","--healthcheck"]` (bash `/dev/tcp`, no curl needed). Verified: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, `user: 10001:10001` with tmpfs `uid=10001` on `enabled.d`, `/var/log/fluent-bit`, `/var/log/errow`. Reading the journal / root-owned logs needs a user/group that can read them (`group_add` systemd-journal) or `user: 0`.

## K8s
Probes `httpGet /api/v1/health :2020` (liveness+readiness). Distroless images lack bash: keep the debug image, or run `entrypoint.sh --render-only /rendered` in an initContainer (emptyDir mounted at `/etc/fluent-bit/enabled.d` in the main container). Expose 9880 only inside the namespace. Scrape annotation `/api/v2/metrics/prometheus`. Hot reload: `POST :2020/api/v2/reload` after changing mounted config. Cfgaudit collection is Compose/manual only in the validation phase; the Helm/Kustomize manifests do not mount or enable it.

## Limits of 3.2.10 (documented, not faked)
`exec` and `winlog` inputs are not compiled in (status file is tailed instead; Windows hosts use the CS3 Windows agent template) · `tls.min_version` is rejected by the http/opentelemetry outputs (enforce TLS 1.3 at the server) · the forward input checks the server side of TLS only: **client certificates are not enforced** on `:24224` here (use network policy; mTLS is enforced by Fluentd `in_forward`) · Console route caps a batch at `CS3_INGEST_MAX_BATCH` (1000) and body at `CS3_JSON_LIMIT` (2mb): raise both if a 413 shows in the `console_ingest` retries · `-D` is shallow; use `tests/validate.sh`.

Tests: `tests/validate.sh` (all legs on/off, optional inputs, negative envs, real boots) · `tests/test_legs.sh` (behavioural leg isolation, ~75 s) · `luajit tests/test_stream_processors.lua`.
