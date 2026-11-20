# Fluentd aggregator (active-active pair) — RUNTIME

**Image** build `vendetta-stack/fluentd:${STACK_VERSION}` from context `fluentd/` + `fluentd/Dockerfile` (base `fluent/fluentd:v1.17-debian-1@sha256:d6114e87…7440`, Fluentd 1.17.1; gems pinned by `plugins/Gemfile.lock`: opensearch 1.1.5, prometheus 2.2.0, record-modifier 2.2.0, rewrite-tag-filter 2.4.0; custom `http_bearer` + `otlp_http` outputs in `plugins/`). Runs as `fluent` (uid 999). Run **two** containers from the one image: `fluentd-1`, `fluentd-2` (network aliases must be exactly these; the PKI certs are `/pki/fluentd-1|2.crt`).
**Entrypoint** `/usr/local/bin/cs3-fluentd-entrypoint` · `CMD ["fluentd"]`. Modes: *(none)* run · `--check` (render + `fluentd --dry-run`) · `--help`. Exit 0 ok · non-zero = refused to start (bad env, missing secret, config rejected, live-execd JWT not obtainable).
**What it does** derives `FLUENTD_NODE_ID` (env, else hostname ending `fluentd-1|2`) → waits for secret files (`FLUENTD_WAIT_SEC`, 60) → renders `optional/*.conf` into `/fluentd/etc/enabled.d/` (disabled legs get `*-null.conf` stubs) → creates buffer/dead-letter dirs, prunes old files → `fluentd --dry-run` → `exec fluentd -c /fluentd/etc/${FLUENTD_CONF} -p /fluentd/plugins`.

## Ports
`24224` in_forward (mTLS, client cert required, CA `/pki/ca.crt`; Fluent Bit `upstream.conf` and edge Fluentd connect here) · `24231` Prometheus `/metrics` (scrape target) · `24220` monitor_agent, **bound to 127.0.0.1** (healthcheck; `FLUENTD_MONITOR_BIND=0.0.0.0` to expose).

## Env (default)
- Core: `FLUENTD_NODE_ID` (1|2, required unless hostname matches), `FLUENTD_LOG_LEVEL` (info), `FLUENTD_WORKERS` (1), `FLUENTD_CONF` (fluent.conf; `edge/forwarder.conf` makes the container an edge forwarder), `FLUENTD_OS_BUFFER_LIMIT` (2GB per OpenSearch buffer), `FLUENTD_WAIT_SEC` (60), `FLUENTD_DEADLETTER_RETENTION_DAYS` / `FLUENTD_DRYRUN_RETENTION_DAYS` (14).
- OpenSearch: `OPENSEARCH_URL` (https://opensearch:9200), `OPENSEARCH_USER` (admin).
- LLM triage: `LLM_GATEWAY_URL` (https://llm-gateway:9101; `/triage` is appended), `LLM_TRIAGE_VENDETTA_SEVERITY_REGEX` (`^(medium|high|critical)$`), `LLM_TRIAGE_ERROW_SEVERITY_REGEX` (`^$` = Errow findings are not triaged).
- Feedback: `ERROW_FEEDBACK_URL` (http://errow-feedback:9102/errow-finding), `ERROW_FEEDBACK_SEVERITY_REGEX` (`^critical$`; only for the execd leg, the webhook always gets severity ≥ high), `ERROW_FEEDBACK_LIVE` (false), `VENDETTA_EXECD_AGENT_REGEX` (`^$`; live: `^[0-9]{3,}$`), `ERROW_FEEDBACK_AR_COMMAND` (`!host-isolate.sh`), `VENDETTA_API_URL` (https://vendetta-manager:55000), `VENDETTA_API_USER` (wazuh-wui), `VENDETTA_API_CA_FILE` (/pki/ca.crt), `VENDETTA_JWT_ATTEMPTS`/`VENDETTA_JWT_RETRY_SEC` (6/5), `VENDETTA_JWT_REFRESH_SEC` (600).
- Optional legs: `CS3_AGGREGATOR_LEGS` (empty; comma list of `esoc`,`siem`) with `CS3_ESOC_URL` / `CS3_ESOC_TOKEN_FILE`, `CS3_SIEM_URL` / `CS3_SIEM_TOKEN_FILE`, `CS3_SIEM_AUTH_SCHEME` (Bearer), `CS3_ESOC_{CA,CERT,KEY}_FILE` (/pki/ca.crt, fluentd-N.crt|key), `CS3_SIEM_CA_FILE`; `ERROW_CLOUD_ENABLED` (false) with `ERROW_CLOUD_URL` (https://app.errow.ai), `ERROW_CLOUD_TOKEN_FILE` (/run/secrets/errow_api_token), `ERROW_CLOUD_SEVERITY_REGEX`, `ERROW_CLOUD_RETEST_PATH`. A private CA for these endpoints: `SSL_CERT_FILE=/pki/ca.crt`.
- Edge mode only: `EDGE_AGGREGATOR_1|2` (fluentd-1|2), `EDGE_FORWARD_PORT` (24224), `EDGE_CLIENT_CERT|KEY` (/pki/fluent-bit.crt|key), `EDGE_BUFFER_LIMIT` (2GB).

## Secrets / PKI read (all `ro`)
`/pki/ca.crt`, `/pki/fluentd-<id>.crt|key` (server cert for 24224 and client cert to the gateway/ESOC) · `/run/secrets/opensearch_admin_password` · `llm_gateway_token` (bearer for `/triage`) · `feedback_webhook_token` · `errow_api_token` (cloud leg) · `vendetta_api_password` (live execd only; the entrypoint mints a JWT into `/run/fluentd/vendetta.jwt`) · ESOC/SIEM token files named by `CS3_*_TOKEN_FILE`.

## Volumes
`/var/log/fluentd` **rw persistent, writable by uid 999** (`buffer/` file buffers = durability across restarts, `dead-letter/` error + unrouted JSON lines, `dry-run/` execd dry-run records) · `/fluentd/etc/enabled.d`, `/run/fluentd` and `/tmp` **tmpfs rw** (the Ruby supervisor and serverengine create lock dirs and the worker socket under `/tmp`) · everything else read-only (verified with `--read-only`, `cap_drop: [ALL]`, `no-new-privileges`, `user: 999:999`).

## Healthcheck
Built in: `ruby -rnet/http -e …GET http://127.0.0.1:24220/api/plugins.json` (no curl in the image; interval 15 s, start period 45 s). Compose may reuse it unchanged.

## HA and delivery
No shared state: each node drains its own file buffers (`retry_forever`, `overflow_action block` where durability matters; triage is best-effort `drop_oldest_chunk`). Edge Fluent Bit (`upstream.conf`) balances over both and tolerates one node down; replays are idempotent (stable `_id`; audit uses `create` → 409 on duplicates). Do not enable the Fluent Bit ESOC/SIEM legs **and** `CS3_AGGREGATOR_LEGS` for the same traffic (duplicates).

## Safety invariants (tests/test_routing.sh proves them)
`cs3.ai.ollama` goes only to the ESOC/SIEM label (never OpenSearch, `/triage`, Console, feedback); `cfgaudit.findings` and `cfgaudit.runs` go only to their dedicated OpenSearch outputs/buffers (no SARIF, triage, feedback, cloud, manager, ESOC or SIEM route); `errow.*` never reaches `/triage` unless `LLM_TRIAGE_ERROW_SEVERITY_REGEX` allows it; unknown tags are parked in `dead-letter/unrouted`. The live execd leg (`ERROW_FEEDBACK_LIVE=true` **and** a non-empty `VENDETTA_EXECD_AGENT_REGEX`) posts to `errow-feedback` `POST /approved-action`; that gate requires the same `APPROVALS.md` approval as the Errow leg (one line per fingerprint, `ERROW_FEEDBACK_APPROVAL_THRESHOLD` distinct approvers) and Fluentd therefore holds no manager credential. It needs `properties.errow.vendetta_agent_id` on findings and always refuses agent `000`.

## K8s
Deployment ×2 or StatefulSet (stable `fluentd-N` names, one PVC per pod for `/var/log/fluentd`); readiness/liveness `exec` = the image healthcheck; scrape `:24231/metrics`; `enabled.d` as emptyDir. Benign dry-run warnings: `@timestamp` reserved prefix, `private_key_passphrase` recommended (PKI keys are unencrypted), `<secondary>` with `retry_forever` on the feedback/cloud outputs.

Tests: `tests/validate.sh` (build + dry-run matrix, `--relock` regenerates the lock) · `tests/test_routing.sh` (static invariant + real run against stub sinks, ~4 min) · `fluentd/edge/forwarder.conf` is dry-run by `validate.sh`.
