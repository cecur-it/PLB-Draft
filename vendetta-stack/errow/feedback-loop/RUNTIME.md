# errow-feedback — RUNTIME (CONTRACT §6, §11)

Webhook + scripts that close the Errow ↔ Vendetta loop. **Dry-run unless `ERROW_FEEDBACK_LIVE=true` AND a signed line in
`APPROVALS.md` covers the finding's fingerprint** (format + signer: `APPROVALS.md`, `approval.py`).

> **DEPLOY MUST (compose + Helm): `errow-feedback` must be able to reach `llm-gateway:9101` (same network as the gateway, NetworkPolicy egress
> `errow-feedback → llm-gateway:9101/tcp`) AND mount `/run/secrets/llm_gateway_token` (secret `llm_gateway_token`, ro) + `/pki/ca.crt`.**
> Without them the loop still isolates/tickets/queues (the LLM is advisory), but logs `forensic unavailable: …` and records no proposals.

- **Image**: `vendetta-stack/errow-feedback:${STACK_VERSION:-1.0.0}`; build context `errow/feedback-loop/`, `Dockerfile` (python:3.12-slim-bookworm pin + bash/jq/curl/util-linux; stdlib-only Python, no requirements.txt); `.dockerignore` strips `tests/`.
- **User / rootfs**: uid/gid 10001; works with `read_only: true` + `cap_drop: [ALL]` + `no-new-privileges` when `/var/log/feedback-loop` is a writable volume and `/tmp` is not needed (nothing writes there).
- **Entrypoint**: `python3 /opt/feedback-loop/server.py` (no command needed). Port **9102/tcp** (HTTP; optional TLS via `FEEDBACK_TLS_CERT`/`FEEDBACK_TLS_KEY`/`FEEDBACK_TLS_CA` → mTLS when `FEEDBACK_TLS_CA` file exists).
- **Healthcheck** (container-internal, no curl): `python3 /opt/feedback-loop/server.py --healthcheck` (GET `http://127.0.0.1:$FEEDBACK_PORT/health`). K8s: `httpGet /health :9102` liveness+readiness; `GET /metrics` is Prometheus text (`errow_feedback_*`), both unauthenticated; pods only on `management`/`aggregation` nets.

## HTTP API
`POST /errow-finding` (`Authorization: Bearer <feedback_webhook_token>`, body ≤ `FEEDBACK_MAX_BODY_BYTES`, one SARIF log, one finding, or NDJSON of §15 `findings` records; `?dry_run=1` forces dry-run). Replies `200 {status,exit_code,live,lines[]}`; `400` invalid body; `401`; `411/413`; `429` (all `FEEDBACK_MAX_PARALLEL` slots busy → Fluentd retries); `504` script timeout. Request data reaches `errow-to-vendetta.sh` on stdin only (fixed argv).

`POST /approved-action` (same bearer, one JSON object ≤ `FEEDBACK_MAX_BODY_BYTES`; `?dry_run=1`): the gate for the Fluentd execd leg, and the only caller that talks to `PUT /active-response` besides the script. Body
`{"fingerprint":"<64 hex>","agent_id":"001","command":"!host-isolate.sh","run":"…"}` — `fingerprint` is the SARIF `partialFingerprints.primaryLocationLineHash`, `command`/`run` optional. Gates in order: `ERROW_FEEDBACK_LIVE` → agent regex + manager `000` refusal → signed approval (`approval.py`, same ledger as the script) → manager. Replies `200 {decision:"live"|"dry-run"}`; `400` invalid body; `401`; `403 {decision:"denied",reason}` (no approval / agent refused — unrecoverable, dead-letter it); `503` (unreadable ledger or key — retry); `502/504` (manager fault — retry). `errow_feedback_gate_decisions_total{decision}` counts outcomes.

## Env (name = default → meaning)
| Var | Default | Meaning |
|---|---|---|
| `FEEDBACK_BIND` / `FEEDBACK_PORT` | `0.0.0.0` / `9102` | listen address |
| `FEEDBACK_WEBHOOK_TOKEN_FILE` | `/run/secrets/feedback_webhook_token` | bearer (server exits if unreadable/empty) |
| `FEEDBACK_MAX_BODY_BYTES` / `FEEDBACK_SCRIPT_TIMEOUT` / `FEEDBACK_MAX_PARALLEL` | `1048576` / `120` / `2` | caps |
| `FEEDBACK_DIR` | `/var/log/feedback-loop` | `feedback.log`, `retest-queue.ndjson` (+`-done`/`-dead`), `soar/ERW-*.json`, `state/*.done`, `instructions/` |
| `ERROW_FEEDBACK_LIVE` | `false` | gate 1 of 2. Must be true **on this service** for the Fluentd execd leg too: that leg posts here and gets a `dry-run` reply otherwise |
| `ERROW_FEEDBACK_APPROVALS_FILE` / `ERROW_FEEDBACK_APPROVAL_KEY_FILE` | `/opt/feedback-loop/APPROVALS.md` / `/run/secrets/feedback_approval_key` | gate 2 (key optional secret; absent ⇒ every live action denied) |
| `ERROW_FEEDBACK_APPROVERS` / `ERROW_FEEDBACK_APPROVAL_MAX_DAYS` | empty (any) / `30` | approver allow-list, max expiry horizon |
| `ERROW_FEEDBACK_APPROVAL_KEYS_DIR` / `ERROW_FEEDBACK_APPROVAL_THRESHOLD` | `<approval-dir>/keys` / `2` | per-approver key dir and how many distinct approvers must sign. The threshold clamps to the authorities present, so a shared-key-only deployment runs at 1 (no dual control) — `scripts/bootstrap.sh --check` warns |
| `ERROW_FEEDBACK_MIN_SEVERITY` / `ERROW_FEEDBACK_ISOLATE_MIN_SEVERITY` | `high` / `high` | act / isolate thresholds |
| `ERROW_FEEDBACK_ALLOWED_TARGETS` | `$ERROW_TARGETS` (compose/Helm default `scan-target.vendetta.lab`) | comma list (`*.suffix` ok); isolate and retest only for these hosts. Must stay a subset of `ERROW_ALLOWED_TARGETS` and of the errow-mcp targets: `scripts/check-allowlists.sh` |
| `ERROW_FEEDBACK_POLL_INTERVAL` / `ERROW_FEEDBACK_LOCK_FILE` / `ERROW_FEEDBACK_HEARTBEAT_FILE` | `0` / `<FEEDBACK_DIR>/vendetta-to-errow.lock` / unset | `vendetta-to-errow.sh` scheduler (see Scheduling) |
| `ERROW_FEEDBACK_AR_COMMAND` | `!host-isolate.sh` | Vendetta active-response command (`!` = script name) |
| `ERROW_SOAR_WEBHOOK_URL` / `ERROW_SOAR_WEBHOOK_TOKEN_FILE` | empty / empty | optional ticket webhook; tickets always written to `soar/` |
| `VENDETTA_API_URL` / `VENDETTA_API_USER` / `VENDETTA_API_PASSWORD_FILE` | `https://vendetta-manager:55000` / `wazuh-wui` / `/run/secrets/vendetta_api_password` | JWT via `/security/user/authenticate` (set USER if `VENDETTA_MANAGER_IMAGE` differs). Used by both live legs: `errow-to-vendetta.sh` and `/approved-action` |
| `VENDETTA_EXECD_AGENT_REGEX` | `^$` (nothing) | agent-id allow-list for `/approved-action`; also applied by `errow-to-vendetta.sh` before `act_isolate`. Empty regex or no match ⇒ `403` |
| `ERROW_FEEDBACK_APPROVAL_SCRIPT` / `VENDETTA_API_CA_FILE` / `VENDETTA_API_TIMEOUT` | `<dir>/approval.py` / `/pki/ca.crt` / `10` s | gate internals (verifier path, manager TLS trust, manager timeout). The CA has **no** system-store fallback: pin the manager with `scripts/pin-manager-cert.sh` and point this at `/pki/manager-ca-bundle.crt`, otherwise every live action is refused with `503` (K8s: `/pki/ca.crt` from cert-manager) |
| `OPENSEARCH_URL` / `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD_FILE` | `https://opensearch:9200` / `admin` / `/run/secrets/opensearch_admin_password` | alert polling and `_update` |
| `LLM_GATEWAY_URL` / `LLM_GATEWAY_TOKEN_FILE` / `ERROW_FEEDBACK_TENANT` | `https://llm-gateway:9101` / `/run/secrets/llm_gateway_token` / `default` | gateway: `/forensic` (every run), `--via-llm` (`/triage`, `/mcp/tool_call`) |
| `ERROW_FEEDBACK_FORENSIC` (+`_MIN_SEVERITY`/`_TIMEOUT`/`_BUDGET`) | `true` (+`high`/`60`/`80` s) | advisory `/forensic` step; `--no-forensic` = off, `--offline` = no network at all. Keep `FEEDBACK_SCRIPT_TIMEOUT` > `_BUDGET` |
| `FEEDBACK_PROPOSALS_FILE` / `ERROW_FEEDBACK_ENRICH_MAX_DOCS` | `$FEEDBACK_DIR/proposals.ndjson` / `500` | proposal ledger (same rw volume); cap for `--apply-enrichment` |
| `ERROW_FEEDBACK_TARGET_URL_TEMPLATE` / `ERROW_FEEDBACK_MIN_LEVEL` / `ERROW_FEEDBACK_LOOKBACK` | `http://{host}:8080` / `7` / `24h` | `vendetta-to-errow.sh` targeting and poll window |
| `ERROW_BIN` / `ERROW_WORKDIR` / `ERROW_FEEDBACK_SCAN_TIMEOUT` / `ERROW_FEEDBACK_MAX_ATTEMPTS` | `errow` / `/workspace` / `1800` / `3` | direct mode (see below) |
| `FL_CA_FILE`, `ERROW_FEEDBACK_CLIENT_CERT`/`_KEY` | `/pki/ca.crt`, `/pki/errow-feedback.crt`/`.key` | TLS trust; client cert used when present (mTLS gateway) |

## Mounts
`/run/secrets/{feedback_webhook_token,vendetta_api_password,opensearch_admin_password,llm_gateway_token}` ro (+ optional `feedback_approval_key`, `errow_soar_webhook_token` if used);
`/run/approval` ro (shared approval key + `keys/<approver>.key`); `/pki` ro (`ca.crt`, optional `errow-feedback.crt|key`);
`/opt/feedback-loop/APPROVALS.md` ro (bind/ConfigMap; image ships an empty ledger); `/var/log/feedback-loop` rw volume `feedback-loop`.

`/approved-action` needs `APPROVALS.md`, the approver keys and the manager credential from the same paths (the compose bind mount is
`${ERROW_FEEDBACK_APPROVAL_DIR:-./secrets/approval}:/run/approval:ro`). Compose already passes `vendetta_api_password`; without it the
gate answers `502` and nothing is isolated.

## Scheduling `vendetta-to-errow.sh`
The `errow-feedback` container only runs the webhook; the poller is a second process. `vendetta-to-errow.sh` has a built-in scheduler:
`--interval SECONDS` (or `ERROW_FEEDBACK_POLL_INTERVAL`; integer 10..86400, `0`/unset = one pass and exit, exit 2 otherwise) repeats a pass
after an interruptible sleep. Passes never overlap (`flock -n` on `ERROW_FEEDBACK_LOCK_FILE`; a locked pass is skipped with a warning). A pass that exits 1 is
logged and the loop continues; exit 2 (usage / unreadable `--alert-file`) and 4 (`--live` while the gate is closed) are fatal. SIGTERM/SIGINT finish the current pass
and exit 0 (`docker stop` while sleeping is immediate). `--max-passes N` stops after N passes (tests). `ERROW_FEEDBACK_HEARTBEAT_FILE` is touched at the start of every pass
(the compose healthcheck uses it). Dry-run stays the default; the live gate is evaluated exactly as for a single run.
- Compose, profile `poller`: `errow-feedback-poller` runs `vendetta-to-errow.sh --via-llm --interval $ERROW_FEEDBACK_POLL_INTERVAL` (default 60).
- Ad hoc: `docker compose exec -d errow-feedback /opt/feedback-loop/vendetta-to-errow.sh --via-llm --interval 60` (long-running; stop it by stopping the process or the container).
- K8s: a CronJob (`errow.feedback.poller.enabled`) with `command: ["/opt/feedback-loop/vendetta-to-errow.sh","--via-llm"]` still works (single run per Job, `concurrencyPolicy: Forbid`); or a long-running container with `--interval`.
**`--via-llm` is the production path**: scans go only through gateway `/mcp/tool_call` (policy + `MCP_LIVE`). Direct mode needs the `errow` CLI: run it inside the `errow` container (mount this dir ro at `/opt/feedback-loop`, `ERROW_BIN=/usr/local/bin/errow-entrypoint`). `--alert-file -` (stdin) cannot be combined with `--interval`.

## Allow-list consistency
`ERROW_TARGETS` feeds `ERROW_ALLOWED_TARGETS` and `ERROW_FEEDBACK_ALLOWED_TARGETS` (explicit values win); the errow-mcp yaml (`MCP_TARGETS_FILE`) is separate. `scripts/check-allowlists.sh [--env FILE]` reports hosts present in the feedback list but missing from `ERROW_ALLOWED_TARGETS`, or in either but not covered by the errow-mcp targets (exit 1).

## Forensic proposals (analyst review — never auto-applied)
After the primary actions, `errow-to-vendetta.sh` sends each finding ≥ `high` (sanitized normalized record only: no poc/exploit bodies, secrets redacted) to gateway
`POST /forensic` (advisory; also in dry-run). Results are **appended** to `/var/log/feedback-loop/proposals.ndjson` (deduped) as `{kind, status:"pending_analyst_review",
applied:false, subject, fingerprint, request_id, model, engine, content}`: `detection_rule` (Vendetta/Sigma text), `remediation`; `mitre_enrichment` (`--threat-model-file
FILE`: shipper `threat_models` NDJSON); `vendetta-to-errow.sh --via-llm` adds `errow_check` for SCA failures (draft instruction text, never launched). Console line:
`PROPOSAL: <kind> for <fingerprint> (pending analyst review, not applied)`. Gateway down/timeout/4xx/5xx ⇒ `forensic unavailable: <reason>` and the run continues (same actions, same exit code).
The scripts never write Vendetta rules/decoders and never call an apply API. **Apply is manual**: an analyst reviews the ledger, installs a rule through Vendetta's normal change
process (or starts a scan from the draft), then records the decision outside this file. `--apply-enrichment` (only with `ERROW_FEEDBACK_LIVE=true` + `OPENSEARCH_URL` + password file)
is the single write: a painless `_update_by_query` that only ADDS `mitre.tactic`, `mitre.technique`, `ai.engine` to alerts whose `errow.run` matches; otherwise `DRY-RUN: would add …`.

## K8s
Deployment (1 replica, `Recreate` — queue is a file) + Service `errow-feedback:9102`; PVC for `/var/log/feedback-loop`; NetworkPolicy ingress only from Fluentd; egress only to manager `:55000`, OpenSearch `:9200`, **llm-gateway `:9101`**, DNS. Exit codes of the scripts: 0 ok, 1 action failed, 2 usage, 3 invalid input, 4 `--live` while gate closed.
