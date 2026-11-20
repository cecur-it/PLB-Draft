# errow-shipper — RUNTIME (CONTRACT §11)
Traces: PROMPT §2.3; CONTRACT §2 (paths), §8.4 (stream names), §15 (record shapes). No network listener; no secrets.

**Build** `docker build -t vendetta-stack/errow-shipper:${STACK_VERSION:-1.0.0} errow/shipper` (context = `errow/shipper/`, `Dockerfile`, base pinned by digest, Python 3.12, uid/gid 10001, `TZ=UTC`).
**Run** `ENTRYPOINT python /app/shipper.py` — no args = loop every `SHIPPER_INTERVAL` s (SIGTERM = clean stop). Flags: `--once` (ship everything pending, exit 0), `--healthcheck`, `--selftest` (sanitiser, parser, dirs writable; rc 0/1), `--version`.
**Role** Errow writes atomically *rewritten* JSON (`run.json`, `vulnerabilities.json`, `findings.sarif`, `coverage.json`, `.state/threat_models.json`, `.state/agents.json`), an append-only `errow.log` and SQLite `.state/agents.db` under `./errow_runs/<run>/`. The shipper watches that tree **read-only** and appends 16 NDJSON streams `/var/log/errow/<stream>.ndjson` (`findings runs transcripts threat_models coverage llm_logs mcp_events runtime_events tui_events cloud_events telemetry agent_state report_artifacts proxy tooling viewer`). `mcp_events.ndjson` is only created (errow-mcp and the gateway write it). Every record: `@timestamp stream run source:"errow" doc_id` + §15 fields.

## Env (name = default → meaning)
| Var | Default | Meaning |
|---|---|---|
| `ERROW_RUNS_DIR` | `/workspace/errow_runs` | run tree (mount **ro**; no symlink is followed) |
| `SHIPPER_OUT_DIR` / `SHIPPER_STATE_DIR` | `/var/log/errow` / `/var/lib/errow-shipper` | NDJSON out / `state.json` + `status.json` |
| `SHIPPER_INTERVAL` | `10` | seconds between passes |
| `SHIPPER_MAX_BYTES` / `SHIPPER_KEEP` | `52428800` / `5` | per-stream rotation: rename to `.1`…`.N`, new file, keep N (Fluent Bit follows the inode; copytruncate-safe) |
| `SHIPPER_MAX_LINE_BYTES` | `262144` | larger record → stub `{truncated_record, original_bytes}` |
| `SHIPPER_MAX_FILE_BYTES` | `67108864` | artefact files above this are skipped (logged) |
| `SHIPPER_MAX_LINES_PER_CYCLE` / `SHIPPER_MAX_MESSAGES_PER_CYCLE` | `5000` / `5000` | backlog budgets (a backlog is drained over several passes) |
| `SHIPPER_RETRY_DELAY` | `0.25` | wait before the single re-read of a half-written JSON |
| `SHIPPER_INCLUDE_COVERAGE_RESULTS` | `false` | `true` → SARIF coverage results (`errow-coverage/*`) also go to `findings` |
| `errow_TELEMETRY` / `SHIPPER_TELEMETRY_MIRROR` | `true` / `true` | `telemetry` is written only if neither is `0/false/no/off` (Errow's own opt-out is honoured) |
| `SHIPPER_HEALTH_MAX_AGE` | `120` | healthcheck: `status.json` age ≤ this, last successful pass ≤ 5× this |
| `CS3_MESSAGE_MAX_CHARS` | `8000` | string cap (same algorithm as the edge Lua) |
| `DOCKER_HOST` (+ `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`) | unset | **optional**: `tcp://errow-dind:2376` + client certs → Caido lines (`proxy`) and sandbox lifecycle events (`runtime_events`) for containers labelled `errow-run-id`. Unset/unreachable → source disabled, reason logged once and in `status.json` |

## Mounts
| Path | Mode | Volume |
|---|---|---|
| `/workspace/errow_runs` | **ro** | `errow-runs` (same volume Errow writes `./errow_runs` to) |
| `/var/log/errow` | **rw** | `errow-ndjson` (Fluent Bit mounts it **ro** and tails `*.ndjson`) |
| `/var/lib/errow-shipper` | **rw** | state volume `errow-shipper-state` (`state.json`, `status.json`); losing it only causes a re-ship (deterministic `doc_id`s) |
| `/certs/client` | ro | only with `DOCKER_HOST` (DinD client TLS) |
Image pre-creates both rw dirs (0755) owned by 10001, so empty named volumes inherit that; NDJSON files and `status.json` are 0644 so a Fluent Bit running as any uid can read them (`state.json` stays 0640). Anything else (`/tmp`) is not needed: `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, user `10001:10001`. `errow-runs` must be world-/group-readable by 10001.

## Healthcheck and Fluent Bit
`HEALTHCHECK CMD ["python","/app/shipper.py","--healthcheck"]` (stdlib only, no curl; rc 0 = fresh). K8s: **exec probe** with the same command (no port). 1 replica; `errow-runs` must be RWX or co-located (same pod as Errow / same node).
`/var/lib/errow-shipper/status.json` (single-line JSON, atomic rewrite each pass) is for Fluent Bit's `exec` input (`cat` it; needs a Fluent Bit image with a shell) or its `tail` input: `{component, ts, ts_epoch, last_ok(_epoch), lag_seconds, cycles, errors, runs, streams{<s>{records_total,bytes_total,last_emit,file_bytes}}, sources{docker,runs_dir}, skipped{}, telemetry_mirror}`. Mount the state volume ro into Fluent Bit (K8s: emptyDir or PVC shared with the sidecar).
Logs: JSON lines on stdout (`ts level component msg …`), secrets redacted.

## Guarantees and behaviour
- **Idempotent**: content hashes/cursors in `state.json` (atomic write). Unchanged file → nothing; changed file → only changed records (findings by `doc_id`, threat models per entry, new `agents.db` rows by id, `errow.log` by byte offset).
- **Crash-safe**: write-ahead marker before appending; on start a torn append is truncated back and re-emitted (or committed if it was complete). Half-written/replaced JSON is retried once, else skipped (counted in `status.json.skipped`) and picked up next pass. Corrupt `state.json` → renamed `.corrupt`, fresh state.
- **No payloads**: `poc_script_code` never emitted; `vulnerabilities.json` and `vulnerabilities/*.md` are only hashed (`report_artifacts`, kinds pdf|sarif|json|md); fenced code elided; tool-call `code/script/payload/…` args replaced by `[omitted:N chars]`; system prompts and `reasoning` items never shipped. Secrets redacted, strings truncated like the edge Lua.
- `agents.db` opened `file:…?mode=ro` (fallback `&immutable=1`), `PRAGMA query_only`; never written.

## Limitations
`errow.log` times are read as UTC (run Errow with `TZ=UTC`). `telemetry` is **derived** from run artefacts (`scan_started`, `finding_reported`, `scan_ended`), not captured from PostHog. A rolled-back batch or an in-place truncated `errow.log` can re-emit records (same `doc_id`; dedupe downstream). A sandbox removed (AutoRemove) between two Docker polls takes unread Caido lines with it. State is not pruned for deleted runs.
