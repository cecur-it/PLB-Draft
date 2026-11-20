# Errow in the vendetta-stack

Errow (formerly Strix — see [Naming](#naming-strix--errow)) is the stack's **offensive-validation platform**: an autonomous agent
that scans a target inside throw-away Kali sandboxes, reasons with the **sovereign Ollama tier through the LLM gateway** (no cloud
LLM in `onprem`/`airgap`), and writes SARIF/JSON run artifacts. Vendetta (the XDR/SIEM) consumes those findings, and Vendetta alerts
can in turn ask Errow to re-test. Every offensive action is dry-run by default and gated twice (policy + signed approval).

Spec: `CONTRACT.md` §2 (ports), §4 (schemas), §6 (feedback loop), §8 (Errow addenda), §11 (runtime files). Operator reference: [`RUNTIME.md`](RUNTIME.md).

## Architecture

```
 (1) scan      operator ──exec──▶ errow ──DOCKER_HOST (TLS)──▶ errow-dind ──▶ sandboxes (Kali, Caido :48080, nmap, nuclei, gobuster, bbot)
                                 │                                  ▲
 (2) LLM                         └─ bearer ─▶ llm-gateway :9101 ─▶ ollama-lb ─mTLS─▶ Ollama workers   (no cloud LLM)
                                                  ▲   │ /triage, /mcp/tool_call
 (3) tools    errow-mcp :9103 (mTLS, policy, MCP_LIVE) ◀┘ and runs its sandboxes in errow-dind ───────┘

 (4) evidence errow ─▶ ./errow_runs/<run>/ ─▶ errow-shipper ─NDJSON─▶ Fluent Bit ─▶ Fluentd ─▶ OpenSearch (errow-* indices)
                              └──────ro──────▶ errow-viewer :8765 (token cookie)        TUI bridge ─forward :24225─▶ Fluent Bit

 (5) response Fluentd ─findings─▶ errow-feedback :9102 ─▶ errow-to-vendetta.sh ─▶ Vendetta active response / SOAR ticket / retest queue
 (6) retest   OpenSearch alerts (FIM, vulnerability, SCA) ─▶ vendetta-to-errow.sh ─/triage─▶ llm-gateway ─/mcp/tool_call─▶ errow-mcp
```

### Bidirectional integration

| Direction | Path | Safety gate |
|---|---|---|
| **Errow → Vendetta** (evidence) | run artifacts → `errow-shipper` (NDJSON, 16 streams) → Fluent Bit → Fluentd → OpenSearch `errow-*`; findings are also mapped to Vendetta alerts (`feedback-loop/schema-validate.py sarif`, field-by-field per §4.1: severity, MITRE/CWE, fingerprint, target/endpoint) | read-only; no exploit payload bodies are shipped |
| **Errow → Vendetta** (response) | `errow-feedback` `POST /errow-finding` → `errow-to-vendetta.sh`: isolate host (Vendetta active response, JWT from the manager API), SOAR ticket (JSON file + optional webhook), enqueue retest | dry-run unless `ERROW_FEEDBACK_LIVE=true` **and** `ERROW_FEEDBACK_APPROVAL_THRESHOLD` distinct approvers (default 2) signed the fingerprint in `feedback-loop/APPROVALS.md` (each line HMAC'd with that approver's own `keys/<approver>.key`; a lone shared `feedback_approval_key` clamps the threshold to 1) |
| **Vendetta → Vendetta** (alert response) | Fluentd `@VENDETTA_EXECD` → `errow-feedback` `POST /approved-action` → `action_gate.py` → manager `PUT /active-response` | same two gates as the row above (same ledger, same verifier); Fluentd holds no manager credential, plus `VENDETTA_EXECD_AGENT_REGEX` agent allow-list |
| **Vendetta → Errow** (retest) | `vendetta-to-errow.sh` polls OpenSearch for FIM/vulnerability/SCA alerts lacking `errow.triggered`, marks them (`errow.triggered`, `errow.run` via `_update`) and plans a scan | `--via-llm` (production): alert → gateway `/triage` → model `toolCalls` → gateway `/mcp/tool_call` → `errow-mcp`; scans never start directly. Target allow-list + `MCP_LIVE=false` by default |
| **LLM** | Errow → `llm-gateway:9101/v1` (OpenAI-compatible, bearer from `llm_gateway_token`) → Ollama | model allow-list (`config/llm-providers.yaml`), `FailClosedError` on cloud keys outside profile `cloud` |
| **LLM** (forensic, both directions) | `errow-feedback` → gateway `/forensic`: detection-rule / remediation / MITRE proposals for findings ≥ high; draft Errow check for SCA failures | advisory only: `proposals.ndjson`, `pending_analyst_review`, `applied:false` — see *Forensic proposals* below |

### The MCP client-vs-server gap, and the bridge

Upstream Errow's `errow/tools/mcp/*` is an **MCP client**: it reads `~/.errow/mcp-servers.json` (`--mcp-config`/`--mcp-server`) and calls
*other* servers' tools. Nothing in Errow *serves* MCP, yet the stack's gateway and the SIEM-triggered flow need to call Errow-grade tools.
`errow-mcp` (`errow/mcp/`, :9103, mTLS) is therefore a compliant **bridge shim**: a policy-enforcing MCP *server* that runs the contract's
tool set (nmap, nuclei, gobuster, bbot, …) in sandboxes of the same image/daemon Errow uses, and writes `mcp_events` for the audit trail.
Related gaps closed by shims:
Errow has **no daemon mode** (one-shot `errow --non-interactive --target … --scan-mode quick --instruction-file …`; hence `errow-entrypoint`
modes `scan|view|idle`), its artifacts are **rewritten JSON** (→ `errow-shipper` makes NDJSON), its sandbox image lacks **gobuster/bbot**
(→ `Dockerfile.sandbox`), and its TUI IPC is an inherited socketpair FD (→ the same-container TUI bridge, `tui/`).

## Naming: Strix → Errow

**Strix is the legacy name of the same product** (an alias, not a sibling project). The rename is complete in the source tree: the CLI is
`errow`, the Python package `errow`, the state directory `~/.errow`, run output `./errow_runs/<run>/`, and environment variables use the
**lowercase** `errow_` prefix (`errow_LLM`, `errow_IMAGE`, `errow_TELEMETRY`, `errow_RUNTIME_BACKEND`, `errow_APP_URL`, …). Older Strix
documentation, blog posts and CI snippets map 1:1: `strix`→`errow`, `STRIX_*`→`errow_*`, `~/.strix`→`~/.errow`, `strix_runs/`→`errow_runs/`.
There is **no compatibility shim** in the code: only the new names are read. The skills under `errow/skills/*-with-errow` are the renamed
`*-with-strix` skills. Stack-level knobs use the `ERROW_` (upper-case) prefix and are consumed by this directory's scripts, not by Errow.

## Runtime summary

| Service | Image | Port | Mode / command |
|---|---|---|---|
| `errow` | `vendetta-stack/errow` | — | `errow-entrypoint --mode idle` (exec scans: `--mode scan -- --target …`) |
| `errow-dind` | `docker:27-dind` (pinned) | 2376 TLS | sandbox daemon (privileged; see RUNTIME.md for sysbox/kata) |
| `errow-viewer` | `vendetta-stack/errow` | 8765 | `ERROW_MODE=view` → `errow view … --host 0.0.0.0 --port 8765` (one run, per-process `?token=`) |
| `errow-feedback` | `vendetta-stack/errow-feedback` | 9102 | `python3 /opt/feedback-loop/server.py` |
| sandbox | `vendetta-stack/errow-sandbox` | (Caido 48080 inside) | per-run container started by Errow/`errow-mcp` in errow-dind |
| `errow-mcp`, `errow-shipper` | `vendetta-stack/errow-mcp`, `…-shipper` | 9103 / — | see `mcp/RUNTIME.md`, `shipper/RUNTIME.md` (owned separately) |

## Build and run

```bash
cd cecur-it-cs3-v1.1.0
# 1. orchestrator image (context = read-only upstream tree; `stack` = this directory)
docker build -f vendetta-stack/errow/Dockerfile.errow --build-context stack=vendetta-stack/errow -t vendetta-stack/errow:1.0.0 errow
# 2. sandbox image: upstream base first (heavy, ~5 GB), then gobuster + bbot on top
docker build -f errow/containers/Dockerfile -t vendetta-stack/errow-sandbox-base:1.0.0 errow
docker build -f vendetta-stack/errow/Dockerfile.sandbox --build-arg ERROW_SANDBOX_BASE=vendetta-stack/errow-sandbox-base:1.0.0 \
  -t vendetta-stack/errow-sandbox:1.0.0 vendetta-stack/errow
# 3. feedback service
docker build -t vendetta-stack/errow-feedback:1.0.0 vendetta-stack/errow/feedback-loop
# resolved configuration without starting anything (prints no secrets)
docker run --rm vendetta-stack/errow:1.0.0 --mode scan --dry-run -- --target http://scan-target.vendetta.lab:8080
```

With the stack's `docker-compose.yml` (deploy tier, which defines profile membership; secrets/PKI come from `scripts/bootstrap.sh`):

```bash
docker compose --profile errow up -d          # errow, errow-dind, errow-viewer, errow-mcp, errow-shipper, errow-feedback
docker compose --profile errow --profile lab up -d   # + scan-target.vendetta.lab, the only default-allowed target
docker compose exec errow errow-entrypoint --mode scan -- --target http://scan-target.vendetta.lab:8080 --scan-mode quick
docker compose exec errow-viewer errow-entrypoint --print-viewer-link     # full viewer URL incl. token (treat as a password)
```

Real (non-lab) targets must be added deliberately. There are three allow-lists: `ERROW_ALLOWED_TARGETS` (entrypoint), `MCP_TARGETS_FILE`
(errow-mcp + llm-gateway; yaml `{hostnames,cidrs,domains,repo_paths}`, additive over `mcp/policy.yaml`) and `ERROW_FEEDBACK_ALLOWED_TARGETS`
(feedback loop). `ERROW_TARGETS` (comma list of host globs, default `scan-target.vendetta.lab`; Helm `config.errowTargets`) is the single
source of truth for the two env lists: both default from it and a non-empty per-service value wins. The yaml cannot be derived from an env
var, so add the same hosts to the `MCP_TARGETS_FILE` yaml and run `scripts/check-allowlists.sh` (exit 1 on drift: feedback list ⊄
`ERROW_ALLOWED_TARGETS`, or either not covered by the errow-mcp hostnames/domains; also run by `tests/check-manifest.sh`). Live execution additionally needs `MCP_LIVE=true`
and/or `ERROW_FEEDBACK_LIVE=true` + an approval line — both default to `false`.

**Viewer frontend** (optional): `viewer/frontend-build.sh` rebuilds the React bundle in a pinned node image without touching upstream and
publishes `viewer/dist/static`; use it with `--build-arg VIEWER_SOURCE=external`. Online runs fill an npm cache (`viewer/.npm-cache`);
copy it to an air-gapped host and run `viewer/frontend-build.sh --offline`.

**Air-gap**: build every image on a connected host, `docker save` them, set `CS3_PROFILE=airgap` (telemetry forced off, cloud endpoints
blackholed) and `ERROW_SANDBOX_IMAGE_TAR` so the entrypoint `docker load`s the sandbox into errow-dind.

## Configuration and secrets

* `config/errow-config.yaml` — documented defaults (scan mode `quick`, telemetry **off**, cloud **off**, lab-only targets, viewer knobs, per-profile
  overlays). Read by the entrypoint through `stack-config.py`; the container environment always wins; secrets/gateway wiring are rejected here.
* `config/llm-providers.yaml` — the local tier: provider `ollama-gateway` (`openai-compatible` → `https://llm-gateway:9101/v1`), models
  `nemotron-3-nano:30b` (agentic, `role: errow-security`, the Errow default), `gemma4:31b` (reasoning tail of the Errow chain), `gemma4:26b`
  (forensic), plus the optional `qwensploit-v2:9b` evaluation model, temperature 0.2, non-streaming, strict JSON. `errow_LLM` in the config file wins over `OLLAMA_SECURITY_MODEL`, which
  wins over `OLLAMA_PRIMARY_MODEL`; a deployment whose gateway lacks the security model degrades to the primary with `ERROW_MODEL_DEGRADED=true`.
  The `cloud-direct` provider is listed **only** in the `cloud` profile — the one place a cloud key may exist.
* **Approval.** The sandbox is isolated, but the gateway still refuses a turn that proposes `execute_command`, `isolate_host` or
  `modify_firewall` without a human-approval token (403 `approval_required`). `CS3_APPROVAL_TOKEN_FILE`
  (`/run/secrets/cs3_approval_token`, compose secret `cs3_approval_token`) is sent as `X-CS3-Approval` through `LLM_EXTRA_HEADERS`, so launching the
  run *is* the approval. Absent the file, the scan starts and then dies on its first shell call — that is the guard working, not a fault.
* **Secrets are files.** The gateway bearer is read from `LLM_GATEWAY_TOKEN_FILE` (`/run/secrets/llm_gateway_token`); in profile `cloud` a direct
  key comes from `LLM_API_KEY_FILE`. Errow's own `errow/utils/secret_files.py` contract is preserved: anything Errow persists (TUI-entered
  settings in `~/.errow/cli-config.json`) is written atomically with mode 0600 under `$HOME/.errow`, so `HOME` must be a writable **tmpfs**
  and the entrypoint scans that file for stale cloud keys and fails closed (exit 78) if one is found outside profile `cloud`.

## Forensic proposals (analyst review)

After isolating/ticketing/queueing a finding, `errow-feedback` asks the llm-gateway (`POST /forensic`, model `gemma4:26b`) for a defensive
**detection rule** and a **remediation** for every finding ≥ `high`; with `errow-to-vendetta.sh --threat-model-file` (shipper `threat_models`
NDJSON) it also proposes a **MITRE tactic/technique**, and `vendetta-to-errow.sh --via-llm` drafts an **Errow check** for failed SCA checks.
Only the sanitized normalized record is sent (no PoC/exploit bodies, credentials redacted). Everything lands in
`/var/log/feedback-loop/proposals.ndjson` as `status:"pending_analyst_review"`, `applied:false`; the console prints
`PROPOSAL: <kind> for <fingerprint> (pending analyst review, not applied)`. **Nothing is applied automatically**: no script writes Vendetta
rules/decoders or calls an apply API, no draft scan is launched, and an unreachable gateway only logs `forensic unavailable: <reason>` —
the response actions never depend on the model. Approval is manual: an analyst reviews the ledger, then installs the rule through the SIEM's
change process or starts the scan by hand. The one optional write is `--apply-enrichment` (needs `ERROW_FEEDBACK_LIVE=true`, `OPENSEARCH_URL`
and the OpenSearch password file; otherwise a `DRY-RUN` line): a non-destructive `_update_by_query` that only **adds** `mitre.tactic`,
`mitre.technique` and `ai.engine` to alerts whose `errow.run` equals the entry's run. Knobs: `ERROW_FEEDBACK_FORENSIC` (default `true`),
`--no-forensic`, `--offline` (no network at all); the container needs `llm-gateway:9101` reachability and `/run/secrets/llm_gateway_token`.

## Layout

| Path | Purpose |
|---|---|
| `Dockerfile.errow`, `Dockerfile.sandbox` (+ `.dockerignore`s) | orchestrator image (multi-stage: Go bridge, optional node viewer build, uv hash-locked install) / sandbox layer |
| `entrypoint.sh`, `dind-ready.py`, `stack-config.py` | container entrypoint, DinD readiness/loader, config + policy loader |
| `config/` | `errow-config.yaml`, `llm-providers.yaml` |
| `tui/bridge/` (Go), `tui/sidecar-deployment.yaml` | TUI→Fluent Bit bridge, K8s errow + errow-dind pods and NetworkPolicies |
| `viewer/` | `deployment.yaml` (K8s Deployment/Service/NetworkPolicy/Ingress), `frontend-build.sh` |
| `feedback-loop/` | `errow-to-vendetta.sh`, `vendetta-to-errow.sh`, `lib.sh`, `forensic.jq`, `normalize-finding.jq`, `schema-validate.py`, `server.py`, `action_gate.py` (approval gate in front of the manager), `APPROVALS.md`, `Dockerfile`, `RUNTIME.md` |
| `mcp/`, `shipper/` | MCP bridge and artifact shipper (separate components) |
| `../tests/synthetic-logs/` | fixtures (see its README) |

## Verification

```bash
cd vendetta-stack/errow
bash tests/test_entrypoint.sh && python3 -B -m unittest discover -s tests -p 'test_stack_config.py'
bash feedback-loop/tests/test_feedback_loop.sh && python3 -B -m unittest discover -s feedback-loop/tests
(cd tui/bridge && go vet ./... && go test ./...)
python3 feedback-loop/schema-validate.py all          # fixtures: SARIF round trip + AIIncidentAnalysis
```
