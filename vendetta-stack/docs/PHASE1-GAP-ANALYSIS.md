# Phase 1 — Spec Ingestion & Gap Analysis

> Deliverable for PROMPT.md §3 Phase 1. Gate: *"Do not proceed to Phase 2 until the gap analysis is acknowledged."*
> The operator instruction for this build was **"accept best recommendations and continue on"**, so every
> recommendation below is treated as acknowledged and the build continued into Phases 2-4. Each assumption that
> an operator may want to veto is listed in §9 with the knob that reverses it.

## 0. Provenance — what was actually ingested

| Source named in PROMPT.md | Present in repo? | How it was handled |
|---|---|---|
| `errow/` directory tree | **Yes** — `cecur-it-cs3-v1.1.0/errow/` | Read module-by-module (§2). Every Errow claim in this suite was checked against code, not docs. |
| CS3 dual-model architecture (`server/inference/*.ts`, `onboarding/models.json`, `scripts/install-ollama.sh`, `deployment/**`) | **Yes** — `cecur-it-cs3-v1.1.0/` | Ported (guardrails, failover, metering, hardening) — see §3. |
| `Vendetta Suite.docx` | **No** — not in the repo or the attachments reachable from this session | The spec itself enumerates the daemon set (`vendetta-remoted/authd/clusterd/analysisd/db/modulesd/execd`, ports 1514/1515/1516/55000/9200, `ossec.conf`, `internal_options.conf`, `cluster.json`, `alerts.json`, AES-256/Blowfish, Blake2b, SQLite/RocksDB, ISM Hot-Warm-Cold, JWT RBAC). That list matches the stand-in's integration contract, so the **default manager image is `wazuh/wazuh-manager:4.9.2`**, overridable with `VENDETTA_MANAGER_IMAGE`. Section references such as "Vendetta §7" are cited by the spec's own section numbers. **If the .docx differs, only §1 of this document and `vendetta-manager` in compose/Helm change.** |

## 1. Vendetta component inventory (from the spec + stand-in reference)

| Component | Role | Port / path | Stack treatment |
|---|---|---|---|
| `vendetta-remoted` | Agent event receiver (AES-256 / Blowfish channel) | TCP 1514 | Published by `vendetta-manager`; agents unchanged. NOT proxied through Fluent Bit (encrypted agent protocol). |
| `vendetta-authd` | Agent enrollment | TCP 1515 | `scripts/enroll-agent.sh`; **never reachable from Errow or Ollama networks** (policy `denied.ports`, NetworkPolicy). |
| `vendetta-clusterd` | Manager cluster (`cluster.json`) | TCP 1516 | Manager-namespace only. |
| Manager API | REST + JWT RBAC | TCP 55000 | Used by `errow-to-vendetta.sh` (active response) and `enroll-*`. |
| Indexer | OpenSearch fork, ISM | TCP 9200/9300 | Replaced 1:1 by **OpenSearch 2.17.1** (same REST/ISM). |
| `vendetta-analysisd` | Rule engine → `alerts.json` | file `/var/ossec/logs/alerts/alerts.json` | Fluent Bit `tail` source for `vendetta.alerts`; AI enrichment is a *post-analysisd* stage (`llm-gateway`), not a rule-engine fork. |
| `vendetta-db` | Agent/state DB (SQLite / RocksDB) | local | Out of scope for the pipeline; covered by manager volume backup. |
| `vendetta-modulesd` | FIM (syscheck), vuln detector, SCA | emits into alerts | Stream split by `rule.groups` → `vendetta.fim/vulnerability/sca` (Lua `classify_vendetta`). |
| `vendetta-execd` | Active response | manager API | Target of the guarded feedback loop (isolate host). |
| `ossec.conf`, `internal_options.conf`, `cluster.json` | Config | `vendetta-manager` volume | Mounted, not regenerated; stack only injects the `<localfile>`/integration hooks documented in `docs/PHASE2-TOPOLOGY.md` §7. |
| `custom-` integrations | Script hooks | `/var/ossec/integrations/custom-*` | The LLM triage is delivered by Fluentd → gateway, so no `custom-*` script is required; the hook point is documented for operators who prefer manager-side enrichment. |

## 2. Errow component inventory (verified against `cecur-it-cs3-v1.1.0/errow`)

| Module / dir | What it is | Integration role |
|---|---|---|
| `errow/errow/core/{runner,execution,agents,sessions,paths,hooks,inputs}.py` | Scan orchestration; `paths.py` fixes run output at **cwd-relative `./errow_runs/<run>/`** | `errow-shipper` source |
| `errow/errow/agents/` | Agent factory + prompts | none (internal) |
| `errow/errow/llm/{request_log,compaction,context_budget,warmup}.py` | LLM client plumbing; `request_log.py` is the `errow-llm-logs-*` source | pointed at `llm-gateway` (`LLM_API_BASE`) |
| `errow/errow/report/{sarif,state,writer,runs,coverage,dedupe,usage,pricing}.py` | Atomic rewrites of `run.json`, `vulnerabilities.json`, `findings.sarif`, `coverage.json`, `.state/*` | shipper converts to NDJSON |
| `errow/errow/runtime/{docker_client,docker_connection,backends,caido_*,session_manager}.py` | Sandbox lifecycle through `DOCKER_HOST`/`from_env` | DinD sidecar; `errow-mcp` reuses the same mechanism |
| `errow/errow/tools/*` (agent_browser, agents_graph, apply_patch, coverage, finish, load_skill, **mcp**, notes, output_store, proxy, reporting, shell, thinking, threat_model, todo, view_image, wait_for_user, web_search) | The agent tool surface | Mapped to policy entries in `llm-gateway/mcp_policy.yaml` (§5.3) |
| `errow/errow/interface/{main,cli,cli_args,cloud/*,auth_cli,…}.py` | CLI (`view`, `auth`, `completion`, `cloud`; default = one-shot scan), cloud API (`app.errow.ai`, `/api/v1`) | `errow-feedback` retest trigger (`ERROW_CLOUD_ENABLED`) |
| `errow/errow/interface/viewer/{cli,server,auth,transcript,report_pdf}.py` + `frontend/` (React) | `errow view` HTTP server; per-process `?token=` → cookie `errow_viewer_session_<port>`; absolute `/api/*` fetches | `errow-viewer` :8765 (pinned; upstream default is ephemeral) |
| `errow/errow/interface/tui/` (`sidecar.py`, Go `cmd/errow-tui`, `internal/`, `backend/`) | TUI sidecar; IPC = inherited socketpair FD (`errow_TUI_FD`) / Windows loopback `errow_TUI_ADDR`+`errow_TUI_TOKEN` | bridge forwards events to Fluent Bit `ERROW_TUI_PORT`=24225 |
| `errow/errow/telemetry/{posthog,scarf,logging,_common}.py` | Opt-in product telemetry | mirrored (§6) |
| `errow/errow/utils/secret_files.py` | `*_FILE` secret path contract | preserved by every Errow-facing script/manifest |
| `errow/errow/skills/**`, `errow/skills/**` | Knowledge base (Markdown) | untouched; mounted with the image |
| `errow/containers/{Dockerfile,docker-entrypoint.sh}` | **Kali sandbox image** (nmap, nuclei, subfinder, wafw00f, trufflehog, ffuf, Caido on :48080 with `--no-logging`; **no gobuster, no bbot**) | reused; `errow/Dockerfile.sandbox` extends it |
| `errow/scripts/{build.sh,docker.sh,install.sh,tui_sidecar_hook.py}` | Packaging; `tui_sidecar_hook.py` is a Hatchling **build** hook | not a runtime hook |
| `errow/tests/` (114 files) | Upstream tests | not executed by this suite (own tests live in `vendetta-stack/*/tests`) |
| `errow/docs/`, `errow/benchmarks/` | Docs / benchmarks | untouched |

**Strix ↔ Errow naming.** The tree contained `docs/logo/strix.png` and four `skills/*-with-strix` directories whose `SKILL.md` files use the Strix brand. Resolution applied: **Strix is the legacy name of the same product (alias, not a sibling product)**. The user's global instruction to rename was honoured: `git mv` renamed `strix.png → errow.png` and `ci-security-scanning-with-strix`, `fix-security-vulnerabilities-with-strix`, `managed-pentesting-with-strix`, `penetration-testing-with-strix` → `…-with-errow`; a repository-wide grep finds no remaining `strix` token under `errow/`. Both names stay documented as aliases in `errow/README.md`.

## 3. LLM component inventory (all pre-existing in CS3; mirrored, not reinvented)

| CS3 asset | Mirrored as | Notes |
|---|---|---|
| Ollama 0.40.5 pin (`install-ollama.sh`, `install.ps1`, `install.command`) | `ollama/install-ollama.sh` (+ `Dockerfile.ollama`, `cs3-ollama.service`, `.plist`) | 15-directive sandbox; `diff -q` idempotent reload; `--offline-binary` for air-gap. Windows (`install.ps1`) stays upstream. |
| `onboarding/models.json` (8 mandatory keys) | `ollama/models.json` | `sha256` keeps the CS3 sentinel `<pinned-per-release>` (weights' digests cannot exist in-repo). `scripts/validate-models-json.sh --release` **fails** on the sentinel. |
| `scripts/detect-hardware.mjs` | `ollama/detect-hardware.mjs` | tier recommendation from GPU/VRAM. |
| `scripts/install-llama.cpp.sh` (`b4000`) | `ollama/install-llama.cpp.sh` | non-CUDA GGUF fallback, same SHAs. |
| `server/inference/{guardrails,gateway,meter,router,types}.ts`, `server/ai/cecurAI.ts` | `llm-gateway/{guardrails,server,meter,failover,heuristics}.py` | TS↔Python equivalence table in `llm-gateway/README.md`. |
| `cs3-launcher.mjs` (`enforceIsolation`, `runHealthChecks`, `probeTcp(127.0.0.1,11434)`) | gateway start-up checks + `scripts/healthcheck.sh` | loopback + FailClosed. |
| `onboarding/wizard.mjs`, `wizard.config.json` | not duplicated — `scripts/bootstrap.sh` is the headless equivalent | |
| `deployment/docker/docker-compose.gpu.yml`, `ollama-lb/{nginx,haproxy}` | `docker-compose.gpu.yml`, `ollama/ollama-lb/{nginx.conf,haproxy.cfg,worker-proxy.cfg}` | mTLS worker hop added (§4, row "Ollama"). |
| `deployment/helm/cs3`, `kustomize`, `argocd`, `ansible/playbooks/model-{update,rollback}.yml` | `kubernetes/helm/vendetta-stack`, `kubernetes/kustomize/overlays/*` | ansible playbooks are referenced (model update/rollback) rather than copied. |
| `deployment/agents/templates/gateway.d/{20-normalize,60-ai-tier}.conf` + `cs3-otlp-normalize.lua` | `fluent-bit/conf.d/60-ai-tier.conf`, `fluent-bit/stream_processors.lua` | same sanitizer algorithm (8,000 chars, control strip, redaction). |

## 4. Combined gap analysis (Vendetta + Errow + LLM)

| # | Spec expectation | Reality | Severity | Resolution (compliant bridge) |
|---|---|---|---|---|
| G-01 | "Errow **exposes** its tooling as an MCP server" (`errow/tools/mcp/*`) | `tools/mcp/*` is an MCP **client** (`list_mcps`, `search_mcp_tools`, `get_mcp_tool_schema`, `call_mcp`; config `~/.errow/mcp-servers.json`). There is no server. | **High** | **`errow-mcp` bridge shim** (`errow/mcp/`): MCP streamable-HTTP JSON-RPC server (`initialize`, `tools/list`, `tools/call`) over mTLS that executes tools in ephemeral Docker sandboxes. Policy re-validated (defense in depth). |
| G-02 | MCP tools `bbot`, `gobuster` in `agent_tools.py` | Not present; the Kali sandbox image has neither bbot nor gobuster | Medium | `errow/Dockerfile.sandbox` extends the upstream sandbox image with pinned bbot + gobuster. |
| G-03 | `tail` on `~/.errow/runs/` and `~/.errow/reports/` **JSONL** | Runs are `./errow_runs/<run>/` (cwd-relative), atomically **rewritten JSON** (`run.json`, `vulnerabilities.json`, `findings.sarif`, `coverage.json`, `.state/*`); not JSONL, not `~/.errow` | High | **`errow-shipper`** converts to idempotent NDJSON (`/var/log/errow/<stream>.ndjson`) which Fluent Bit tails; `${ERROW_REPORTS_DIR}` tail kept for operators that do keep reports there. |
| G-04 | `dummy`/`exec` input bridging CLI stdout/stderr | Errow has no log socket | Low | `errow` entrypoint tees stdout/stderr to `/var/log/errow/cli.log`; Fluent Bit `tail` (of `cli.log` and the shipper `status.json`; the `exec` input is not compiled into 3.2.10, see §10). |
| G-05 | `forward` input from `errow-tui` sidecar | TUI IPC is a socketpair FD (POSIX) / ephemeral loopback (Windows) — not a network service | Medium | Bridge in `errow/tui/sidecar-deployment.yaml`; `ERROW_TUI_PORT`=24225 is **the bridge's forward port**, not Errow's. Routed only to Fluentd forward. |
| G-06 | `tail` on `~/.caido/` | Caido runs **inside per-run sandbox containers** (:48080, `--no-logging`) | Medium | Shipper captures sandbox container logs/events through the Docker API → `errow.proxy`; `${CAIDO_LOG_GLOB}` tail kept for native installs. |
| G-07 | Errow Viewer port "derive from cli.py/server.py" | Ephemeral by default; token-per-process auth; frontend fetches absolute `/api/*` | Low | Pinned **8765** (`errow view --host 0.0.0.0 --port 8765`); own hostname at the shared Ingress (no sub-path hosting); auth stays token/cookie. Standalone viewer cannot steer a run. |
| G-08 | Errow runs as a long-lived service | No daemon mode; one-shot scans | Medium | K8s `Job`/compose one-shot runner + DinD sidecar; scheduled by `errow-feedback`/CI. |
| G-09 | Errow cloud API base URL | `https://app.errow.ai` (`/api/v1`) | Low | `ERROW_CLOUD_URL`, feedback path degrades to local-only when `ERROW_CLOUD_ENABLED=false` (default). |
| G-10 | Vendetta XML rule-engine parity in Fluent Bit/Fluentd | Not reproducible with a log pipeline | Deferred (non-goal) | `vendetta-analysisd` stays in the manager; the pipeline adds enrichment, not rules. |
| G-11 | Ollama "11434 mTLS" between HAProxy and workers | Ollama must bind 127.0.0.1:11434 (hard rule); a second listener cannot share that port | **High (design)** | Per-worker **TLS-terminator sidecar** (`ollama-N-proxy`, HAProxy) in the worker netns listening `:11443` (mTLS) → `127.0.0.1:11434`; `ollama-lb` shares the **gateway** netns and binds `127.0.0.1:11434`. The gateway still speaks only to loopback. |
| G-12 | `/metrics` on Ollama | Ollama 0.40.5 exposes no Prometheus endpoint | Medium | Gateway meter on :9101 exports `ollama_gpu_memory_util` and per-model counters; LB stats via HAProxy :8404. |
| G-13 | `Vendetta Suite.docx` | absent | Medium | See §0 (Vendetta-compatible stand-in; one image variable). |
| G-14 | Real SHA-256 pins for model weights | unknowable in-repo | Medium | Sentinel + `validate-models-json.sh --release` gate + `pin-model-digests.mjs` + `enroll-ollama.sh` blob verification + `verify-bundle.sh`. |
| G-15 | Errow `/metrics` "if exposed" | Not exposed | Low | Shipper `status.json` + `errow-mcp` `/metrics`; Errow cost/usage arrive via `errow.llm_logs`. |
| G-16 | Docker Desktop-style `docker run` sandbox inside K8s | needs a Docker API | Medium | DinD sidecar (`privileged`) documented with the safer alternatives (rootless/sysbox/kata) + NetworkPolicy isolating sandboxes. |
| G-17 | Fluent Bit config reload | Process-level only | Low | `Hot_Reload On` + `entrypoint.sh` renders legs from env at start. |
| G-18 | Fluent Bit `systemd` input in containers | Needs the host journal | Low | Mounted only when `/var/log/journal` exists; HTTP test hook (`POST /host.journal`) exercises the same retag filters in CI. |

### 4.1 Telemetry overlap — decision

| Stream | Decision |
|---|---|
| Errow PostHog + Scarf | **Keep native, opt-in** (`errow_TELEMETRY` default off in this stack). When enabled, the same events are mirrored through Fluent Bit (`errow.telemetry`) into `errow-telemetry-*` (dual sink; PostHog/Scarf untouched). |
| Vendetta telemetry | Unchanged (`vendetta.*`). |
| Ollama journald (`cs3.ai.ollama`) | Retagged at the edge, delivered **only** to ESOC OTLP + SIEM NDJSON + a local safety file. **Excluded from the Console ingest leg, `vendetta-alerts-*`, and `/triage`** (CS3 §4.3 telemetry-loop prevention); this is structural (`Match_Regex` cannot match `cs3.ai.*`) and asserted by `fluent-bit/tests/test_legs.sh`, `fluentd/tests/test_routing.sh`, `scripts/healthcheck.sh`, and the smoke test. |

### 4.2 Schema alignment

**SARIF result → Vendetta alert** (shipped record = raw SARIF result + `rule`; implemented by ingest pipeline `sarif-to-vendetta-alert`, verified by `errow/feedback-loop/schema-validate.py sarif` and `opensearch/tests/run-tests.sh`)

| Vendetta alert field | Source (shipped Errow finding) |
|---|---|
| `@timestamp` | shipper `@timestamp` |
| `id` | `doc_id` (= `sha256(run+ruleId+partialFingerprints.primaryLocationLineHash)`) |
| `source.system` / `source.stream` | constant `errow` / `errow.findings` |
| `rule.id` | `ruleId` |
| `rule.level` | from severity: critical 14, high 11, medium 8, low 5, info 2 |
| `rule.description` | `message.text` |
| `rule.groups` | `[errow, sarif, <cwe>]` |
| `severity` | `properties.errow.severity`; else SARIF `level` (error→high, warning→medium, note→low) |
| `mitre.{id,tactic,technique}` | CWE→ATT&CK map (ingest pipeline) |
| `agent.name` | host of `properties.errow.target` |
| `location` | primary `locations[0]` URI, else `properties.errow.endpoint` |
| `full_log` | concise summary (never PoC bodies; `poc_script_code` is never emitted) |
| `errow.run / finding_id / cwe / cve / owasp / cvss / confidence / target / endpoint / sarif_rule_id / fingerprint` | shipper `run`, `properties.errow.id`, `…cwe`, `…cve`, enrichment `owasp`, `…cvss`, `…confidence`, `…target`, `…endpoint`, `ruleId`, `partialFingerprints.primaryLocationLineHash` |

**`AIIncidentAnalysis` → Vendetta alert** (`aiincident-to-vendetta-alert` pipeline and Fluentd `12-filter-ai-inference.conf`)

| `AIIncidentAnalysis` | Alert field |
|---|---|
| `severityAssessment` | `severity` (lower-case) + `rule.level` |
| `mitreTactic` / `mitreTechnique` | `mitre.tactic[]` / `mitre.technique[]` |
| `probableRootCause` | `root_cause` |
| `recommendedImmediateAction` | `recommended_action` |
| `confidenceScore` | `ai.confidence` |
| `engineUsed` | `ai.engine` (`ai.role` = triage/forensic/heuristic from the engine) |
| `gpuSeconds` | `ai.cost.gpu_seconds` |
| `triageSummary` | `ai.verdict` summary |
| fallback | `ai.fallback` (`Cecur Heuristics` ⇒ `true`) |

### 4.3 Throughput budgets (planning figures — validate with `docs/capacity.md` test plan before sizing production)

| Path | Sustained | Burst | Mechanism that protects it |
|---|---|---|---|
| Vendetta events | `events_per_second: 500` (manager leaky bucket) | ~10× for 60 s | Fluent Bit filesystem buffer + `storage.pause_on_chunks_overlimit on`; Fluentd file buffers, `overflow_action block`; OpenSearch bulk back-pressure |
| Errow findings/transcripts | ≤ 50 rec/s per active scan | 1k rec/s at scan end (SARIF rewrite) | shipper content-hash dedupe, per-tail `Mem_Buf_Limit` |
| LLM triage (Nemotron 3.5B active, 24 GB) | ~1.5-3 triage/s/worker (≈250 output tokens, `OLLAMA_NUM_PARALLEL=4`) | alert storms exceed it by design | **Only the medium+ subset reaches the model path**; the rest is enriched by heuristics; HAProxy `maxconn 4`/server + `timeout queue 30s`; gateway `GATEWAY_MAX_CONCURRENCY`; 3-tier failover |
| Forensic (Gemma 26b 4B active / 31b dense) | ~0.3-1/s (26b), ~0.1-0.3/s (31b) | n/a | invoked only for Errow findings ≥ HIGH and escalations |
| `mcp_tool_calls_per_sec` | 10/min/tenant, 100/min cluster (per replica), 4 concurrent | none (hard cap) | `llm-gateway` rate limiter + `errow-mcp` limiter |

### 4.4 Anti-flooding equivalence

| Vendetta mechanism | Stack equivalent |
|---|---|
| Leaky-bucket `events_per_second` | Fluent Bit `Mem_Buf_Limit` + `storage.type filesystem` + `pause_on_chunks_overlimit` ⇒ inputs pause, not drop |
| Agent-side queue | Fluent Bit disk buffer (`storage.max_chunks_up`, backlog limit) |
| Manager queue overflow | Fluentd `total_limit_size` + `overflow_action block` (back-pressure to Fluent Bit, no loss) |
| (new) LLM KV-cache thrashing | HAProxy per-server `maxconn`, global concurrency queue, `timeout queue 30s`, gateway concurrency semaphore; overflow degrades to heuristics instead of stalling the SOC |

## 5. Mandatory mapping tables (PROMPT §2)

### 5.1 Vendetta → Stack — see §1 plus data-flow rows in `PHASE2-TOPOLOGY.md` §3.

### 5.2 Errow → Stack

| Errow artifact / source | Shipped stream (Fluent Bit tag) | Index (daily `…-YYYY.MM.dd`) | Notes |
|---|---|---|---|
| `findings.sarif` results | `errow.findings` | `errow-findings-*`, `errow-sarif-*`, **and** `vendetta-alerts-*` via `sarif-to-vendetta-alert` | ISM `errow-findings-retention` |
| `run.json` | `errow.runs` | `errow-runs-*` | |
| agent messages | `errow.transcripts` | `errow-transcripts-*` | redacted + truncated at 8,000 chars |
| `.state/threat_models.json` | `errow.threat_models` | `errow-threat-models-*` | feeds MITRE enrichment |
| `coverage.json` | `errow.coverage` | `errow-coverage-*` | |
| `llm/request_log.py` output | `errow.llm_logs` | `errow-llm-logs-*` | no prompt bodies |
| MCP bridge + gateway tool calls | `errow.mcp_events` / `cs3.ai.tool_call` | `errow-mcp-*` (+ `cs3-ai-audit-*`) | AU-9 |
| `errow.log`, container events | `errow.runtime_events` | `errow-runtime-*` | |
| Caido (sandbox container logs) | `errow.proxy` | `errow-proxy-*` | |
| tool executions | `errow.tooling` | `errow-tooling-*` | |
| TUI bridge | `errow.tui_events` | `errow-tui-*` | |
| cloud session | `errow.cloud_events` | `errow-cloud-*` | |
| PostHog/Scarf mirror | `errow.telemetry` | `errow-telemetry-*` | opt-in, dual sink |
| `.state/agents.db` | `errow.agent_state` | `errow-agent-state-*` | read-only sqlite |
| viewer access log | `errow.viewer` | `errow-viewer-*` | |
| generated files | `errow.report_artifacts` | `errow-report-artifacts-*` | `{artifact,path,sha256,bytes,kind}` |

### 5.3 Errow as MCP server — spec table vs. implemented policy

The spec attributes every row to `errow/tools/mcp/agent_tools.py`; that file is client-side. The policy entries below are served by the `errow-mcp` bridge and enforced by the gateway **before** forwarding and again inside the bridge. Authoritative file: `llm-gateway/mcp_policy.yaml` (byte-identical `errow/mcp/policy.yaml`, CI-checked by `scripts/sync-mcp-policy.sh --check`).

| Tool | Role (model) | Implemented guardrail |
|---|---|---|
| `bbot` | triage (nemotron) | domain allow-list; presets `subdomain-enum`/`safe`; passive flag only; 1/min/target |
| `nmap` | triage | host allow-list; `-sn/-sT/-sV` only; ports ∈ {1-1024,3389,8080,8443}; `--script/-A/-sC/-sU/-sS` forbidden |
| `nuclei` | triage | tags ∈ {cves, exposures, misconfiguration, technologies}; `dos/fuzz/intrusive/rce-exploit` forbidden; rate ≤ 50 |
| `gobuster` | triage | `dir` mode; two pre-approved wordlists; threads ≤ 10 |
| `subfinder` | triage | domain allow-list; passive only |
| `wafw00f` | triage | passive only |
| `trufflehog` | triage | `/workspace/repos/*` only; no network verification |
| `shell` | triage | enum commands `curl -sI`, `dig`, `nslookup`, `ping -c 3`; metacharacters rejected; Docker sandbox |
| `agent_browser` | forensic (gemma) | HTTPS + domain allow-list; screenshot retention ≤ 30 d (default 7) |
| `proxy` | forensic | allow-listed target; read-only actions |
| `web_search` | forensic | ≤ 5/min; query ≤ 200 chars |
| `threat_model`, `coverage` | forensic | read-only |

Defaults: **default-deny**; `denied` CIDRs/hostnames/ports are evaluated first; execution only when `MCP_LIVE=true`, otherwise a `dry_run` plan is returned and audited.

### 5.4 LLM model → role → node assignment

| Model | Role | Node tier | Role label | Consumers |
|---|---|---|---|---|
| `nemotron-3-nano:30b` | triage / agentic SOAR / MCP tool-calling | 24 GB+ VRAM / 64 GB RAM pool | `INFERENCE_MODEL_TRIAGE` | alert enrichment, FIM/SCA/vuln triage, MCP `tool_call` planning |
| `gemma4:26b` | forensic / fallback (default) | 16 GB VRAM / 32 GB RAM | `INFERENCE_MODEL_FORENSIC` | root-cause synthesis, compliance gaps, multimodal OCR, failover from Nemotron |
| `qwensploit-v2:9b` | *optional* security evaluation model (not a production default) | any security node, 16 GB VRAM / 32 GB RAM | `INFERENCE_MODEL_SECURITY`, `INFERENCE_MODEL_ERROW_SECURITY` (when pinned) | ablation/evaluation of the agentic security tier; not the guard/judge |
| `gemma4:31b` | high-assurance forensic (optional upgrade) | 24 GB+ / 64 GB | `INFERENCE_MODEL_FORENSIC` (upgrade) | multi-hop reconstruction, **defensive SIEM-rule synthesis from Errow findings**, large multimodal |

### 5.5 Bidirectional feedback loop (all outbound actions default to dry-run)

| Trigger | LLM step | Action | Guardrail (as implemented) |
|---|---|---|---|
| Any Vendetta alert (medium+) | Nemotron → `AIIncidentAnalysis` | enrich alert (`cs3.ai.enrichment` upsert); if HIGH plan `toolCalls` | gateway concurrency/rate limits; tool calls are *returned*, never auto-run by `/triage` |
| "needs verification" | Nemotron `tool_call` | `/mcp/tool_call` → nmap/nuclei in sandbox | allow-list, denied-first, `MCP_LIVE=false` ⇒ dry-run, audited |
| Errow finding ≥ HIGH | Gemma forensic | proposed Vendetta rule + SOAR playbook (`proposedDetectionRule`) | analyst confirmation (`APPROVALS.md` signed line + `ERROW_FEEDBACK_LIVE=true`) |
| Errow finding (SARIF) | Gemma | proposed remediation | never auto-applied |
| Errow threat model | Gemma | MITRE tag enrichment | alert-document only |
| Vendetta SCA failure | Gemma | draft Errow `source_aware_sast` check | analyst approval |
| GPU alert / timeout | gateway failover | Nemotron → Gemma → heuristics | deterministic, logged, `llm_gateway_failover_total` |

## 6. Port / protocol additions invented by this design

| Item | Value | Reason |
|---|---|---|
| Ollama | 127.0.0.1:11434 (**loopback only, never published**) | CS3 §2.2 |
| Ollama worker TLS terminator | `:11443` mTLS inside the worker network namespace → loopback 11434 | G-11 |
| LLM gateway | :9101 HTTPS (+metrics/health) | spec |
| `errow-mcp` | :9103 HTTPS mTLS | bridge (G-01) |
| `errow-feedback` | :9102 HTTP bearer | feedback-loop webhook |
| Errow viewer | :8765 | G-07 |
| TUI bridge forward | :24225 | G-05 |
| Caido | :48080 in sandbox (spec's 8080/8443 are upstream defaults of Caido, not this image) | G-06 |
| Fluent Bit test/gateway HTTP | :9880 (path = tag) | gateway events + CI hook |
| Errow cloud | `https://app.errow.ai/api/v1` | G-09 |

## 7. Pinned versions

Fluent Bit **3.2.10**, Fluentd **v1.17** (`fluent/fluentd:v1.17-debian-1`), OpenSearch/Dashboards **2.17.1**, Prometheus **v2.55.1**, Alertmanager **v0.27.0**, Grafana **10.4.19**, HAProxy **3.0-alpine**, NGINX **1.27-alpine**, Ollama **0.40.5**, Python **3.12-slim-bookworm**, Docker **27-dind**. Every image is referenced as `name:tag@sha256:digest` (digests resolved from Docker Hub). Compose/Helm variables live in `.env.example` / `values.yaml`.

## 8. Non-goals / deferred

| Item | Status |
|---|---|
| Full Vendetta XML rule-engine parity | Deferred; manager keeps its engine (G-10). |
| Vendetta §7 RAG copilot | **Not built.** It would only be admissible if it reused `errow/errow/llm/`; the gateway `/v1/chat/completions` passthrough is the sanctioned seam (`errow_LLM=openai/<model>`), so a future copilot can reuse `errow/llm/{compaction,context_budget}` through it. |
| Strix → Errow rename | **Done** (global instruction); aliases documented. |
| `gemma4:31b` | Optional upgrade (`INFERENCE_MODEL_FORENSIC=gemma4:31b`); in the air-gap bundle only with `--with-31b`. |
| Multi-region OpenSearch | Single cluster per site; CCR documented in operations guides. |

## 9. Default engineering assumptions (reversal knob in brackets)

1. Errow shares the Vendetta namespace but runs on an isolated `offensive` network. [`values.yaml: errow.namespace`]
2. `errow/containers/Dockerfile` stays the canonical sandbox; extra tools are layered, not forked. [`ERROW_SANDBOX_BASE`]
3. The Errow Viewer sits behind the shared Ingress on its own host. [`ingress.viewerHost`]
4. Errow cloud is optional; the loop degrades to local-only. [`ERROW_CLOUD_ENABLED`]
5. Ollama runs on a dedicated GPU node pool; the gateway is the **only** client of 11434. [`ollama.nodeSelector`]
6. Weights are pre-staged in the air-gap bundle with SHA-256 pins; digests are pinned at release time (sentinel until then). [`scripts/pin-model-digests.mjs`]
7. `temperature 0.2`, `top_p 0.9`, `top_k 40`, strict JSON are **hard-coded** in the gateway (not tenant-tunable).
8. **Safe by default**: `MCP_LIVE=false`, `ERROW_FEEDBACK_LIVE=false`, `ERROW_CLOUD_ENABLED=false`, telemetry off, `CS3_*` egress legs off.
9. FailClosed: any cloud-LLM key present under profile `onprem`/`airgap` stops the gateway, bootstrap and healthcheck.
10. The Vendetta-compatible manager image stands in for the unavailable Vendetta docx (§0).

## 10. Implementation deviations (recorded after Phase 3)

Differences between what Phases 1-2 proposed and what the pinned upstream versions allow. Each is also documented in the component `RUNTIME.md`.

| Area | Deviation | Consequence / mitigation |
|---|---|---|
| Fluent Bit 3.2.10 | The `exec` and `winlog` inputs are not compiled in. | CLI stdout/stderr and shipper status are `tail`ed from files; Windows hosts use the CS3 Windows agent template (`deployment/agents`). |
| Fluent Bit forward-in | The `forward` input checks the server side of TLS only; client certificates are not enforced on `:24224`. | Restrict that port with NetworkPolicy / compose networks; mTLS is enforced by Fluentd `in_forward`. |
| Fluentd ESOC leg | OTLP/HTTP-JSON through custom plugins; the Fluent Bit ESOC leg is OTLP/gRPC. | A leg is enabled in exactly one of them (`CS3_AGGREGATOR_LEGS` vs the Fluent Bit leg switches). |
| Prometheus | OpenSearch is not scraped (no exporter in the contract); `errow-mcp` is scraped for `up` only. | Index health is covered by `scripts/healthcheck.sh` and Grafana panels that read OpenSearch directly. |
| Alertmanager | Receivers are intentionally empty. | No secret or external endpoint is shipped; operators add a receiver (see `prometheus/RUNTIME.md`). |
| Errow MCP | `errow/tools/mcp/*` is an MCP client, so `errow/mcp/` is a bridge shim (G-01). | Same policy as the gateway, byte-identical (`scripts/sync-mcp-policy.sh --check`). |
| Vendetta manager | Default stand-in image (`wazuh/wazuh-manager:4.9.2`); its API TLS mount and healthcheck were not exercised (image not pulled in the build environment). | Verify with `scripts/healthcheck.sh` on first deployment. |
| Compose networks | Six segmented networks (`edge`, `aggregation`, `storage`, `management`, `offensive`, `inference`). A Docker daemon whose embedded DNS is not scoped per network (Engine 29.1.3 observed) cannot run them. | `tests/smoke-test.sh` probes for this and falls back to one flat network (`tests/flatten-networks.py`); segmentation is then proven by Helm NetworkPolicies only, not by the Compose smoke run. |
| Compose configs | `configs: content:` is injected by copying into the container, which a `read_only` rootfs rejects. | File-backed configs only (`errow/config/scan-target.nginx.conf`). |
