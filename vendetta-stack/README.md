# vendetta-stack

Production deployment and automation for the **Vendetta XDR/SIEM suite**, the **Errow** offensive-security platform and a
**sovereign, zero-egress local LLM tier** (Ollama 0.40.5: `nemotron-3-nano:30b` triage/security/Errow, `gemma4:26b` forensic,
`gemma4:31b` deep reasoning and the only security/Errow fallback). Qwensploit 9B is optional evaluation-only and is not pulled by default.
It runs as Docker Compose (dev/smoke/on-prem), Helm or Kustomize (production), and as an offline air-gap bundle.

```
 hosts / agents ──► Fluent Bit 3.2.10 ──► Fluentd 1.17 (x2, active-active) ──► OpenSearch 2.17 ──► Dashboards · Grafana
   (edge sanitization,   (buffer, route, copy)                    │                 ▲
    8,000-char cap)                                               ▼                 │
 Errow runs / TUI / Caido ──► errow-shipper ──►        errow-feedback ◄──► Vendetta manager (execd, host-isolate)
                                                            │ ▲
                              llm-gateway (guardrails, failover, metering) ──► errow-mcp ──► Errow sandbox (Docker/DinD)
                                      │  triage: nemotron ► gemma 26B ► heuristics; security/Errow: nemotron ► gemma 31B
                                      ▼  loopback only
                              ollama-lb (HAProxy | NGINX) ──► Ollama (GPU) ──► models.json SHA-256 pins
```

Everything is **dry-run and local by default**: `MCP_LIVE=false`, `ERROW_FEEDBACK_LIVE=false`, Errow cloud and telemetry off,
every published port bound to `127.0.0.1`, Ollama reachable only through the gateway's loopback.

## Read first

| Document | What it is |
|---|---|
| [`docs/PHASE1-GAP-ANALYSIS.md`](docs/PHASE1-GAP-ANALYSIS.md) | component inventories (Vendetta, Errow, LLM), the five mapping tables, gap analysis, assumptions, non-goals, throughput budgets |
| [`docs/PHASE2-TOPOLOGY.md`](docs/PHASE2-TOPOLOGY.md) | directory manifest, trust boundaries, data-flow table, HA / active-active model, Vendetta `ossec.conf` hooks (§7) |
| [`docs/qwensploit-routing-rationale.md`](docs/qwensploit-routing-rationale.md) | ISSO routing rationale, rollback procedure, acceptance summary and open risks |
| [`docs/change-records/CHG-2026-11-19-NEMOTRON/ACCEPTANCE.md`](docs/change-records/CHG-2026-11-19-NEMOTRON/ACCEPTANCE.md) | durable live-host evidence pack: exactly 18 acceptance rows, raw transcripts, smoke artifacts, rollback rehearsals and hashes |
| [`docs/runbooks.md`](docs/runbooks.md) | one runbook per Prometheus alert (the alert annotations link to these anchors) |
| [`docs/capacity.md`](docs/capacity.md) | capacity test plan: EPS, MCP calls/s, LLM inferences/s, sizing rules |
| [`scripts/README.md`](scripts/README.md) | bootstrap, enrollment, certificate rotation, backup, air-gap bundle, health check |
| [`cfgaudit/README.md`](cfgaudit/README.md) | optional offline network-config audits, dedicated NDJSON/OpenSearch contracts, manual Compose ingestion and validation gates |
| [`kubernetes/README.md`](kubernetes/README.md) | Helm chart and Kustomize overlays (dev, onprem, airgap), CoreDNS rewrite for the lab target |
| `<component>/RUNTIME.md` | per-component environment, mounts, ports and probes (`fluent-bit`, `fluentd`, `prometheus`, `ollama`, `llm-gateway`, `errow`, `errow/mcp`, `errow/shipper`, `errow/feedback-loop`, `opensearch`) |

## Quick start (single Docker host)

Prerequisites: Docker Engine with Compose v2, `jq`, `openssl`, `vm.max_map_count >= 262144` on the host
(`sudo sysctl -w vm.max_map_count=262144`), and 4 GB free RAM for the smoke profile (a GPU host for the real models).

```bash
cd vendetta-stack
scripts/bootstrap.sh                       # preflight, secrets/ (0600), pki/ (private CA + leaf certs), .env
docker compose up -d --build --wait        # core: Fluent Bit, 2x Fluentd, OpenSearch, Prometheus, Alertmanager, Grafana,
                                           #       llm-gateway, ollama-lb, errow-mcp, errow-shipper, errow-feedback
scripts/healthcheck.sh                     # one table: every service, port, TLS and certificate expiry
```

Compose profiles add optional parts:

| Profile | Adds |
|---|---|
| `llm` | the real Ollama node (`vendetta-stack/ollama`, pinned `ollama/ollama:0.40.5`); layer `-f docker-compose.gpu.yml` for NVIDIA passthrough |
| `mock-llm` | a mock Ollama for tests and demos without a GPU |
| `dashboards` | OpenSearch Dashboards |
| `errow` | Errow, the Docker-in-Docker sandbox host and the Errow Viewer (`:8765`) |
| `poller` | the periodic `vendetta-to-errow.sh --via-llm` loop (Vendetta alert → LLM plan → Errow MCP scan) |
| `lab` | the deliberately vulnerable scan target `scan-target.vendetta.lab` |
| `manager` | the Vendetta manager (default stand-in image, see below) |
| `nginx-lb` | NGINX instead of HAProxy in front of Ollama (set `OLLAMA_LB_HAPROXY_REPLICAS=0`) |
| `test` | `smoke-runner` and the sink stub used by `tests/smoke-test.sh` |

Real models: `docker compose --profile llm up -d`, then `scripts/enroll-ollama.sh` verifies the Ollama version, the loopback-only
bind and every blob's SHA-256 against [`ollama/models.json`](ollama/models.json) before the node joins the load balancer.
Hosts without CUDA use [`ollama/install-llama.cpp.sh`](ollama/install-llama.cpp.sh) (same pinned SHAs).

## End-to-end smoke test (no GPU, no internet egress from the stack)

```bash
tests/smoke-test.sh                  # bootstrap -> up --wait -> ingest -> pipeline -> guardrails -> mcp -> failover -> metrics -> report -> down -v
tests/smoke-test.sh --keep           # leave the stack running for inspection;  tests/smoke-test.sh --down  to remove it
```

It starts the `mock-llm`, `test` and `lab` profiles with `.env.smoke`, runs [`tests/validate-pipeline.py`](tests/validate-pipeline.py)
inside the compose network and writes `tests/results/{junit.xml,smoke.log,compose.log}`. It proves:

- Vendetta alerts and FIM events, Errow SARIF / runs / threat models reach their OpenSearch indices (`vendetta-alerts-*`, `errow-*`),
  and the SARIF → Vendetta-alert transform keeps `errow.sarif_rule_id`, `rule.id` and severity;
- edge sanitization: control characters stripped, 8,000-character cap, `Bearer` tokens and `password|token|secret|api_key|authorization` redacted;
- `cs3.ai.ollama` journald records appear in the ESOC / SIEM legs and the local safety file, **never** in the Console leg, OpenSearch
  or `/triage` (infinite-triage-loop guard);
- gateway guardrails (injection signatures, `<untrusted_data>` wrapping, strict `AIIncidentAnalysis` schema), the MCP policy matrix
  and the `errow-mcp` bridge in dry-run;
- failover: `nemotron-3-nano:30b` down → Gemma answers with a recorded reason; every model down → `Cecur Heuristics`, `fallback: true`;
- the hash-chained `cs3-ai-audit-*` chain verifies end to end, and `cs3-ai-inference-*` carries tenant, model, role, tokens, latency, GPU-seconds;
- the Errow → Vendetta feedback loop plans (does not perform) isolation and a SOAR ticket, and writes advisory `/forensic` proposals
  that stay `pending_analyst_review`;
- Prometheus targets and rules, Fluentd and gateway metric families.

The smoke run probes the Docker daemon's embedded DNS first. A few daemons (seen on Engine 29.1.3) answer a query with the peer's
address on a network the caller is *not* attached to, which makes healthy multi-homed services unreachable across the stack's six
segmented networks. If the probe fails, the smoke puts every service on one flat network via [`tests/flatten-networks.py`](tests/flatten-networks.py)
(`SMOKE_FLAT_NETWORK=auto|1|0` overrides). Network segmentation is then covered by the Helm NetworkPolicies, not by this run.
Verified so far: a from-scratch run (bootstrap included) passes 49/49 checks on such a daemon. The informational `scripts/healthcheck.sh`
pass at the end of the smoke is expected to WARN, not FAIL, on: Fluentd `monitor_agent` (bound to the container loopback on purpose;
set `FLUENTD_MONITOR_BIND=0.0.0.0` to verify it from the host), a single-node OpenSearch with unassigned replicas, and the mock Ollama
having no model loaded.

## Validation without containers or a cluster

```bash
tests/check-manifest.sh                         # every promised file exists, MCP policy copies identical, models.json keys, no placeholders / legacy brand
scripts/validate-models-json.sh                 # 8 mandatory keys; add --release to refuse the sha256 sentinel
scripts/sync-mcp-policy.sh --check              # llm-gateway/mcp_policy.yaml == errow/mcp/policy.yaml
kubernetes/helm/vendetta-stack/sync-files.sh --check && kubernetes/kustomize/render-base.sh --check
vendetta/tests/test_host_isolate.sh             # active-response isolate hook (PATH stubs, no root needed)
```

Component suites (the validators boot the pinned upstream images in config-test mode): `python -m pytest` in `cfgaudit`,
`fluent-bit/tests/{validate,test_legs}.sh`, `fluentd/tests/{validate,test_routing}.sh`, `prometheus/tests/validate.sh --strict-docs`, `grafana/tests/validate.sh`,
`opensearch/tests/run-tests.sh`, `errow/feedback-loop/tests/test_feedback_loop.sh`, `scripts/tests/test_scripts.sh`,
`python -m pytest` in `llm-gateway`, `errow/mcp` and `errow/shipper`. CI runs all of them:
[`.github/workflows/vendetta-stack-validate.yml`](../.github/workflows/vendetta-stack-validate.yml).

Capacity: `tests/loadgen.py` (rate-limited, stdlib only) drives Fluent Bit or the gateway `/triage`; the procedure and pass criteria are in
[`docs/capacity.md`](docs/capacity.md).

## Kubernetes and air-gap

```bash
helm upgrade --install vendetta kubernetes/helm/vendetta-stack -n vendetta --create-namespace \
  -f kubernetes/helm/vendetta-stack/values-onprem.yaml          # or values-airgap.yaml
kubectl apply -k kubernetes/kustomize/overlays/onprem           # same manifests without Helm
scripts/healthcheck.sh --kubernetes --namespace vendetta
```

Air-gap: `scripts/build-airgap-bundle.sh` (on a connected host) produces a deterministic tar with images, model blobs, the Ollama and
llama.cpp binaries, the chart, `SHA256SUMS`, a CycloneDX SBOM and a cosign signature; `scripts/verify-bundle.sh` checks it inside the enclave
before anything is loaded. `ERROW_SANDBOX_IMAGE_TAR` is mandatory for air-gap installs.

## Vendetta-side hooks

[`vendetta/ossec-hooks.conf`](vendetta/ossec-hooks.conf) is the manager snippet (JSON alerts for Fluent Bit, `host-isolate` active response, no
`custom-` integration needed). [`vendetta/active-response/host-isolate.sh`](vendetta/active-response/host-isolate.sh) isolates / un-isolates a host with
nftables or iptables from the active-response JSON on stdin; it refuses to run without an `isolate-allow.conf` (exit 3) and honours `ISOLATE_DRY_RUN`.

[`vendetta/manager/`](vendetta/manager) is the managed alternative: a reserved rule block (`10120-10199`), decoders for the host-log streams, and a
boot-time (cont-init) stage that splices a loopback syslog receiver into `ossec.conf` so endpoint and network logs pass the manager's rule engine instead of
bypassing it — including journald, where endpoint and container events actually originate. Alerts come back through
`POST /api/cecur/manager/alerts` with rule ID, original event time, device identity and severity preserved. `CS3_MANAGER_FEED_MODE`
owns the CTI feed updater, which otherwise fails against `cti.wazuh.com` on every interval without egress. Enabled with
`CS3_MANAGER_ENABLED=true`; see [`docs/MANAGER-INTEGRATION.md`](docs/MANAGER-INTEGRATION.md).

## Assumptions and known limits

- **Vendetta manager.** `Vendetta Suite.docx` was not available, so the manager image defaults to the Vendetta-compatible stand-in
  `wazuh/wazuh-manager:4.9.2` (`VENDETTA_MANAGER_IMAGE` overrides it). Daemon names, ports 1514/1515/1516/55000, `ossec.conf` and
  `alerts.json` follow the Vendetta-compatible contract in the Phase 1 document.
- **`models.json` digests.** The release manifest carries concrete SHA-256 pins; `validate-models-json.sh --release` and
  `build-airgap-bundle.sh --require-signature` refuse sentinel values. Enrollment must still verify the actual local blobs,
  and any model update requires the controlled repinning and rollback procedure rather than editing a digest in place.
- **Shims.** Errow has no network MCP server, so `errow/mcp/` is a small bridge that exposes `errow/tools/mcp/*` over JSON-RPC, with the same policy
  as the gateway; `errow/shipper/` tails `errow_runs/` and ships NDJSON, because Errow writes atomically rewritten JSON, not JSONL.
- **Fluent Bit 3.2.10** has no `exec` or `winlog` input and does not enforce forward-in client certificates; CLI output and shipper status are tailed
  from files, Windows hosts use the CS3 Windows agent template, and aggregator mTLS is enforced on the Fluentd side
  (Phase 1 §10 lists every deviation).
- **The Fluentd ESOC leg** is OTLP/HTTP-JSON (custom plugins); the Fluent Bit ESOC leg is gRPC. Never enable the same leg in both.
- **Throughput numbers** in the Phase 1 document are planning figures until `docs/capacity.md` has been run on your hardware.
- **Proposals are advisory.** LLM-generated detection rules, remediations, MITRE enrichments and Errow checks are written to
  `proposals.ndjson` as `pending_analyst_review`, `applied: false`; nothing applies them automatically.
- **Not exercised here:** the real Ollama image with a GPU, OpenSearch Dashboards, the 3-node OpenSearch topology (smoke uses `opensearch.single-node.yml`),
  the Vendetta manager's API TLS mount and healthcheck, and the NGINX load balancer outside Docker (its `resolver 127.0.0.11` is Docker-specific).
- Legacy brand names in the original Errow tree were renamed to Errow; the alias handling is documented in Phase 1 §2.
