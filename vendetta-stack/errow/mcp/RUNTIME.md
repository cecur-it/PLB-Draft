# errow-mcp — RUNTIME (CONTRACT §11)
Traces: PROMPT §2.3; CONTRACT §2 (:9103 mTLS), §4.5 (MCP policy), §8.4/§15 (`mcp_events`). Spec of the server: `mcp-server.yaml`.

**Build** `docker build -t vendetta-stack/errow-mcp:${STACK_VERSION:-1.0.0} errow/mcp` (context = `errow/mcp/`, `Dockerfile`, base pinned by digest, Python 3.12, uid/gid 10001).
**Run** `ENTRYPOINT python /app/server.py` (flags: `--healthcheck`, `--selftest` = plan every tool dry, rc 0, no Docker; `--version`).
**Port** 9103/tcp, HTTPS only, mTLS `verify required` (TLS ≥ 1.2, CA `/pki/ca.crt`). `POST /mcp` JSON-RPC 2.0 (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`; stateless, JSON replies, GET/DELETE → 405); `GET /health`; `GET /metrics`.
Every endpoint needs a client cert signed by the CA. `POST /mcp` additionally needs a cert CN/SAN in `MCP_ALLOWED_CLIENTS`; `/health` and `/metrics` accept any CA-signed client (Prometheus scrapes with its own cert).

## Env (name = default → meaning)
| Var | Default | Meaning |
|---|---|---|
| `MCP_LIVE` | `false` | exactly `true` → run tools in sandboxes; else dry-run plan (argv + sandbox spec), Docker never touched |
| `DOCKER_HOST` | unset | **required for live**: `tcp://errow-dind:2376`; live is refused without it (never the host socket). TLS: `DOCKER_TLS_VERIFY=1`, `DOCKER_CERT_PATH=/certs/client` (`ca.pem cert.pem key.pem`) |
| `errow_IMAGE` (alias `ERROW_IMAGE`) | unset | **required for live**: Errow sandbox image (`errow/Dockerfile.sandbox`, has gobuster+bbot), present inside the DinD daemon |
| `MCP_SANDBOX_NETWORK` / `_CREATE` | `offensive` / `true` | network INSIDE the DinD daemon (auto-created as plain bridge). Refused if named host/bridge/default/edge/aggregation/storage/management/inference or if vendetta/opensearch/ollama/gateway/fluent/errow-* containers are attached |
| `MCP_POLICY_FILE` | `/app/policy.yaml` | baked copy of `llm-gateway/mcp_policy.yaml` (byte-identical) |
| `MCP_TARGETS_FILE` | unset | YAML `{hostnames: [], cidrs: [], domains: [], repo_paths: []}`; only ADDS targets, never relaxes `denied`/tools/limits |
| `MCP_ALLOWED_CLIENTS` | `llm-gateway,errow,errow-mcp` | client cert names allowed on `/mcp` (`*` = any CA-signed) |
| `MCP_PKI_DIR` / `MCP_PORT` / `MCP_BIND` | `/pki` / `9103` / `0.0.0.0` | cert dir (`ca.crt`, `errow-mcp.crt`, `errow-mcp.key`; reloaded on mtime change) |
| `MCP_REPOS_SOURCE` | unset | host path or named volume mounted **ro** at `/workspace/repos` in the trufflehog sandbox (network none); required for trufflehog live |
| `MCP_WEB_SEARCH_KEY_FILE` / `_PROVIDER` / `MCP_WEB_SEARCH_NETWORK` | unset / `exa` / sandbox net | provider key file (never argv); without it `web_search` → `unconfigured` |
| `MCP_SANDBOX_MEM_LIMIT` `_CPUS` `_PIDS_LIMIT` `_SHM_SIZE` `_TMPFS_SIZE` | `1g` `1.0` `256` `64m` `128m` | per-sandbox cgroup limits |
| `SANDBOX_NMAP_CAPS` / `SANDBOX_USER` / `SANDBOX_TMPFS` | `NET_RAW,NET_ADMIN,NET_BIND_SERVICE` / `pentester` / unset | nmap cap set (see deviations), sandbox user, extra tmpfs paths |
| `MCP_OUTPUT_MAX_BYTES` `MCP_MAX_BODY_BYTES` `MCP_MAX_CONNECTIONS` `MCP_READ_TIMEOUT_S` | `1048576` `65536` `128` `15` | output cap, request cap, thread bound, socket read timeout |
| `MCP_EVENTS_FILE` / `_MAX_BYTES` / `_KEEP` | `/var/log/errow/mcp_events.ndjson` / `52428800` / `5` | audit stream; rotates itself (rename `.1`…, keeps N) |
| `ERROW_RUNS_DIR` | `/workspace/errow_runs` | read by `threat_model`/`coverage`; `proxy` targets the newest run sandbox (`MCP_PROXY_RUN_ID` pins one) |

## Files and mounts
`/pki` **ro** (`ca.crt`, `errow-mcp.crt`, `errow-mcp.key`; key must be readable by uid 10001 — bootstrap mode 0600 owned by root will NOT work → chown 10001 or K8s `defaultMode 0440` + `fsGroup 10001`).
`/var/log/errow` **rw** = volume `errow-ndjson` (bridge appends `mcp_events.ndjson`; shipper writes the other streams; Fluent Bit reads ro). Mount an empty named volume over a dir owned by 10001 (image pre-creates it) or chown it.
`/workspace/errow_runs` **ro** = volume `errow-runs`. `/certs/client` **ro** (DinD client TLS). `/tmp` tmpfs (Python needs none; optional).
Secrets: only `MCP_WEB_SEARCH_KEY_FILE` (e.g. `/run/secrets/…`). No tokens in env or logs.

## Networks, security
Attach to the network that reaches `errow-dind` and that resolves `scan-target.vendetta.lab` (DNS is resolved by the bridge and **fail-closed**: unresolvable targets are denied; the sandbox is pinned to the validated IP via `extra_hosts`). The bridge itself needs no access to Vendetta 1514-1516/55000, OpenSearch or Ollama. Sandboxes join `offensive` inside DinD only.
`read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, user `10001:10001`; no privileged, no host mounts, no docker.sock.
Sandbox spec per call: read-only rootfs, `cap_drop ALL` (+ nmap caps / `NET_RAW` for `ping`), no-new-privileges, pids 256, 1 GiB, 1 CPU, noexec tmpfs, `AutoRemove`, killed at the policy timeout, label `vendetta.component=errow-mcp-exec`.

## Healthcheck
`HEALTHCHECK CMD ["python","/app/server.py","--healthcheck"]` (stdlib `urllib`, mTLS with `/pki/errow-mcp.{crt,key}` to `https://localhost:9103/health`; rc 0 = ok). No curl in image.
K8s: **exec probes** with the same command (kubelet HTTP probes cannot present a client cert); 1 replica (rate limits are in-process); manifests in `k8s.yaml` (Deployment, Service `errow-mcp:9103`, NetworkPolicy, PDB).

## Observability
Logs: JSON lines on stdout, no secrets. Metrics: `errow_mcp_calls_total{tool,status}`, `errow_mcp_call_duration_seconds` (histogram), `errow_mcp_sandbox_running`, `errow_mcp_policy_denied_total{tool,reason}`, `errow_mcp_live`, `errow_mcp_event_write_errors_total`, `errow_mcp_tls_failures_total`, `errow_mcp_client_rejected_total`, `errow_mcp_build_info`.
Policy results are `isError:true` tool results, `structuredContent.status` = `policy_violation|rate_limited|dry_run|executed|error`; `violations[]` strings are `<category>:<detail>` (`tool:unknown`, `role:*`, `arg:<name>:<rule>`, `forbidden_arg:<tok>`, `forbidden_tag:<v>`, `target:denied_cidr|denied_host|denied_port|unresolvable|not_allowed|malformed`, `rate:*`). Role comes from `params._meta.role` (`triage|forensic`).

## Deviations / notes
nmap sandbox gets `NET_RAW,NET_ADMIN,NET_BIND_SERVICE` (the image's `setcap +eip nmap` fails exec otherwise). bbot also gets `-rf passive`. Screenshots live in sandbox tmpfs (die with the container). Errow's own MCP client speaks Bearer-only HTTP, so the supported caller is `llm-gateway` (mTLS).
