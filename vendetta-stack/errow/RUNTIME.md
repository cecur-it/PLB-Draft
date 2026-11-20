# errow (+ errow-dind, errow-viewer, errow-feedback) — RUNTIME (CONTRACT §11)
Traces: CONTRACT §2, §4.4, §6, §8. K8s reference manifests: `viewer/deployment.yaml`, `tui/sidecar-deployment.yaml`. Full `errow-feedback` env table: `feedback-loop/RUNTIME.md`. Architecture: `README.md`.

## Build (run from `cecur-it-cs3-v1.1.0/`; compose lives in `vendetta-stack/`)
| Image | Build |
|---|---|
| `vendetta-stack/errow:${STACK_VERSION:-1.0.0}` (services `errow`, `errow-viewer`) | `docker build -f vendetta-stack/errow/Dockerfile.errow --build-context stack=vendetta-stack/errow -t … errow` — compose: `build: {context: ../errow, dockerfile: ../vendetta-stack/errow/Dockerfile.errow, additional_contexts: [stack=./errow]}` (context = READ-ONLY upstream tree; **the `stack` context is mandatory**). Args: `VIEWER_SOURCE=prebuilt/built/external`, `ERROW_PIP_SPEC`, `PIP_INDEX_URL`, `GOPROXY`, `UV_VERSION`. Base python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df, uid/gid 10001, ~800 MB |
| `vendetta-stack/errow-sandbox:${STACK_VERSION}` (`errow_IMAGE`, run INSIDE errow-dind) | 2 steps: upstream `errow/containers/Dockerfile` → `…/errow-sandbox-base`, then `Dockerfile.sandbox --build-arg ERROW_SANDBOX_BASE=…` (adds gobuster 3.8.2 + bbot 3.1.0; base is ~5 GB, unpinned `kali-rolling`: freeze it by digest, `docker save` for air-gap) |
| `errow-dind` | `docker:27-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce` (no build) |
| `vendetta-stack/errow-feedback:${STACK_VERSION}` | `docker build -t … errow/feedback-loop` |

## `errow` — scan runner (no daemon: one-shot CLI)
- **Entrypoint** `tini -- errow-entrypoint`; mode = `--mode` flag > any errow args (⇒ `scan`) > `ERROW_MODE` > `idle`. Compose: `command: ["--mode","idle"]`, scan with `docker compose exec errow errow-entrypoint --mode scan -- --target http://scan-target.vendetta.lab:8080 --scan-mode quick` (profiles `errow`/`lab`).
- **Sets itself** (don't set): `LLM_API_BASE=${LLM_GATEWAY_URL}/v1`, `errow_LLM` (`select_llm_model`: an explicit `errow_LLM` wins, else `openai/${OLLAMA_SECURITY_MODEL}`, else `openai/${OLLAMA_PRIMARY_MODEL}` with `ERROW_MODEL_DEGRADED=true` — both default to the same agentic tag), `LLM_API_KEY`(from file), `LLM_DISABLE_STREAMING=true`, `errow_API_TYPE=chat_completions`, `errow_TELEMETRY`, `errow_APP_URL` (blackholed unless `ERROW_CLOUD_ENABLED`), `errow_IMAGE`, `SSL_CERT_FILE` (system CAs + `/pki/ca.crt`).

| Env | Default | Meaning |
|---|---|---|
| `CS3_PROFILE` | `onprem` | `cloud/onprem/airgap/edge`; anything but `cloud` ⇒ fail closed (exit 78, `FailClosedError`) if a cloud LLM key/endpoint env or `~/.errow/cli-config.json` key is present, or the model is not in `llm-providers.yaml` |
| `OLLAMA_SECURITY_MODEL` / `OLLAMA_PRIMARY_MODEL` | `nemotron-3-nano:30b` / `nemotron-3-nano:30b` | the Errow model and the degraded substitute (the same agentic tag unless a deployment splits them); both must be in `llm-providers.yaml` (exit 78 otherwise) |
| `ERROW_MODEL_DEGRADED` | unset | `true` forces the primary model without a second policy check — set it when the gateway tier has no security model (also exported automatically on a silent downgrade) |
| `LLM_GATEWAY_URL` / `LLM_GATEWAY_TOKEN_FILE` | `https://llm-gateway:9101` / `/run/secrets/llm_gateway_token` | gateway (bearer only: the LLM client sends no client certificate, keep gateway mTLS optional for this service) |
| `ERROW_MODE` `ERROW_TARGET` `ERROW_SCAN_MODE` `ERROW_INSTRUCTION_FILE` `ERROW_FAIL_ON` | `idle`, —, `quick`, —, — | scan inputs (`quick/standard/deep`) |
| `ERROW_ALLOWED_TARGETS` | `$ERROW_TARGETS` (compose/Helm default `scan-target.vendetta.lab`) | host globs a scan target must match (exit 77); extend `ERROW_TARGETS` for real engagements and keep `scripts/check-allowlists.sh` green |
| `ERROW_TELEMETRY` / `ERROW_CLOUD_ENABLED` / `ERROW_CLOUD_URL` | `false` / `false` / `https://app.errow.ai` | opt-in only; `airgap` forces both off |
| `DOCKER_HOST` `DOCKER_TLS_VERIFY` `DOCKER_CERT_PATH` | `tcp://errow-dind:2376` (TLS if `/certs/client/ca.pem`, else `:2375`) `1` `/certs/client` | sandbox daemon; `ERROW_DIND_TIMEOUT=120` wait |
| `ERROW_SANDBOX_IMAGE` / `ERROW_SANDBOX_IMAGE_TAR` | `vendetta-stack/errow-sandbox:${STACK_VERSION}` / — | tar is `docker load`ed into DinD when the image is absent (mandatory in `airgap`) |
| `errow_LLM` | unset | explicit OpenAI-style alias override (`openai/cs3-errow-security`, or a raw approved tag in direct airgap mode); survives the config-file/environment merge |
| `ERROW_CONFIG_FILE` / `ERROW_LLM_PROVIDERS_FILE` | `/etc/errow/errow-config.yaml` / `/etc/errow/llm-providers.yaml` | defaults (environment wins) / model allow-list; baked in the image, mount to override |
| `ERROW_TUI_FORWARD_ADDR` / `_TAG` / `ERROW_TUI_EVENTS_FILE` | `fluent-bit:24225` (`off` disables) / `bridge` / unset | TUI bridge → Fluent Bit forward (interactive sessions only; leave the file mirror unset, the shipper tails `tui_events.ndjson`) |

- **Mounts** `errow-runs`→`/workspace/errow_runs` rw; `errow-ndjson`→`/var/log/errow` rw (`cli.log`, redacted); tmpfs `/home/errow` (uid 10001; Errow writes 0600 secrets via `utils/secret_files.py` under `~/.errow`) and `/tmp`; ro: `/run/secrets/llm_gateway_token`, `/pki/ca.crt`, `/certs/client` (volume `errow-dind-certs`, from errow-dind). Local-source scans (`--target <dir>`) need that dir at the SAME path in errow-dind (daemon-side bind mount).
- **Healthcheck** `errow-entrypoint --healthcheck` (image HEALTHCHECK; idle/scan: fail-closed recheck + DinD ping + gateway TCP). Hardening: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, user 10001. Exit: 64 usage, 66 missing file/secret, 69 DinD/sandbox image, 73 state dir, 77 target, 78 config/FailClosed.
- **Networks** `offensive` (+ `management` for the gateway/Fluent Bit); never `storage`. No published ports (Caido :48080 lives inside sandboxes).

### Model contract and re-pointing

Errow runs on the security tier (`nemotron-3-nano:30b`, `role: errow-security` in `llm-providers.yaml`): the agentic model plans the tool chain,
and its only fallback is `gemma4:31b`, which flags `degraded_model_fallback` and makes the run an analyst-review item. `gemma4:26b` is never in this
chain, and the chain does not reach triage. The gateway refuses `INFERENCE_MODEL_GUARD` = either security tag.

When the security model is absent from the tier (a cut-down or `OLLAMA_PRELOAD_MODELS=none` deployment), the entrypoint downgrades on its own,
prints the reason and sets `ERROW_MODEL_DEGRADED=true`; set that flag deliberately instead of letting the policy check trip. With
`ERROW_LLM_ROUTE=direct` (cloud profile only) there is no gateway to fall back on, so re-point the run by hand: set `errow_LLM=openai/<approved tag>`
to the model you actually provisioned and record the substitution in the run notes. Never point it at a tag that is missing from
`llm-providers.yaml` — the entrypoint fails closed (exit 78) rather than letting Errow 403 mid-scan.

## `errow-dind`
`docker:27-dind` pinned; `privileged: true` (dockerd); `DOCKER_TLS_CERTDIR=/certs` ⇒ certs in volume `errow-dind-certs` (server+client; clients mount `/certs/client` ro); `/var/lib/docker` on volume `errow-dind-data` (≥ 40 GB). Port 2376 (TLS) only on `offensive`. Healthcheck `docker -H unix:///var/run/docker.sock info`. **Sandbox egress = this container's egress**: attach only to `offensive`, which must NOT route to Vendetta 1515/1516 (manager network), Ollama 11434 (`inference` is internal) or OpenSearch.

## `errow-viewer` (same image)
`ERROW_MODE=view` · `errow view <newest run> --host 0.0.0.0 --port 8765 --no-open` · port **8765/tcp** (`ERROW_VIEWER_HOST/_PORT/_FOLLOW=true/_POLL=10/_MIN_RESTART=60`). `errow-runs` mounted **ro**; tmpfs `/home/errow`, `/tmp`; `/var/log/errow` may be a private tmpfs (viewer logs go to stdout). No secrets/egress/gateway needed. Healthcheck: same command (waiting ⇒ healthy, serving ⇒ TCP 8765). Waits for the first run, serves ONE run, restarts on a newer run (token changes). Auth = per-process `?token=` cookie → **one replica**; get the link with `docker compose exec errow-viewer errow-entrypoint --print-viewer-link` (0600 file, redacted in logs; swap host). Put a real auth gate in front (K8s: Ingress basic-auth on a dedicated hostname, no sub-path — frontend uses absolute `/api/*`).

## `errow-feedback` (image above; spec `feedback-loop/RUNTIME.md`)
`python3 /opt/feedback-loop/server.py` · **9102/tcp** (`POST /errow-finding`, `GET /health|/metrics`) · secrets `feedback_webhook_token`, `vendetta_api_password`, `opensearch_admin_password`, `llm_gateway_token`, optional `feedback_approval_key` · volume `feedback-loop`→`/var/log/feedback-loop` rw · healthcheck `python3 /opt/feedback-loop/server.py --healthcheck` · live actions need `ERROW_FEEDBACK_LIVE=true` + a signed `APPROVALS.md` line from `ERROW_FEEDBACK_APPROVAL_THRESHOLD` distinct approvers. Networks `management`+`aggregation`. Schedule `vendetta-to-errow.sh --via-llm` (60 s loop/CronJob).

## K8s notes
- Probes: exec `errow-entrypoint --healthcheck` (no HTTP). `errow`/`errow-viewer`/`errow-feedback` are single-replica `Recreate`. `errow-runs` must be RWX (or co-scheduled): errow rw, viewer/mcp/shipper ro.
- DinD needs `privileged`; safer: Sysbox (`runtimeClassName: sysbox-runc`) or Kata. NetworkPolicy of the errow-dind pod = sandbox policy: allow only DNS and lab targets (default deny ⇒ 1514–1516, 11434, 9200, 9101 blocked); allow ingress 2376 only from `errow`, `errow-mcp`, `errow-shipper`.
- TUI bridge cannot be a separate container: Errow↔TUI IPC is an inherited socketpair FD (`errow_TUI_FD`; Windows: loopback `errow_TUI_ADDR`+`errow_TUI_TOKEN`) — the bridge is installed as `errow/bin/errow-tui` in the errow container and forwards metadata over TCP to `fluent-bit:24225`.
