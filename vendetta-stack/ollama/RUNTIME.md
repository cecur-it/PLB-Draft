# ollama tier — RUNTIME (CONTRACT §8.1, §8.2, §11)

Four runnable components: **1 ollama**, **2 ollama-proxy**, **3 ollama-lb**, **4 mock-ollama**. Build context = `ollama/`. Images are pinned `name:tag@sha256` (CONTRACT §1).
Path: `llm-gateway ⇄ ollama-lb (127.0.0.1:11434, gateway netns) ⇒ mTLS ⇒ ollama-workers:11443 (ollama-N-proxy) ⇒ 127.0.0.1:11434 (ollama-N | mock-ollama)`.

## 1. ollama — compose `ollama-1` (profile `llm`), `image: vendetta-stack/ollama:${STACK_VERSION}` (built locally)
- Build: `docker build -f ollama/Dockerfile.ollama -t vendetta-stack/ollama:${STACK_VERSION:-1.0.0} ollama/` (base `ollama/ollama:0.40.5@sha256:5d3a2f25f9825628daba94dc0b1d421c7d57d6c03ae5faa9ba050e058bab8241`, user `10001:10001`, `HOME=/var/lib/cs3-ollama`).
- Entrypoint `/usr/local/bin/entrypoint.sh`, default CMD `serve`: starts `ollama serve`, waits ≤ `OLLAMA_READY_TIMEOUT`, then `pull-models.sh --from-models-json --profile $CS3_PROFILE`. Other args go to the `ollama` CLI.
- Ports: none published. API is `127.0.0.1:11434` inside the netns (reachable only by the proxy sibling). Attach the **worker** (not the proxy) to `inference` with alias `ollama-workers`.
- Env (name = default — meaning):
  - `CS3_PROFILE` = `onprem` — cloud, onprem, airgap or edge; **airgap never pulls**.
  - `OLLAMA_PRELOAD_MODELS` = unset → `$OLLAMA_PRIMARY_MODEL,$OLLAMA_FALLBACK_MODEL,$OLLAMA_SECURITY_MODEL,$INFERENCE_MODEL_REASONING_DEEP` (edge: fallback, security, then deep); CSV of approved tags, `all` or `none`. The shipped default provisions all three production models, including the Gemma 31B security/Errow fallback.
  - `OLLAMA_PRIMARY_MODEL` = `nemotron-3-nano:30b`, `OLLAMA_FALLBACK_MODEL` = `gemma4:26b`, `OLLAMA_SECURITY_MODEL` = `nemotron-3-nano:30b`
    (security shares the agentic tag; only its chain, budget and cache flag differ). `eval`-tier models such as the optional
    `qwensploit-v2:9b` are pulled only when listed in `OLLAMA_PRELOAD_MODELS`.
  - Models carrying an `upstream` in models.json (`hf.co/xtools-at/Qwensploit-V2-9B-CyberSecurity-Qwen3.5-GGUF:Q4_K_M` for the optional eval model) are pulled
    from that Hub tag and then registered under the approved id (`ollama create` from the baked Modelfile, else `ollama cp`); the digest pin is
    verified against the source blobs either way.
  - `OLLAMA_AIRGAP_BUNDLE_DIR` = unset — dir with `<tag, ':'→'_'>.gguf` (e.g. `gemma4_26b.gguf`); loaded with `ollama create`, sha256 checked against models.json (sentinel refused).
  - `OLLAMA_PRELOAD_STRICT` = `true` — exit non-zero when provisioning fails (integrity failures are always fatal). `OLLAMA_READY_TIMEOUT` = `120` s.
  - `OLLAMA_HOST` = `127.0.0.1:11434` (keep loopback), `OLLAMA_MODELS` = `/var/lib/cs3-ollama/.ollama/models`, `OLLAMA_NOHISTORY` = `1`, `TMPDIR` = `/tmp`.
  - `OLLAMA_KEEP_ALIVE` = `30m`, `OLLAMA_NUM_PARALLEL` = `4` (must equal LB per-server `maxconn`), `OLLAMA_MAX_LOADED_MODELS` = `3` (the preload set is three models).
- Files read: baked `/opt/cs3/models.json` (override `OLLAMA_MODELS_JSON`), `/opt/cs3/modelfiles/*.Modelfile`. No PKI/secrets (TLS lives in the proxy).
- Volumes: `ollama-models:/var/lib/cs3-ollama` **rw** (plan ≥ 90 GB for all four models); air-gap: `${OLLAMA_AIRGAP_BUNDLE_DIR}:/bundle:ro` + `OLLAMA_AIRGAP_BUNDLE_DIR=/bundle`.
- Healthcheck: `["CMD","/usr/local/bin/entrypoint.sh","--healthcheck"]` (`ollama list` works AND every model of the preload set is present); `interval 15s, timeout 10s, retries 5, start_period 600s` (first pull; raise on slow links, 60s for airgap/`none`). The image has no curl.
- Hardening: `user: "10001:10001"`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true` + `tmpfs: [/tmp]` (mechanics verified on a stub base; the real 3.8 GB image was not run in CI).
- GPU (`docker-compose.gpu.yml`): `deploy.resources.reservations.devices: [{driver: nvidia, count: all, capabilities: [gpu]}]` (host needs nvidia-container-toolkit). K8s: `resources.limits."nvidia.com/gpu": 1` (+ NVIDIA device plugin, optional `runtimeClassName: nvidia`).
- K8s: StatefulSet, PVC on `/var/lib/cs3-ollama`; containers `ollama` + `ollama-proxy` in ONE pod (shared netns); headless Service `ollama-workers` → port 11443. `startupProbe`/`readinessProbe`: exec `/usr/local/bin/entrypoint.sh --healthcheck` (failureThreshold × period ≥ 600 s); `livenessProbe`: exec `ollama list`.

## 2. ollama-proxy — compose `ollama-1-proxy` (real worker) and `mock-ollama-proxy` (mock)
- Image `haproxy:3.0-alpine@sha256:d2b3567d836f3b7d174edb6d6f611ed5308e7966e53a9cd9a597e0415a298efd` (no build); command = image default (`haproxy -f /usr/local/etc/haproxy/haproxy.cfg`).
- `network_mode: service:ollama-1` (K8s: sidecar). Listens `0.0.0.0:11443` (mTLS, `verify required`, CA `/pki/ca.crt`, cert `/pki/ollama-1.pem`) → `127.0.0.1:11434`; plain `127.0.0.1:8405/healthz` (loopback only). Publish nothing.
- Denies `/api/{pull,push,create,delete,copy,blobs}`, admin paths and anything outside the inference allowlist with 403.
- Env: none. Mounts (ro): `ollama/ollama-lb/worker-proxy.cfg:/usr/local/etc/haproxy/haproxy.cfg`, `$STACK/pki:/pki`. The image runs as uid 99: `/pki/ollama-1.pem` and `ca.crt` must be readable by it (e.g. `chgrp 99` + `0640`) or set `user: "0"`.
- Healthcheck: `["CMD","wget","-q","-O","/dev/null","http://127.0.0.1:8405/healthz"]` (fails when the local Ollama check is down). K8s: exec probe (`wget` as above) — the port is loopback-only, so `httpGet` cannot reach it.
- Hardening: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges` — verified with the real image.

## 3. ollama-lb — compose `ollama-lb` (HAProxy default) / `ollama-lb-nginx` (profile `nginx-lb`)
- **HAProxy**: same image as §2, config `ollama/ollama-lb/haproxy.cfg` → `/usr/local/etc/haproxy/haproxy.cfg:ro`, `$STACK/pki:/pki:ro` (needs `ollama-lb.pem`, `ca.crt`, readable by uid 99). `network_mode: service:llm-gateway` (K8s: sidecar of the gateway pod).
- Ports (gateway netns): `127.0.0.1:11434` API; ops `127.0.0.1:8404` → `/healthz` (liveness only: 200 even with 0 workers so the gateway can boot and degrade to heuristics), `/ready` (503 until ≥ 1 healthy worker), `/metrics` (Prometheus), `/stats`.
- Behaviour: workers from DNS `ollama-workers:11443` (`server-template 1-8`, `resolvers sys parse-resolv-conf init-addr none`), `leastconn`, `maxconn 4`/server, `timeout queue 30s`, 429 when queue > 32, `httpchk GET /api/tags`, verifies hostname `ollama-1`. Env: none.
- Healthcheck: `["CMD","wget","-q","-O","/dev/null","http://127.0.0.1:8404/healthz"]`; readiness (K8s/compose gate): `…:8404/ready` via an exec `wget` probe (loopback-only port; `httpGet` cannot reach it). Hardening as §2.
- **NGINX variant**: `nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`, `nginx.conf` → `/etc/nginx/nginx.conf:ro`, same `/pki` mount (`ollama-lb.crt`, `ollama-lb.key`, `ca.crt`), same netns/ports; ops `127.0.0.1:8404` serves `/healthz` and `/stub_status` only (no `/ready`). Passive failover (`max_fails=2 fail_timeout=15s`).
  Hardening: `read_only: true` + `tmpfs: [/tmp]`, `cap_drop: [ALL]` + `cap_add: [CHOWN, SETGID, SETUID]` (verified; without them nginx refuses to start). `resolver 127.0.0.11` is Docker DNS — **change it to the cluster DNS IP on Kubernetes**. Healthcheck: same `wget …:8404/healthz`.

## 4. mock-ollama — compose `mock-ollama` (profile `mock-llm`, CI default) + `mock-ollama-proxy`
- No Dockerfile: image `python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df`, mount `ollama/mock/mock_ollama.py:/app/mock_ollama.py:ro`, command `python /app/mock_ollama.py` (stdlib only). `user: "65534:65534"`, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges` (verified).
- Same netns pattern as §1: attach the mock to `inference` with alias `ollama-workers`; `mock-ollama-proxy` (§2, same `/pki/ollama-1.pem`) uses `network_mode: service:mock-ollama`.
- Port `127.0.0.1:11434` (`MOCK_BIND`): `/v1/chat/completions`, `/v1/models`, `/api/tags` (4 approved models), `/api/version` → `{"version":"0.40.5"}`, `/metrics`, `/__control`.
- Env: `MOCK_BIND` = `127.0.0.1:11434`; `MOCK_DOWN_MODELS` = empty (CSV of tags that answer HTTP 503); `MOCK_LATENCY_MS` = `0`; `MOCK_TOOL_TARGET` = `scan-target.vendetta.lab` (nmap target of the nemotron `toolCalls`).
- Control (loopback only; 403 for non-loopback peers or `Forwarded`/`X-Forwarded-*` headers, and both proxies deny it, so use exec; the image has no curl/wget):
  `docker compose exec mock-ollama python -c "import urllib.request as u; print(u.urlopen(u.Request('http://127.0.0.1:11434/__control', b'{\"down_models\":[\"gemma4:26b\"]}')).read().decode())"`; body `{"reset":true}` restores health (also clears extras `bad_output_models`, `latency_ms`).
- Healthcheck: `["CMD","python","/app/mock_ollama.py","--healthcheck"]` (exit 0 when `/api/version` answers 0.40.5). K8s: exec the same command; the pod also needs the §2 sidecar. Models in the down state still answer `/api/tags`; only chat returns 503.
- Verified e2e (`ollama/tests/validate-lb-configs.test.sh`): mock ← worker-proxy ← ollama-lb with mTLS, 403 denials, `/ready`, 503 pass-through.
