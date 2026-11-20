# ollama/ — sovereign LLM tier of the vendetta-stack

Everything the on-prem / air-gapped AI tier needs: pinned **Ollama 0.40.5** workers, the mTLS worker proxy, the load balancer in front of the gateway, a `llama.cpp` CPU fallback, host installers, and a deterministic mock for CI.
Traces: PROMPT §1 Tier 4, §2.4; CONTRACT §8.1, §8.2, §10, §11. Runtime facts for the deploy agent: [`RUNTIME.md`](RUNTIME.md).

## Model → role → node

Source of truth: [`models.json`](models.json) (CS3 `onboarding/models.json` format). `detect-hardware.mjs` reads the thresholds from it.

| Model | Role | Tier (`models.json`) | Node it is meant for | Thresholds |
|---|---|---|---|---|
| `nemotron-3-nano:30b` | **Triage** — fast AIIncidentAnalysis, function calling (nmap via the gateway tool policy, `needsVerification`) | `agentic` | GPU node, ≥ 24 GB VRAM / 64 GB RAM | 30B total / 3.5B active |
| `gemma4:26b` | **Forensic** (default) and edge fallback; entry node runs triage + forensic on this one model | `entry` | GPU node, ≥ 16 GB VRAM / 32 GB RAM | 26B total / 4B active |
| `gemma4:31b` | **Forensic upgrade** — deeper reasoning, `proposedDetectionRule` / `proposedRemediation` | `frontier` | GPU node, ≥ 24 GB VRAM / 64 GB RAM (same node class as nemotron) | 31B dense |
| `qwensploit-v2:9b` | *Optional* **evaluation** model — exploit/CVE reasoning ablation. Not pulled by default and in no production chain | `eval` | any node that runs security work, ≥ 8 GB VRAM / 32 GB RAM | 9B dense, Q4_K_M |
| `llama.cpp` (`llama-server`, GGUF) | **CPU fallback** for nodes with no usable CUDA/Metal accelerator; serves the entry-tier GGUF on the same `127.0.0.1:11434` | — | CPU only / unknown or non-CUDA GPU | `install-llama.cpp.sh` |

Security and Errow run on the agentic tier (`nemotron-3-nano:30b`) with `gemma4:31b` as their only fallback; the CVE/ATT&CK/playbook knowledge is expected from the tool loop and the retrieval index, not from a fine-tune. Defaults: `OLLAMA_PRIMARY_MODEL=nemotron-3-nano:30b` (`INFERENCE_MODEL_TRIAGE`), `OLLAMA_FALLBACK_MODEL=gemma4:26b` (`INFERENCE_MODEL_FORENSIC`, may be `gemma4:31b`). No other tag is ever pulled: `pull-models.sh` refuses anything outside the approved set (exit 3).

```bash
node ollama/detect-hardware.mjs --text      # which backend/models fit this host (JSON without --text)
```

## Failover cascade

The gateway (`llm-gateway`, sole client of `127.0.0.1:11434`) degrades step by step per spec §1 Tier 4:

1. **Triage** model (`nemotron-3-nano:30b`) answers → normal path.
2. Triage unavailable / 503 / invalid output → retry on the **forensic** model (`gemma4:26b` / `gemma4:31b`).
3. Nothing answers (or `ollama-lb` `/ready` = 503) → the gateway falls back to **deterministic heuristics**; it never calls a cloud API in `onprem`/`airgap` (FailClosed, CONTRACT §2).

Below the gateway, `ollama-lb` adds worker-level failover: active `GET /api/tags` checks, `leastconn`, `maxconn 4` per worker (= `OLLAMA_NUM_PARALLEL`), a bounded queue (`timeout queue 30s`, HTTP 429 beyond 32 waiting) so concurrent requests cannot thrash a worker's KV-cache. `mock/mock_ollama.py` reproduces every step in CI: `POST /__control {"down_models":["nemotron-3-nano:30b"]}` makes a model answer 503.

`ollama-lb` and the worker proxy answer **403** to `/api/pull|push|create|delete|copy|blobs`, admin paths and anything outside the inference allowlist: models are provisioned on the worker, never through the LB.

## Layout

| Path | Purpose |
|---|---|
| `install-ollama.sh`, `cs3-ollama.service`, `com.cecur-it.cs3-ollama.plist`, `cs3-ollama.logrotate`, `cs3-ollama.newsyslog.conf` | host install (Linux systemd / macOS launchd): pinned binary, service account `cs3-ollama` / `_cs3-ollama`, loopback bind, `--status`, `--uninstall [--purge]`, `--verify-loopback` |
| `install-llama.cpp.sh`, `cs3-llama-cpp.service` | non-CUDA fallback: verified `b4000` source, static CPU build, sandboxed unit bound to `127.0.0.1:11434` |
| `Dockerfile.ollama`, `entrypoint.sh`, `pull-models.sh`, `modelfiles/` | worker image (`vendetta-stack/ollama`): serve, wait ready, provision per profile |
| `ollama-lb/{haproxy.cfg,nginx.conf,worker-proxy.cfg}` | LB (HAProxy default, NGINX variant) and worker-side mTLS terminator |
| `mock/` | stdlib-only mock Ollama for CI (`mock-llm` profile) |
| `detect-hardware.mjs` | hardware probe → backend/model recommendation |
| `tests/`, `*.test.mjs`, `mock/test_mock_ollama.py` | test suites (below) |

The `cs3-ollama.service` sandbox has exactly 15 directives: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `CapabilityBoundingSet=` (empty), `MemoryDenyWriteExecute`, `RestrictSUIDSGID`, `SystemCallFilter=@system-service`, `LockPersonality`, `RestrictRealtime`, `RestrictAddressFamilies`, `PrivateDevices=false` (GPU access). `MemoryDenyWriteExecute=true` blocks JIT: if a CUDA driver/runtime combination aborts with it, flip it in a drop-in and record the exception — do not weaken the unit file.

## Air-gap flow

1. **Connected staging host** — pull the three approved models and put each weight blob into a bundle directory as `<tag with ':' → '_'>.gguf` (`gemma4_26b.gguf`, `gemma4_31b.gguf`, `nemotron-3-nano_30b.gguf`), optionally with a `digests.json` (`{tag: sha256}`); then pin the digests (next section).
2. **Transfer** the bundle (plus the pinned `models.json` and, for CPU nodes, the `llama.cpp` source archive) over the approved medium.
3. **Target host / container** — `CS3_PROFILE=airgap` and `OLLAMA_AIRGAP_BUNDLE_DIR=<bundle>`. `pull-models.sh` **never pulls**: it hashes each GGUF, compares with `models.json`, runs `ollama create` with the repo `modelfiles/` parameters and re-verifies the stored blob. The `<pinned-per-release>` sentinel is refused in this mode. With no bundle mounted the worker only serves what is already in its store.
4. Host installs use `install-ollama.sh --offline-binary <tgz> --offline-sha256 <hex>` (network access refused) and `install-llama.cpp.sh --offline-binary …`.

## How digests are pinned

`models.json` ships the documented `"sha256": "<pinned-per-release>"` sentinel. A release pins real digests, then CI refuses a sentinel:

```bash
node scripts/pin-model-digests.mjs --from-bundle <bundle-dir>          # or --digests digests.json / --registry (staging only)
node scripts/pin-model-digests.mjs --from-bundle <bundle-dir> --check  # no writes; exit 1 on drift or unpinned models
scripts/validate-models-json.sh --release                              # fails (exit 8) if any sentinel remains
```

A model entry may carry `upstream` (the Hub tag it actually comes from, e.g. `hf.co/xtools-at/Qwensploit-V2-9B-CyberSecurity-Qwen3.5-GGUF:Q4_K_M`). `pull-models.sh` then pulls that tag and registers the approved local id from the baked Modelfile (or `ollama cp`), and `pin-model-digests.mjs` resolves the digest against the upstream host instead of the library path. The local id is what `models.json`, the tiers, the gateway and Errow all see.

The pin is deterministic (stable key order, `updated` untouched unless `--updated`/`SOURCE_DATE_EPOCH`). `validate-models-json.sh` (exit codes 0 ok, 2 usage, 3 JSON, 4 schema, 5 approved set, 6 tiers, 7 sha format, 8 sentinel in `--release`) checks the 8 mandatory keys, types, the exact approved tag set and tier references; CI runs it on every change.

## Load-balancer topologies

Topologies, health semantics and the compose/Kubernetes wiring follow CS3 §4.5 (Ollama load balancing); the original CS3 material is [`deployment/docker/README.md`](../../deployment/docker/README.md) and [`deployment/docker/ollama-lb/`](../../deployment/docker/ollama-lb/). Here: HAProxy (active checks, queue back-pressure) is the default, NGINX (passive `max_fails`) is the `nginx-lb` variant; both sit in the `llm-gateway` network namespace on `127.0.0.1:11434` and reach workers over mTLS on `ollama-workers:11443`.
HAProxy `/healthz` (ops listener `127.0.0.1:8404`) is **liveness only** — 200 even with no workers, so the gateway boots and degrades to heuristics; gate on `/ready` (503 until one worker passes `/api/tags`).

Notes: `llama-server` has no `/api/tags` or `/api/version`; probe `/v1/models` on CPU nodes. The LB checks `/api/tags` only, while the worker image healthcheck also proves the preloaded models exist.

## Tests

```bash
cd ollama && export TMPDIR=$PWD/.scratch && mkdir -p "$TMPDIR"
node --test detect-hardware.test.mjs tests/pin-model-digests.test.mjs
python3 -B -m unittest discover -s mock -p 'test_mock_ollama.py'
for t in validate-models-json install-ollama install-llama-cpp pull-models; do tests/$t.test.sh; done
tests/validate-lb-configs.test.sh      # needs docker + openssl: haproxy -c / nginx -t on the pinned images + mTLS e2e
shellcheck -x *.sh tests/*.sh ../scripts/validate-models-json.sh
```
