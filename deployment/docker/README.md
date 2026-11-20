# deployment/docker

Docker Compose stack for local / single-host on-prem CS3: console, PostgreSQL (JSONB, RLS-protected
audit ledger), two Ollama nodes behind an NGINX (or HAProxy) load balancer, optional OpenSearch.

```bash
cp .env.example .env            # then fill JWT_SECRET, POSTGRES_*, CS3_*_PASSWORD
docker compose up -d --build     # builds the versioned console from packaged source
docker compose --profile pull-models up ollama-init   # connected profiles only
curl -fsS http://localhost:3000/api/health
```

The preloader uses the pinned Ollama release and `OLLAMA_PRELOAD_MODELS` (default `nemotron-3-nano:30b,gemma4:26b,gemma4:31b`) on both Ollama nodes. The wizard-generated role variables select those models for triage, forensic/guard, security/Errow, and deep reasoning respectively. Qwensploit is evaluation-only and is not preloaded by default.

## Optional Errow connector

`ERROW_BASE_URL` and `ERROW_API_KEY` configure the remote Errow `/api/tasks` service; Ollama does not implement that contract. For on-prem installations, `on-prem/bin/prepare-compose-env.sh` imports a non-loopback URL and existing key from the root environment without printing the key, and selects `ERROW_MODE=remote`. It deliberately skips root loopback URLs because loopback inside the console container is not the Docker host. Set a container-reachable URL in this directory's `.env` instead. A blank URL leaves Errow unconfigured and never simulates results. The current task connector has no `ERROW_MODEL` option; model selection belongs to the Errow service.

| File | Purpose |
|---|---|
| `docker-compose.yml` | Base stack. Profiles: `siem`, `haproxy`, `pull-models`. |
| `docker-compose.gpu.yml` | NVIDIA GPU pinning (one GPU per Ollama node). |
| `docker-compose.supabase.yml` | Supabase self-hosted Postgres image profile. |
| `postgres/init/` | `001_roles.sh`, `002_schema.sql`, `003_audit_protection.sql`, `004_notify.sql`, `005_migrate_hexstrike_to_errow.sql` (idempotent rename for standing DBs). Executed on first start. |
| `postgres/tests/` | `audit_tamper_test.sql` — proves AU-9 protections. |
| `ollama-lb/` | `nginx.conf` (passive checks) and `haproxy.cfg` (active checks, queue backpressure). |

## Podman

`podman compose up -d` (Podman ≥ 4.7 with the compose provider) or `podman-compose up -d`.
Rootless notes: ports < 1024 need `sysctl net.ipv4.ip_unprivileged_port_start=80`; for GPUs use CDI
(see comments in `docker-compose.gpu.yml`); add `:Z` to bind mounts on SELinux hosts, e.g.
`./postgres/init:/docker-entrypoint-initdb.d:ro,Z`.

## Air-gap

Set `CS3_PROFILE=airgap`, pre-load images with
`docker load` / `podman load`, and import models from the verified bundle
(`../operations/model-update-rollback.md`). Do **not** use the `pull-models` profile.

## Re-initialising Postgres

Init scripts only run on an empty data volume. `docker compose down -v` destroys data — never
do this in production; schema changes go through new numbered migrations run as `cs3_migrator`.

## Operational notes

- **Code changes need a new image.** The console runs the compiled bundle in `/app/dist` from
  `CS3_CONSOLE_IMAGE` (default `cs3-soc-console:1.1.0`) with no source bind mount. Compose builds it
  from `demo/demo-100226`; its Node base is pinned by digest. Run `docker compose up -d --build`
  after editing the console. A registry replacement should use an explicit image digest. This
  source-build context requires a repository checkout; other deployment packagings must stage it
  separately or supply an available pinned registry image.
- **Loopback and proxy boundary.** The console publishes to `127.0.0.1` by default (`CS3_CONSOLE_BIND`) for the Host NGINX proxy. Compose sets `CS3_TRUST_PROXY_HOPS=1` for that single known hop, preserving client-IP rate limiting without trusting arbitrary forwarding chains. Direct local development uses `0`.
- **Real data only.** Nothing is seeded or simulated, and `CS3_DEMO_MODE=true` fails console startup.
  The console starts empty; agents, logs, scan results and the `PLB_Assets.csv` inventory (mounted or via
  `PLB_ASSETS_CSV`) are the only data sources. The old `POST /api/system/reseed` was removed.
- **Port 11434 conflicts.** A host Ollama service can hold the port. Run `ss -ltnp | grep 11434`, then
  `sudo systemctl disable --now ollama` (or `mask` it) before starting the stack.
