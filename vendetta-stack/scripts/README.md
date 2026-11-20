# vendetta-stack operator scripts

Production helpers for the Vendetta XDR/SIEM + Errow + sovereign Ollama stack.
Traceability: `PROMPT §3 Phase 3 scripts/*`, `CONTRACT §0/§1/§2/§4.5/§8.6/§9/§12`; air-gap bundle parity with
CS3 §3.3 (`SHA256SUMS` + CycloneDX SBOM + cosign).

Every script is `bash`, `set -euo pipefail`, shellcheck-clean (`shellcheck -x`), supports `--help`, and
every script that mutates supports `--dry-run`. Secrets are read from files only (never argv, never logged).
Colour is disabled when stdout is not a TTY or `NO_COLOR` is set. Network calls retry with exponential backoff.
Scratch space is `$STACK/.scratch` (git-ignored), never `/tmp` (`VS_WORK_ROOT` overrides).

## Scripts

| Script | Purpose | Mutates | Exit codes |
|---|---|---|---|
| `bootstrap.sh` | preflight, secrets, `secrets/approval/` dir, PKI, `.env`; `--check` validates without writing | yes | 0 ok · 1 fail · 2 usage · **3 FailClosedError** · 4 preflight · 5 `--check` problems |
| `enroll-agent.sh` | enroll a host as a Vendetta agent (agent-auth / native authd 1515 / API 55000) and set up its Fluent Bit edge forwarder (TLS) | yes | 0 · 1 · 2 · 3 policy · 4 prereq · 5 manager unreachable/refused |
| `enroll-errow.sh` | validate `errow_api_token`, Errow cloud reachability (`ERROW_CLOUD_ENABLED`), write `~/.errow/mcp-servers.json` (+ mTLS sidecar), `tools/list` smoke, target allow-list check | yes | 0 · 1 · 2 · 3 · 4 · 5 errow-mcp unreachable |
| `enroll-ollama.sh` | verify an Ollama node (version, loopback-only 11434, models, blob SHA-256 vs `models.json`), register it with the LB, confirm via gateway `/health`; `--remove` | yes | 0 · 1 verification · 2 · 3 policy/integrity · 4 · 5 node unreachable |
| `rotate-certs.sh` | re-issue service certs (existing CA, or `--rotate-ca` dual-trust), archive previous set to `pki-archive/`, reload without downtime | yes | 0 · 1 · 2 · 3 · 4 · 5 issued but a service unhealthy |
| `backup-opensearch.sh` | fs snapshot repo + dated snapshot, verify `SUCCESS`, `--keep N` prune, `--verify-restore`, encrypted file backups (`models.json`, `pki/`, optional `secrets/`) | yes | 0 · 1 · 2 · 3 · 4 · 5 unreachable/auth |
| `build-airgap-bundle.sh` | the 7 compose-built images + pinned third-party images (`docker save` → `images/`), the Errow sandbox (`errow-sandbox.tar`, bundle root), model blobs, Ollama binary, llama.cpp, Helm chart, config → deterministic tar + `SHA256SUMS` + CycloneDX 1.5 SBOM + cosign | yes | 0 · 1 · 2 · 3 policy (`--require-signature`, sentinel, `--release` with a missing built image / sandbox) · 4 · 5 refused (enclave) |
| `verify-bundle.sh` | verify a bundle: `SHA256SUMS`, SBOM hashes, cosign, model pins, built images + `errow-sandbox.tar`, safe layout | no | **0 ok · 1 usage/IO · 2 integrity · 3 policy** |
| `healthcheck.sh` | stack-wide health (Compose or `--kubernetes`), table or `--json` | no | **0 healthy · 1 degraded · 2 unhealthy** · 4 prereq · 64 usage |
| `pin-manager-cert.sh` | pin the manager API certificate: probe, chain the presented leaf to the stack CA, write `pki/manager-ca-bundle.crt` (`CA` + leaf) for `VENDETTA_API_CA_FILE`; an untrusted/stand-in or SAN-less certificate needs `--yes` | yes | 0 · 1 · 2 usage · 3 policy (unconfirmed or changed pin) · 4 prereq |
| `verify-manager.sh` | assert the manager still presents the pinned, CA-trusted certificate with the right SAN (used by `healthcheck.sh` under `ERROW_FEEDBACK_LIVE=true`) | no | 0 · 1 mismatch · 2 usage · 4 prereq |
| `check-allowlists.sh` | drift between `ERROW_ALLOWED_TARGETS`, the errow-mcp targets (`policy.yaml` + `MCP_TARGETS_FILE`) and `ERROW_FEEDBACK_ALLOWED_TARGETS` (both env lists default from `ERROW_TARGETS`); parses the env file, never sources it | no | 0 · 1 drift · 2 usage |
| `sync-mcp-policy.sh` | `llm-gateway/mcp_policy.yaml` ↔ `errow/mcp/policy.yaml` byte-identity | `--write` | 0 · 1 drift · 2 usage |
| `validate-models-json.sh`, `pin-model-digests.mjs` | owned by the models agent (B1); used by the scripts above. The validator checks the exact approved tag set (`DEFAULT_APPROVED`, overridable with `--approved`); the pinner resolves a model's registry host from its `upstream` when present, so Hub-sourced tags (`hf.co/…`) are pinned from their own repo instead of the library path | — | — |
| `lib/common.sh`, `lib/pki.sh`, `lib/models.sh`, `lib/images.sh` | sourced helpers (logging, retry, `vs_http`, FailClosed, PKI, model pins, image list) | — | — |

Exit-code differences worth remembering: `healthcheck.sh` uses 64 for usage errors (0/1/2 are health states);
`verify-bundle.sh` uses 1 for usage/IO (2 is integrity, 3 is policy).

## Key flags

* `bootstrap.sh` — `--check` · `--dry-run` · `--pki openssl|step-ca|mkcert` · `--pki-algo ec|rsa` · `--pki-days N`
  (`PKI_DAYS`, default 397) · `--ca-days N` (`PKI_CA_DAYS`, default 3650) · `--ca-passphrase-file F` ·
  `--dev-readable-keys` · `--dev-readable-secrets` · `--key-group GID` · `--extra-services A,B` ·
  `--set KEY=VALUE` · `--skip-preflight` · `--no-secrets|--no-pki|--no-env`.
* `pin-manager-cert.sh` — `--connect H:P` · `--server-name NAME` · `--ca-file F` · `--out F` · `--force` · `--yes`.
* `verify-manager.sh` — `--connect H:P` · `--server-name NAME` · `--bundle F` · `--quiet`.
* `healthcheck.sh` — `--json` · `--kubernetes [--namespace NS]` · `--transport auto|host|kube` · `--no-docker` ·
  `--only/--skip a,b` · `--wait SECS` · `--timeout SECS` · `--cert-warn-days N` · `HC_URL_<NAME>` / `HC_TCP_TIMEOUT` (see
  "Healthcheck from the host").
* `rotate-certs.sh` — `--dry-run` · `--only-expiring --threshold 30` · `--services A,B` · `--rotate-ca [--ca-phase P]` ·
  `--no-reload` · `--kubernetes`.
* `enroll-agent.sh` — `--manager HOST` · `--method auto|agent-auth|authd|api` · `--password-file F` ·
  `--forward-host H:P` · `--issue-client-cert` · `--force-reenroll` · `--install-systemd` · `--skip-forwarder|--skip-enroll`.
* `enroll-ollama.sh` — `--node N` with `--address IP` / `--container C` / `--local` · `--models-dir D` · `--release` · `--remove N`.
* `backup-opensearch.sh` — `--keep N` · `--verify-restore` · `--passphrase-file F` / `--create-passphrase` ·
  `--include-secrets` · `--snapshot-only|--files-only` · `--decrypt F --extract-to D`.
* `build-airgap-bundle.sh` — `--release` · `--skip-images|--skip-models|…` · `--skip-sandbox` (leave out
  `errow-sandbox.tar` only; refused with `--release`) · `--build` (`docker compose --profile '*' build` first; the
  sandbox is **not** built by compose) · `--no-pull` · `--image REF` / `--exclude-image SUBSTR` · `--models-dir D` ·
  `--cosign-key F` · `--require-signature` · `--offline` · `--dry-run`.

## Runbook snippets

```bash
# 1. First bring-up (idempotent; never rotates existing secrets or valid certs)
scripts/bootstrap.sh --check            # exit 5 if anything is missing or invalid
scripts/bootstrap.sh                    # secrets/ (0600), secrets/approval/ (0700), pki/, .env from .env.example if absent
docker compose up -d && scripts/healthcheck.sh --wait 300

# 2. FailClosed: onprem/airgap with a cloud LLM key in the environment is refused
CS3_PROFILE=airgap GEMINI_API_KEY=x scripts/bootstrap.sh --check   # exit 3, FailClosedError

# 3. Certificate renewal (monthly, or from cron with --only-expiring)
scripts/rotate-certs.sh --dry-run
scripts/rotate-certs.sh --only-expiring --threshold 30

# 3b. CA rotation = three runs with propagation of pki/ca.crt in between
scripts/rotate-certs.sh --rotate-ca --ca-phase overlap     # ca.crt = OLD+NEW bundle; distribute it
scripts/rotate-certs.sh --rotate-ca --ca-phase reissue     # leaves signed by the new CA
scripts/rotate-certs.sh --rotate-ca --ca-phase finalize    # ca.crt = NEW only

# 3c. Manager certificate pinning (before ERROW_FEEDBACK_LIVE=true)
scripts/pin-manager-cert.sh --dry-run
scripts/pin-manager-cert.sh                    # untrusted/self-signed stand-in certs need --yes
scripts/verify-manager.sh

# 4. Edge host
sudo scripts/enroll-agent.sh --manager vendetta-manager --password-file /etc/vendetta/authd.pass \
     --ca /etc/vendetta/ca.crt --issue-client-cert        # needs pki/ca.key on this host, or pass --client-cert/--client-key

# 5. Errow runner
scripts/enroll-errow.sh --mcp-resolve errow-mcp:9103:127.0.0.1

# 6. Ollama GPU node (model blobs verified against ollama/models.json)
scripts/enroll-ollama.sh --node gpu-01 --address 10.0.4.21 --models-dir /srv/ollama/models --release

# 7. Backups (nightly)
scripts/backup-opensearch.sh --keep 14 --verify-restore --passphrase-file secrets/backup_passphrase
scripts/backup-opensearch.sh --decrypt secrets/backups/<ts>/pki.tar.enc --extract-to ./restore --passphrase-file secrets/backup_passphrase

# 8. Air-gap bundle: build on the connected host, verify inside the enclave
#    (the Errow sandbox image must exist first: errow/RUNTIME.md two-step build → vendetta-stack/errow-sandbox:$STACK_VERSION)
scripts/build-airgap-bundle.sh --release --build --cosign-key cosign.key --cosign-password-file cosign.pass --require-signature
scripts/verify-bundle.sh dist/vendetta-stack-airgap-<releaseTag>.tar --cosign-pub cosign.pub --require-signature --release
# in the enclave: extract the tar, `for f in images/*.tar; do docker load -i "$f"; done`, then point compose at the sandbox tarball:
#   ERROW_SANDBOX_IMAGE_TAR=/bundle/errow-sandbox.tar   with the extracted bundle directory mounted at /bundle

# 9. Policy drift gate (CI)
scripts/sync-mcp-policy.sh --check || scripts/sync-mcp-policy.sh --write
# Target allow-list drift gate: feedback ⊆ ERROW_ALLOWED_TARGETS ⊆ errow-mcp targets (reads .env, else .env.example)
scripts/check-allowlists.sh [--env FILE] [--targets-file FILE]
```

## Things the deployment must know

**Key permissions.** Keys are `0600` by default and owned by whoever ran `bootstrap.sh`. Containers run as
non-root uids (typically 10001 for the Vendetta services, 1000 for OpenSearch), so the compose `user:` must match one of:

* `chown` the specific keys to the container uid after bootstrap (production), or
* `--key-group GID` → keys and secrets `0640`, group `GID`, and give the compose service `group_add: ["GID"]`, or
* `--dev-readable-keys` / `--dev-readable-secrets` → `0644` (local development only).

Approvals additionally need one key **per approver** in `secrets/approval/keys/<approver>.key` (created by
`approval.py keygen`, `0600`): `ERROW_FEEDBACK_APPROVAL_THRESHOLD` (default 2) distinct approvers must sign, and a
shared `feedback_approval_key` alone is clamped to 1. `bootstrap.sh --check` fails on loose or short keys.

Certificates are `0644`. `<svc>.pem` is cert+key for HAProxy and follows the key mode.

**PKI.** Private CA `pki/ca.crt` / `ca.key` (ECDSA P-384 by default; `--pki-algo rsa` → RSA 4096 CA / 3072 leaves;
`ca.key` always `0600`, optionally encrypted via `--ca-passphrase-file`). Leaves are issued for opensearch, fluentd-1,
fluentd-2, fluent-bit, llm-gateway, ollama-lb, ollama-1, mock-ollama, errow-mcp, errow, errow-feedback, prometheus,
plus `vendetta-manager`, `opensearch-dashboards` and `opensearch-admin`. SANs = service DNS name(s) + `localhost` +
`127.0.0.1`; EKU serverAuth+clientAuth. `ollama-1` also carries `ollama-1-proxy` and `ollama-workers`; `mock-ollama` carries `mock-ollama-proxy`, `ollama-1` and `ollama-workers`
(the LB verifies workers by the name `ollama-workers`/`ollama-1`).
OpenSearch DNs are `CN=opensearch,O=Vendetta Stack` and `CN=opensearch-admin,O=Vendetta Stack`
(`plugins.security.nodes_dn` / `authcz.admin_dn`). Existing certs with more than 30 days left are kept.
During CA rotation `pki/ca-signer.crt`, `pki/ca-next.*` and `pki/.rotation-state` exist (plain files in `pki/`); copies
are archived on every rotation and `ca-signer.crt`, `ca-next.*` and `.rotation-state` are removed/consumed on finalize.

**PKI archive (`pki-archive/`).** Previous certificate sets, old CAs and mkcert's CA store live in
`$PKI_ARCHIVE_DIR/<UTC ts>/` (default `$STACK/pki-archive/`, `0700`, git-ignored), **never inside `pki/`**: compose
mounts the whole `pki/` tree at OpenSearch's `config/certs` (read as uid 1000) and OpenSearch's security setup aborts
with `BootstrapException: AccessDeniedException: …/config/certs/archive` on any subdirectory it cannot read. So `pki/`
holds files only. A `PKI_ARCHIVE_DIR` inside `pki/` is refused (exit 2). `bootstrap.sh` and `rotate-certs.sh` move a
legacy `pki/archive/` (and `pki/.mkcert/`) out to `pki-archive/` automatically; `bootstrap.sh --check` reports such a
directory as `FAIL … legacy layout: move it to pki-archive/` (manual fix: `mv pki/archive pki-archive`). The archive is
excluded from the air-gap bundle and from `backup-opensearch.sh` (which archives `pki/` only).

**Manager TLS trust (live actions).** `errow-feedback` verifies the manager with `VENDETTA_API_CA_FILE` and fails
closed (503) when that file is missing or unusable — it never falls back to the system trust store. The bundled
manager is a stand-in that lets authd mint its own certificate, so pin it before turning live actions on:

```bash
scripts/pin-manager-cert.sh                    # probe 127.0.0.1:55000, inspect, write pki/manager-ca-bundle.crt
# compose already defaults VENDETTA_API_CA_FILE=/pki/manager-ca-bundle.crt — just restart errow-feedback
scripts/verify-manager.sh                      # what healthcheck.sh runs under ERROW_FEEDBACK_LIVE=true
```

The bundle never replaces the private CA (`bootstrap.sh` always writes `pki/ca.crt` too), so a later real,
pki-issued manager keeps working. Any rotation of the manager certificate changes the pin: `verify-manager.sh` and
the healthcheck row fail until it is re-pinned (`--force`). See `vendetta/API-CONTRACT.md`.

**Restart-order gotcha.** `ollama-lb` runs with `network_mode: service:llm-gateway`; restarting the gateway orphans
the LB's network namespace, so `rotate-certs.sh` always restarts `ollama-lb` immediately after `llm-gateway`.
Do the same in any manual restart.

**Ollama enrollment model.** `enroll-ollama.sh` writes `ollama/ollama-lb/workers.d/<node>.json` and a
`workers.hosts` file next to it, which provide the `ollama-workers` DNS records the HAProxy LB resolves (mTLS on
11443). Port 11434 must stay loopback-only on the node; the script refuses a node that exposes it. The model
verification hashes the manifests' blobs against `ollama/models.json`; the `<pinned-per-release>` sentinel is
refused with `--release` and under `CS3_PROFILE=airgap`. Add `ollama/ollama-lb/workers.d/` and
`ollama/ollama-lb/workers.hosts` (generated) and `/backups/` to `.gitignore` if you keep them in the tree.

**Errow mTLS.** Errow's own MCP client is Bearer-only (`extra=forbid` on its config schema), so `enroll-errow.sh` puts
the client certificate paths in a sidecar `~/.errow/mcp-mtls.json` rather than in `mcp-servers.json`; the transport
wrapper reads the sidecar. The target allow-list (`MCP_TARGETS_FILE`, default `errow/config/targets.yaml`) is validated
(keys, CIDR syntax, absolute `repo_paths`; a `/0` CIDR is refused with exit 3; CIDRs inside the policy's denied
ranges are reported) and created empty when absent.

**Healthcheck.** The `cs3.ai.ollama` loop guard is proven statically from the Fluent Bit config (and an optional
`--rendered-dir`): no Console leg `Match_Regex` may match `cs3.ai.*` and no network output may match `cs3.ai.ollama`.
Probe targets can be overridden with `HC_URL_{FLUENT_BIT,FLUENTD_1,FLUENTD_2,OPENSEARCH,DASHBOARDS,PROMETHEUS,GRAFANA,
ALERTMANAGER,LLM_GATEWAY,ERROW_MCP,ERROW_FEEDBACK}`; thresholds with `HC_FB_BACKLOG_*`, `HC_FLUENTD_QUEUE_*`,
`HC_FLUENTD_RETRY_WARN`, `HC_SPOOL_*`; the client identity with `HC_CLIENT_CERT` / `HC_CLIENT_KEY`.
`llm-gateway` `/health` maps `ok → pass`, `degraded → warn` (exit 1), anything else → fail.

**Healthcheck from the host (unpublished ports).** Compose publishes only some ports (Fluentd `24220`/`24231`,
`errow-feedback` `9102` and `errow-mcp` `9103` are internal). With `--transport auto` (default, Docker usable) and no
`HC_URL_<NAME>` override, a service is reached in this order:

1. the published port on `127.0.0.1` (a short TCP probe, `HC_TCP_TIMEOUT` seconds, default 2); this path is unchanged and
   Docker is not consulted for addresses;
2. the **container IP** — found with `docker compose ps -q <svc>`, else `docker inspect <project>-<svc>-1` (then
   `<project>_<svc>_1`), project = `COMPOSE_PROJECT_NAME` (default `vendetta-stack`). The first IP that accepts a TCP
   connection is used as `curl --resolve <svc>:<port>:<ip>` against `scheme://<svc>:<port>`, so TLS is still verified
   against `pki/ca.crt` for the service's own certificate name (never `-k`; there is no insecure mode). Linux only
   (container IPs are not routable from macOS/Windows Docker Desktop);
3. otherwise, if the HTTP probe fails with *connection refused/timeout* and Docker reports `State.Health.Status=healthy`,
   the row is **WARN** `healthy per docker, HTTP not reachable from host` (never OK; `starting`/`unhealthy`/no healthcheck
   stay FAIL). The `fluentd (active-active)` aggregate is then WARN `no aggregator verified over HTTP` — it is OK only when
   both aggregators were verified over HTTP, and a Docker-only aggregator never counts as a healthy one.

Without Docker (`--no-docker`, `docker` missing, `--transport host`) or when the container is not running under that
project, behaviour is the plain host-port probe (FAIL on refusal). Fluentd's `monitor_agent` (`24220`) binds the
container loopback by default; set `FLUENTD_MONITOR_BIND=0.0.0.0` on the Fluentd services (or publish/forward the port,
or set `HC_URL_FLUENTD_1`/`HC_URL_FLUENTD_2`) to get a full OK from the host — otherwise step 3 applies.

**Backups.** The snapshot repository needs `path.repo: /usr/share/opensearch/snapshots` in `opensearch.yml` and a
persistent volume mounted there, otherwise registration fails. The encryption passphrase is a file (≥ 16 chars,
`0600`); `--create-passphrase` generates it — keep an offline copy, the archives are unrecoverable without it.
Files land in `<backup-dir>/<UTC ts>/` (`ollama-models.json`, `pki.tar.enc`, optional `secrets.tar.enc`, `SHA256SUMS`,
`MANIFEST.json`), encrypted with `openssl enc -aes-256-cbc -pbkdf2 -iter 600000`; use `--decrypt` to restore. `secrets/` is only archived with
`--include-secrets`. The default backup directory is `$STACK/secrets/backups`.

**Air-gap bundle.** Output: `dist/vendetta-stack-airgap-<releaseTag>.tar` plus `.tar.sha256`. Layout (top directory
`vendetta-stack-airgap-<releaseTag>/`): `manifest.json`, `images/*.tar` + `images/images.tsv`, **`errow-sandbox.tar`**,
`models/`, `bin/ollama`, `llama.cpp/`, `helm/`, `config/`, `sbom.cdx.json`, `SHA256SUMS`, `SHA256SUMS.sig` or `UNSIGNED`.

* *Images.* `images/` holds the pinned third-party images (`.env.example` `*_IMAGE`, else the built-in contract §1 list)
  and exactly the **seven** images compose/Helm build: `vendetta-stack/{fluentd,llm-gateway,errow-mcp,errow,
  errow-feedback,errow-shipper,ollama}:${STACK_VERSION}`. `ollama-lb` and `mock-ollama` are stock-image services, not
  images, and are never bundled. Digest-pinned references survive `docker load` only with the containerd image store,
  so on the air-gap host check `docker image ls --digests` after loading (`verify-bundle.sh` checks the tarball hashes,
  not loaded image IDs). `--build` runs `docker compose --profile '*' build` first; a built image that is not present
  locally is a warning, and exit 3 with `--release`.
* *Errow sandbox layout.* The sandbox image (`ERROW_SANDBOX_IMAGE`, default `vendetta-stack/errow-sandbox:${STACK_VERSION}`)
  is `docker save`d to **`errow-sandbox.tar` in the bundle root** — deliberately not in `images/`: it runs inside
  `errow-dind` and must not be loaded into the host daemon. It is not part of `docker compose build` (two-step build,
  `errow/RUNTIME.md`), so build it before the bundle. It is listed in `SHA256SUMS`, has a `container` component with a
  purl in the SBOM, and is recorded in `manifest.json` (`errowSandbox` `{ref,file,id}`, `contains.errowSandbox`,
  `builtImages`). Deployment: **compose** `ERROW_SANDBOX_IMAGE_TAR=/bundle/errow-sandbox.tar` (mount the extracted bundle
  directory, `ERROW_BUNDLE_DIR`, at `/bundle`); **Helm** key `errow-sandbox.tar` in the `errow-bundle` PVC
  (`kubernetes/README.md`). A missing sandbox image is a warning, and exit 3 with `--release`; `--skip-sandbox` leaves it
  out (refused with `--release`); `--skip-images` skips images and sandbox.
* *Verification.* `verify-bundle.sh` additionally requires every manifest image to be listed in `SHA256SUMS` and to be
  one of the real built components (a stale `ollama-lb` / `mock-ollama` entry is an integrity failure), checks that
  `errow-sandbox.tar` is declared by the manifest and is a docker-save archive of that image (an undeclared root
  tarball or a tarball of another image is an integrity failure, exit 2), and with `--release` requires all seven built
  images and the sandbox tarball (exit 3; without `--release` the absent sandbox is a warning).

The bundle manifest records `STACK_VERSION` (default `1.0.0`), Ollama `OLLAMA_PINNED_VERSION` (0.40.5) and
`LLAMA_CPP_PINNED_TAG`. The tar is deterministic (sorted names, `--mtime` from `SOURCE_DATE_EPOCH` or the `models.json`
`updated` date, owner 0). `UNSIGNED` marker + exit 3 when `cosign` is missing and `--require-signature` is set; keyless
signing is refused for `airgap`/enclave builds.

**Secret files.** Written without a trailing newline: `opensearch_admin_password`, `llm_gateway_token`,
`errow_api_token`, `grafana_admin_password`, `feedback_webhook_token`, `vendetta_api_password`. The OpenSearch password
contains upper/lower/digit/special (≥ 16). Existing files are never replaced.

**Approval directory.** Compose bind-mounts `${ERROW_FEEDBACK_APPROVAL_DIR:-./secrets/approval}` read-only at
`/run/approval`; when it is missing Docker creates it root-owned. `bootstrap.sh` therefore creates `secrets/approval/`
(`0700`; `0750` + `chgrp` with `--key-group`; `0755` with `--dev-readable-secrets`; honours `ERROW_FEEDBACK_APPROVAL_DIR`)
and tightens a looser existing directory. It never generates `feedback_approval_key` — live feedback is opt-in
(`ERROW_FEEDBACK_LIVE=true`) and the operator creates the key per `errow/feedback-loop/APPROVALS.md`, e.g.
`(umask 077; openssl rand -hex 32 >secrets/approval/feedback_approval_key)`. Without the key bootstrap prints a
`NOTE feedback_approval_key …` row; an existing key is reported `KEEP … never touched`. `--check` fails when the
directory is missing or too open, warns about a loose key mode, and fails when `ERROW_FEEDBACK_LIVE=true` but the key is
missing. The key is not in `VS_SECRET_NAMES`, so it is not part of the secrets bootstrap manages.

**Useful environment.** `STACK_DIR`, `SECRETS_DIR`, `PKI_DIR`, `PKI_ARCHIVE_DIR` (default `$STACK_DIR/pki-archive`, must be
outside `pki/`), `ENV_FILE`, `VS_WORK_ROOT`, `MIN_DISK_GB` (20),
`MIN_RAM_MB` (6144), `CS3_PROFILE`, `OLLAMA_PINNED_VERSION`, `OLLAMA_PRELOAD_MODELS`, `OPENSEARCH_URL`,
`ENROLL_GATEWAY_URL`, `ERROW_CLOUD_ENABLED`, `ERROW_CLOUD_URL`, `MCP_TARGETS_FILE`, `MCP_ALLOWED_CLIENTS`,
`VENDETTA_AUTHD_PASSWORD_FILE`, `VENDETTA_HOME`, `EDGE_FORWARD_HOSTS`, `ERROW_HOME`, `BACKUP_DIR`,
`BACKUP_PASSPHRASE_FILE`, `CURL_IMAGE`, `HC_TCP_TIMEOUT` (healthcheck TCP probe, default 2 s), `COMPOSE_PROJECT_NAME`
(default `vendetta-stack`). `VS_NO_SLEEP=1` makes backoff instantaneous (tests).
Values resolve in the order: command-line flag → process environment → `$STACK/.env` → built-in default.

## Tests

```bash
scripts/tests/test_scripts.sh            # whole suite (~3 min, no containers; mocks in tests/mock_*.py + PATH shims)
scripts/tests/test_scripts.sh --list     # case names
scripts/tests/test_scripts.sh --only bootstrap_secrets_and_pki,rotate_dry_run_and_issue --keep
(cd scripts && LC_ALL=C.UTF-8 shellcheck -x *.sh lib/*.sh tests/test_scripts.sh tests/cases/*.sh)   # run from scripts/ so `source=` hints resolve
```

The suite builds temporary copies of the tree under `$STACK/.scratch/test.<pid>` (removed on exit unless `--keep`),
generates a real PKI and checks it with `openssl verify` plus SAN/EKU assertions, exercises idempotent re-runs,
bootstrap `--check` (including the approval directory), rotate-certs (dry-run, real, CA rotation), policy sync with
drift detection, real air-gap bundle builds (`--skip-images`, and with a docker shim: the seven built images + the root
`errow-sandbox.tar`, release/skip/exclude policy, `--build`) followed by `verify-bundle.sh` success and tamper-detection
(including sandbox tamper / wrong-image / stale `ollama-lb` cases), healthcheck against
mock endpoints (including the container-IP fallback with a docker shim: published-port path unchanged, IP path with
verified TLS, docker-health WARN, docker absent, never `-k`), backups against a mock OpenSearch, and the three
enrollment flows including a mock authd.
