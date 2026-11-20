# General CS3 On-Premises Installation & Telemetry Playbook

**Status:** Generalized operator template

**Companion:** [General_Telemetry_Onboarding_Plan.md](General_Telemetry_Onboarding_Plan.md)
**Production status:** Not a production certification. No live site installation, appliance change, production OpenSearch restart, outage test, or restore was executed during preparation.

> **Labels:** `[REPO]` = traced to repository code/configuration; `[LOCAL-TEST]` = isolated synthetic execution only; `[PROPOSED]` = example, not shipped; `[SITE-VALIDATE]` = execute on the approved target/version before reliance. Replace every `<PLACEHOLDER>` before running a command. Never paste real secrets into this file or a ticket.

## 1. Scope and implemented boundaries

This playbook covers an on-premises CS3 console, durable OpenSearch evidence, host/relay enrollment, a proposed network-syslog relay, acceptance, operations, and rollback. It does not replace device backups, existing performance monitoring, network change control, or vendor support.

| Area | Implemented behavior and limitation `[REPO]` |
|---|---|
| Ingest | `POST /api/cecur/logs/ingest`; object, array, or `{events:[...]}`; default batch limit 1000; per-agent `X-API-Key` when required. |
| Hot logs | `GET /api/cecur/logs` reads a 300-row memory cache and defaults to 100 results. It is not durable history. |
| Durable logs | Optional OpenSearch sink. HTTP 201/`success:true` can include `indexed:false`; this is failed durable delivery. |
| Fleet | Bulk single-use enrollment tokens and per-agent keys. Runtime fleet maps are not hydrated from PostgreSQL after console restart; verify and re-enroll if needed. |
| Accounts | Registration exists, but registered users are memory-backed with a Firestore synchronization qualification. Implement durable/external IAM or explicitly risk-accept a restricted pilot, including offboarding and break-glass recovery. |
| Incidents | Existing-incident read/update, playbook-step update, and AI analysis. No incident-create, playbook-generation, or action-execution API. `CONTAINED` is a workflow status, not proof of isolation. |
| Agent actions | FIM/SCA queueing only; containment is not an implemented enforcement channel. |
| Sensors | Calibration/reboot routes return 501. Manage sensors on their hosts. |
| Errow | Implemented routes are `GET /status`, `GET/POST /allowlist`, `DELETE /allowlist/:id`, and `POST /run-scan` below `/api/errow`; admin-gated and allowlist-gated. |
| Audit | `GET /api/audit/export` returns the bounded in-memory window, not necessarily the complete PostgreSQL ledger. Use durable ledger backup/query procedures for complete evidence. |
| Retention | Supplied ISM policy transitions hot → warm at 30 days → cold/snapshot at 90 days → delete at 365 days. A longer external archive is a separate SOP and restore obligation. |

## 2. Before installation

### 2.1 Site worksheet

| Value | Replace with |
|---|---|
| Repository and approved release | `<REPOSITORY_URL>` / `<APPROVED_RELEASE>` |
| Checkout path | `<CHECKOUT_DIR>` |
| Console FQDN and host address | `<CS3_FQDN>` / `<CS3_HOST_IP>` |
| Console upstream from proxy | `<CONSOLE_UPSTREAM>` |
| Relay hostname, address, approved agent ID | `<RELAY_HOSTNAME>` / `<RELAY_IP>` / `<AGENT_ID>` |
| Syslog listener port | `<SYSLOG_PORT>` |
| Internal CA / console CA file | `<CA_FILE>` |
| Inventory and expectation files | `<INVENTORY.csv>` / `<EXPECTATIONS.json>` |
| Expected manifest count | `<EXPECTED_COUNT>` |
| Administrative and device source networks | `<ADMIN_SUBNET>` / `<DEVICE_NETWORKS>` |
| NTP/DNS servers | `<NTP_SERVERS>` / `<DNS_SERVERS>` |
| Change, window, owner, rollback owner | `<CHANGE_ID>` / `<WINDOW>` / `<OWNER>` / `<ROLLBACK_OWNER>` |
| Secret vault and backup locations | `<VAULT_REF>` / `<BACKUP_REF>` |

### 2.2 Supported environment and capacity gate

Repository documentation identifies Ubuntu 22.04/24.04 LTS and RHEL 8/9 for on-premises installation, with Docker Engine + Compose v2, Node.js 18+, Git, curl, jq, and OpenSSL. The forwarder installer requires root and systemd on Linux. Use only an OS/container/collector version approved by your platform owner and record the actual versions.

Repository planning guidance includes 200 GB+ NVMe, 32 GB RAM with a 16 GB VRAM tier, or 64 GB RAM with a 24 GB+ VRAM tier for the larger default local models. These are starting requirements, not a measured site capacity guarantee. Size from model choice, event rate/size, retention, replica policy, buffer outage budget, and concurrent users; then load/soak-test.
<!-- confidence: inference -->

Minimum tools/checks:

```bash
git --version
node --version
docker --version
docker compose version
curl --version
jq --version
openssl version
timedatectl status
ss -ltnp
ss -lunp
```

If using NVIDIA acceleration, record `nvidia-smi`, driver/CUDA compatibility, and a model-inference test. Confirm OpenSearch kernel/memory requirements, including `vm.max_map_count`, using `deployment/operations/opensearch-cluster.md`; do not assume defaults fit production.

### 2.3 Credentials and access

Obtain without embedding values in commands or documents:

- repository read access and an immutable approved release;
- console bootstrap secret, personal admin account, and bearer-token handling process;
- PostgreSQL/OpenSearch secrets and a host-side OpenSearch CA/trust path;
- relay root/sudo access, device administration, Dashboard access where applicable;
- internal CA issuance/rotation access and optional client certificates;
- backup/restore and secret-vault access;
- firewall/DNS/NTP/change approvers.

Set `umask 077` for local evidence/credential work. The forwarder token is single-use and read from `CS3_ENROLL_TOKEN` or `--token-file`, never intentionally from its command line. The telemetry verifier supports `CS3_TOKEN` from the environment but currently requires the ingest key through `--ingest-key`; use a variable rather than a literal, run only on a trusted host, and note that command arguments can be visible to other local processes.

### 2.4 Network matrix

| Source | Destination | Port | Rule |
|---|---|---|---|
| `<ADMIN_SUBNET>` | `<CS3_FQDN>` | TCP 443 | UI/API through approved TLS proxy |
| `<RELAY_IP>` | `<CS3_FQDN>` | TCP 443 | Enrollment and ingest |
| `<DEVICE_NETWORKS>` | `<RELAY_IP>` | UDP/TCP `<SYSLOG_PORT>` | Only transports proven per device class |
| Proxy | `<CONSOLE_UPSTREAM>` | TCP 3000 | East-west/proxy only |
| Console | PostgreSQL / OpenSearch / model LB | TCP 5432 / 9200 / 11434 | Internal service networks |
| Administrator | Console host OpenSearch | TCP 9200 | Bundled default binds host loopback only |
| Bastion | Console/relay | TCP 22 | Administration only |
| Local operator | Relay Fluent Bit health | TCP 2020 | Loopback only |

Keep console 3000, PostgreSQL 5432, OpenSearch 9200, model service 11434, and relay health 2020 off untrusted networks. Cloud-managed appliances may still require approved vendor-cloud/DNS/NTP access.
<!-- confidence: inference -->
The `onprem` profile is not, by itself, proof that all egress is blocked; approve telemetry/update endpoints explicitly. The `airgap` template and launcher set/enforce telemetry and update checks false.

### 2.5 Mandatory pre-change safeguards

- [ ] Inventory identities, models, running versions, management/source addresses, and owners reconciled.
- [ ] Console, relay, and device configuration backups captured and restoration access tested.
- [ ] Existing monitoring/syslog destinations recorded; changes are additive unless explicitly approved.
- [ ] Unique benign event triggers and expected messages identified.
- [ ] Source/NAT behavior and per-device attribution approach approved.
- [ ] Capacity, disk-full, maximum-outage, and high-volume-category policies approved.
- [ ] Rollback and stop criteria from the companion plan copied into `<CHANGE_ID>`.
- [ ] Runtime fleet/IAM limitations remediated or explicitly risk-accepted for a restricted pilot.

## 3. Install the console

### 3.1 Obtain the reviewed source

```bash
git clone <REPOSITORY_URL> <CHECKOUT_DIR>
cd <CHECKOUT_DIR>
git checkout <APPROVED_RELEASE>
```

Do not use an unrelated repository URL from an old example. Record `git rev-parse HEAD`, dirty-state review, image tags/digests, and installer hashes in the change evidence.

The base Compose file still contains a site-specific inventory mount and variable names. Before a generic deployment, run `grep -n 'ASSETS_CSV' deployment/docker/docker-compose.yml`, override the discovered host-path setting with `<INVENTORY.csv>` in the reviewed environment, or remove/replace the mount in an approved overlay. Verify whether the running release consumes that inventory; do not silently mount another site's asset file. `[REPO]` `[SITE-VALIDATE]`

### 3.2 Path A — on-premises Docker Compose `[REPO]`

Use this path when the bundled PostgreSQL/OpenSearch model is intended.

```bash
cd <CHECKOUT_DIR>
on-prem/bin/bootstrap-onprem.sh --vehicle docker
```

Ordering implemented by the script:

1. `onboarding/wizard.mjs --profile onprem`;
2. `scripts/install-ollama.sh`;
3. `on-prem/bin/prepare-compose-env.sh`;
4. Compose base + on-premises overlay with `--profile siem`, from `deployment/docker`;
5. environment loading and `on-prem/bin/preflight-check.sh`.

Preparation creates/chmods `deployment/docker/.env`, preserves existing secrets, imports/generates required values, rejects mismatched bundled indexer passwords, and overwrites required on-premises profile/key/indexing settings. Back up and review that file before rerunning; it is not a generic merge that preserves every prior value.

**The Docker bootstrap does not run the separate `ollama-init` model-pull service.** For a connected, approved registry path, initialize both Compose model nodes explicitly after the model services are healthy:

```bash
cd <CHECKOUT_DIR>/deployment/docker
docker compose --project-directory "$PWD" \
  -f docker-compose.yml -f ../../on-prem/compose/docker-compose.onprem.yml \
  --profile pull-models up ollama-init

docker compose --project-directory "$PWD" \
  -f docker-compose.yml -f ../../on-prem/compose/docker-compose.onprem.yml \
  --profile siem up -d
```

If bootstrap preflight stops on indexer TLS trust, pause and install the approved CA or correct the indexer URL; do not bypass certificate verification. Resolve that failure before declaring the stack installed.

For disconnected sites, skip registry pulls and use the reviewed bundle/import process in §3.5. Confirm models on **both Compose nodes**, not merely a host Ollama service:

```bash
cd <CHECKOUT_DIR>/deployment/docker
docker compose exec -T ollama-1 ollama list
docker compose exec -T ollama-2 ollama list
```

The Compose model nodes are not made healthy by checking an unrelated host `localhost:11434` service. Conversely, the repository's Linux host installer creates **`cs3-ollama.service`**, not an `ollama` unit. Inspect the appropriate runtime:

```bash
systemctl status cs3-ollama.service --no-pager   # host-installed runtime, if used
<CHECKOUT_DIR>/scripts/install-ollama.sh --status
```

### 3.3 Compose command context `[REPO]`

Run maintenance from `deployment/docker`, or always supply an explicit `--project-directory` and the same file set. Do not run a base-file-only command from the repository root and assume it manages the same project.

```bash
cd <CHECKOUT_DIR>/deployment/docker
docker compose -f docker-compose.yml -f ../../on-prem/compose/docker-compose.onprem.yml --profile siem ps
docker compose -f docker-compose.yml -f ../../on-prem/compose/docker-compose.onprem.yml --profile siem logs --no-color console
```

**Never use `docker compose down -v` as routine rollback**: it destroys PostgreSQL, OpenSearch, and model volumes.

### 3.4 Path B — single-host launcher `[REPO]`

```bash
cd <CHECKOUT_DIR>
node cs3-launcher.mjs --profile onprem
```

The launcher runs onboarding/install checks, configures the local model runtime, and starts the console container. It does not by itself prove or enable a durable OpenSearch deployment. For C3 acceptance, configure a reachable trusted OpenSearch sink and pass §7, or use the Compose/Ansible durable architecture.

On-premises templates default telemetry/update checks enabled. Set `CS3_TELEMETRY_ENABLED=false` and `CS3_UPDATE_CHECK_ENABLED=false` when egress is not approved; air-gap defaults/enforces them false. Hosted-model keys must remain blank for on-premises/air-gap profiles.

### 3.5 Path C — Ansible and air-gap

**Ansible `[REPO]` `[SITE-VALIDATE]`**

```bash
cd <CHECKOUT_DIR>
on-prem/bin/bootstrap-onprem.sh --vehicle ansible --inventory <INVENTORY_FILE>
```

Alternatively follow `deployment/ansible/` directly. Keep secrets in Ansible Vault, use `vars/onprem.yml`, verify required non-empty database/indexer/bootstrap secrets, and retain trusted indexer TLS. Execute against a test inventory before production.

**Air-gap `[REPO]` `[SITE-VALIDATE]`**

**Release blocker:** `onboarding/models.json` contains `<pinned-per-release>` placeholders in this checkout, and the model-bundle workflow referenced by the operations documentation is absent. Resolve this gate before running the procedure: a release owner must pin/verify model digests and produce a verified bundle. Do not bypass mismatches with `--allow-tag-mismatch`.

On a connected staging host:

```bash
cd <CHECKOUT_DIR>
node scripts/build-airgap-bundle.mjs \
  --out <BUNDLE.tar> --release-tag <APPROVED_RELEASE> \
  --models <COMMA_SEPARATE_APPROVED_MODELS> \
  --include-ollama-binary --include-console-image
node scripts/verify-bundle.mjs --bundle <BUNDLE.tar> --verbose
```

Transfer the bundle and companion checksum through approved media controls. On the target:

```bash
cd <CHECKOUT_DIR>
node scripts/verify-bundle.mjs --bundle <BUNDLE.tar> --sha256 <BUNDLE.tar.sha256> --verbose
node cs3-launcher.mjs --profile airgap --bundle <BUNDLE.tar>
```

No air-gap build was executed for this playbook. Air-gap C3 still needs a durable indexer and §7 evidence.

### 3.6 TLS reverse proxy `[PROPOSED]` `[SITE-VALIDATE]`

The repository documents a proxy architecture but this Nginx configuration is an example, not shipped. Certificates, upstream reachability, headers, request limits, and SSE behavior require testing.

```nginx
server {
    listen 443 ssl;
    server_name <CS3_FQDN>;
    ssl_certificate     /etc/cecur/pki/<CS3_FQDN>/fullchain.pem;
    ssl_certificate_key /etc/cecur/pki/<CS3_FQDN>/tls.key;
    client_max_body_size 4m;

    location / {
        proxy_pass http://<CONSOLE_UPSTREAM>:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
    location /api/live/stream {
        proxy_pass http://<CONSOLE_UPSTREAM>:3000;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
```

Use an internal CA trusted by browsers, enrollment, forwarder, and host-side verification. Keep production TLS verification enabled; `CECUR_INDEXER_TLS_INSECURE=true` is a lab-only exception.

## 4. Post-install verification and hardening

### 4.1 Environment loading and preflight `[REPO]`

`bootstrap-onprem.sh` loads root and Compose environment files before its final preflight. Standalone `on-prem/bin/preflight-check.sh` reads **only its current process environment**; running it without loading values can produce misleading failures.

For repository-generated, reviewed, shell-compatible environment files only:

```bash
cd <CHECKOUT_DIR>
set -a
[ ! -f .env ] || . ./.env
[ ! -f deployment/docker/.env ] || . ./deployment/docker/.env
set +a
export CECUR_INDEXER_VERIFY_URL="${CECUR_INDEXER_VERIFY_URL:-https://127.0.0.1:9200}"
on-prem/bin/preflight-check.sh
```

Sourcing is shell execution: never source an unreviewed or attacker-controlled `.env`. For arbitrary dotenv syntax, use a reviewed non-evaluating loader rather than `eval`. Preflight requires demo mode off, profile `onprem`/`airgap`, ingest keys required, hosted-model keys blank, and—on `onprem`—indexing enabled and reachable.

### 4.2 Health, authentication, and persistence

```bash
curl -fsS http://127.0.0.1:3000/api/health | jq .
curl -fsS https://<CS3_FQDN>/api/health | jq .
```

Authenticate without putting the bootstrap password in a saved command:

```bash
read -rsp 'Bootstrap password: ' BOOTSTRAP_PASSWORD; echo
CS3_TOKEN="$({ jq -n --arg username admin --arg password "$BOOTSTRAP_PASSWORD" \
    '{username:$username,password:$password}' \
  | curl -fsS https://<CS3_FQDN>/api/auth/login \
      -H 'Content-Type: application/json' --data-binary @-; } | jq -er '.token')"
export CS3_TOKEN
unset BOOTSTRAP_PASSWORD
curl -fsS -H "Authorization: Bearer $CS3_TOKEN" https://<CS3_FQDN>/api/auth/me | jq .
curl -fsS -H "Authorization: Bearer $CS3_TOKEN" https://<CS3_FQDN>/api/fleet/summary | jq .
```

Rotate the bootstrap password and establish personal least-privilege accounts. Treat registration as pilot-only until durable/external IAM is approved. Tokens expire; discard client tokens on sign-out—there is no implemented logout route in the reviewed auth routes.

Check audit-chain integrity from the Compose directory when PostgreSQL is enabled:

```bash
cd <CHECKOUT_DIR>/deployment/docker
docker compose exec -T postgres psql -U postgres -d cs3 -c 'select cs3.verify_audit_chain();'
```

Investigate a non-null/broken result; do not manually rewrite the ledger. Complete `on-prem/checklists/go-live-checklist.md` and a backup restore rehearsal before go-live.

## 5. Enroll and install a Linux relay

### 5.1 Native enrollment `[REPO]`

Create `<HOSTS.csv>` with one real relay row (the wrapper rejects common placeholder/sample files):

```csv
hostname,ip,platform,osName,osVersion,arch,workloadType,group
<RELAY_HOSTNAME>,<RELAY_IP>,linux,<OS_NAME>,<OS_VERSION>,<ARCH>,virtual,<GROUP>
```

On the admin host:

```bash
cd <CHECKOUT_DIR>
read -rsp 'Admin bearer token: ' CS3_TOKEN; echo
export CS3_TOKEN
on-prem/bin/enroll-real-endpoints.sh \
  --url https://<CS3_FQDN> --file <HOSTS.csv> --group <GROUP> --dry-run
on-prem/bin/enroll-real-endpoints.sh \
  --url https://<CS3_FQDN> --file <HOSTS.csv> --group <GROUP> --out <ENROLLMENT.json>
```

Review the output, map the relay row to `<AGENT_ID>`, and protect `<ENROLLMENT.json>` as a secret until its single-use token is claimed. Tokens default to 24 hours and are stored server-side as hashes.

### 5.2 Installer and dry-run warning `[REPO]`

Copy the reviewed `deployment/agents/` bundle to the relay. As root:

```bash
cd <AGENT_BUNDLE_DIR>
read -rsp 'Single-use enrollment token: ' CS3_ENROLL_TOKEN; echo
export CS3_ENROLL_TOKEN
./install-forwarder.sh \
  --console-url https://<CS3_FQDN> --agent-id <AGENT_ID> \
  --ca-file <CA_FILE> --profile gateway
unset CS3_ENROLL_TOKEN
```

Optional mTLS, pin, and offline package flags are documented in the installer header. Verify offline package SHA-256 values; HTTPS is mandatory.

> **Dry-run is not guaranteed non-mutating.** With an enrollment token, `--dry-run` creates installation directories and writes `/etc/cecur/forwarder.env.new` directly before its wrapped rename. Use only a disposable lab/snapshot for installer dry-run, or back up and accept that mutation. Do not advertise it as a read-only production check.

Installed components include `/etc/cecur/forwarder.env` (mode 0600), `/etc/cecur/fluent-bit.conf`, `/etc/cecur/parsers.conf`, gateway fragments, `/var/lib/cecur-forwarder/buffer`, `cecur-forwarder.service`, and a watchdog timer. The native output uses JSON, gzip, verified TLS, unlimited retries, and a 2G output storage cap. The gateway's extra OTLP listener defaults to loopback; leave it there unless a separate mTLS design is approved.

```bash
systemctl status cecur-forwarder cecur-forwarder-watchdog.timer --no-pager
curl -fsS http://127.0.0.1:2020/api/v1/health | jq .
journalctl -u cecur-forwarder -n 100 --no-pager
```

## 6. Add network syslog

### 6.1 Status and rejected design

No `71-network-syslog.conf` ships in `deployment/agents/templates/gateway.d/`; this entire section is `[PROPOSED]` until implemented, reviewed, and tested in the deployment bundle.

Do **not** use raw `udp`/`tcp` inputs with `Format none` plus `Source_Address_Key` for sender attribution. Local Fluent Bit 3.2.10, 4.0.0, and 5.1.5 tests accepted that syntax but emitted no `source_ip`; mappings failed and events used the relay fallback. `[LOCAL-TEST]`

The replacement below uses the `syslog` input and RFC3164 parser. Synthetic RFC3164 UDP/TCP input passed with mapped sender attribution and message redaction on Fluent Bit **5.1.5** only. Real vendor messages, RFC5424, production TLS, and target collector versions remain `[SITE-VALIDATE]`.

### 6.2 Add the parser to the deployment bundle `[PROPOSED]`

The installed forwarder parser template contains only JSON. It is overwritten on installer rerun, and Fluent Bit rejects `[PARSER]` sections in `fluent-bit.d` fragments. Add this parser to the **reviewed deployment bundle's** `deployment/agents/templates/parsers.conf`, then reinstall/render through the approved configuration process; do not make an untracked live-only edit.

```ini
[PARSER]
    Name        syslog-rfc3164
    Format      regex
    Regex       ^\<(?<pri>[0-9]+)\>(?<time>[^ ]* {1,2}[^ ]* [^ ]*) (?<host>[^ ]*) (?<ident>[a-zA-Z0-9_\/\.\-]*)(?:\[(?<pid>[0-9]+)\])?(?:[^\:]*\:)? *(?<message>.*)$
    Time_Key    time
    Time_Format %b %d %H:%M:%S
    Time_Keep   On
```

Back up `/etc/cecur/parsers.conf`, verify the rendered file contains exactly one `syslog-rfc3164` definition, and test on the exact deployed Fluent Bit binary. Dry-run alone is insufficient: local testing observed a missing-parser runtime failure even when configuration acceptance checks had not caught the full behavior.

### 6.3 Relay fragment `[PROPOSED]` `[SITE-VALIDATE]`

Create `/etc/cecur/fluent-bit.d/71-network-syslog.conf` through the approved configuration bundle. Replace the mapping example with one anchored rule per **observed** sender address:

```ini
[INPUT]
    Name               syslog
    Alias              network_syslog_udp
    Tag                host.netsyslog
    Mode               udp
    Listen             0.0.0.0
    Port               <SYSLOG_PORT>
    Parser             syslog-rfc3164
    Source_Address_Key source_ip
    storage.type       filesystem
    Mem_Buf_Limit      16MB

[INPUT]
    Name               syslog
    Alias              network_syslog_tcp
    Tag                host.netsyslog
    Mode               tcp
    Listen             0.0.0.0
    Port               <SYSLOG_PORT>
    Parser             syslog-rfc3164
    Source_Address_Key source_ip
    storage.type       filesystem
    Mem_Buf_Limit      16MB

# Example only: replace both device values. Escape regex metacharacters in the IP.
[FILTER]
    Name      modify
    Match     host.netsyslog
    Condition Key_Value_Matches source_ip ^(udp|tcp)://<REGEX_ESCAPED_DEVICE_IP>:
    Set       agentName <DEVICE_NAME>

[FILTER]
    Name    lua
    Match   host.netsyslog
    Alias   network_syslog_normalize
    script  /etc/cecur/fluent-bit.d/cs3-otlp-normalize.lua
    call    cs3_normalize

[FILTER]
    Name    modify
    Match   host.netsyslog
    Add     source syslog
    Add     agentName ${CS3_HOSTNAME}
```

Why these details matter:

- Local syslog-input values were transport-qualified endpoints such as `udp://127.0.0.1:<ephemeral-port>`; exact bare-IP equality does not match that form. `[LOCAL-TEST]`
- The mapping runs before Lua normalization; the normalizer moves non-reserved values into `fields`, including `source_ip` and parsed syslog metadata. `[REPO]`
- `Add agentName` is the relay fallback; investigate every fallback where a device was expected.
- Do **not** add `Raw_Message_Key`. A local test retained an unredacted raw copy in `fields.raw`; the current normalizer redacts the normalized message, not arbitrary nested field values. `[LOCAL-TEST]`
- One enrolled relay key pins `agentId` to the relay, not each device. Sender mappings, parsed hostname, message fields, and `agentName` are unauthenticated attribution. `[REPO]`

Validate and apply:

```bash
/opt/fluent-bit/bin/fluent-bit -c /etc/cecur/fluent-bit.conf --dry-run
systemctl restart cecur-forwarder
ss -lunp | grep '<SYSLOG_PORT>'
ss -ltnp | grep '<SYSLOG_PORT>'
curl -fsS http://127.0.0.1:2020/api/v1/health | jq .
journalctl -u cecur-forwarder -n 100 --no-pager
```

Then send sanitized lab messages over **both enabled transports** and inspect actual output/ingest. A dry-run plus listener check is not parser/mapping acceptance. Use host firewall rules restricted to `<DEVICE_NETWORKS>` and the enabled protocol(s); firewall examples are `[PROPOSED]`.

### 6.4 Device configuration examples `[PROPOSED]` `[SITE-VALIDATE]`

These are starting fragments only. Save prior configuration, check exact-version help/vendor documentation, canary one device, and retain existing monitoring. Restore the prior destination/settings for rollback rather than blindly disabling a shared syslog service.

**Cisco IOS/IOS XE-style example**

```text
configure terminal
 logging source-interface <MGMT_INTERFACE>
 logging host <RELAY_IP> transport udp port <SYSLOG_PORT>
 logging trap informational
end
write memory
show logging
```

Custom-port syntax is unverified for every target train. If exact-version help rejects it, stop; use only a separately approved/tested standard-port listener/privilege/firewall design.
<!-- confidence: inference -->

**FortiOS-style example**

```text
config log syslogd setting
    set status enable
    set server "<RELAY_IP>"
    set mode udp
    set port <SYSLOG_PORT>
    set facility local7
    set source-ip "<DEVICE_SOURCE_IP>"
    set format default
end
config log syslogd filter
    set severity information
end
```

Vendor FortiOS CLI references support the principal fields on the reviewed release; confirm every field against the exact target version. Exact emitted identity/source behavior must be captured. `source-ip` selects egress; it does not configure CS3 attribution.
<!-- confidence: inference -->

**Cloud-managed switch/AP example**

1. Open the approved Dashboard network's syslog-server configuration.
2. Add `<RELAY_IP>` and `<SYSLOG_PORT>` with a transport supported by the exact device/firmware.
3. Enable only approved event roles; start without high-volume flows/URLs.
4. Repeat per network and capture the actual sender at the relay.

For an MR target earlier than 33.1, use UDP for this design; MR TCP requires MR 33.1 or later. Do not infer switch behavior or outage buffering from AP documentation.
<!-- confidence: inference -->

For every class, record sender, NAT, format, event role, rollback, and evidence. During an approved outage test, separately interrupt cloud management/internet access while preserving device-to-relay LAN connectivity; do not assume either continuous delivery or buffering.

## 7. Acceptance: C2, C3, and fresh C3+

### 7.1 Prepare expectations and event window

Build `<EXPECTATIONS.json>` from real triggers and reviewed mappings:

```json
[
  {
    "device": "<STABLE_DEVICE_ID>",
    "message": "<UNIQUE_OBSERVED_MESSAGE_TOKEN>",
    "agentName": "<EXPECTED_DEVICE_NAME>",
    "sourceIp": ""
  }
]
```

The verifier requires unique `device` values, a non-empty array, and exact `--expect-count` when supplied. `sourceIp` is optional match text. Because observed sender values contain scheme and ephemeral port, leave it empty unless a stable match is explicitly tested; preserve full sender evidence separately. A correct mapped `agentName` still proves only recorded attribution, not authenticated device identity.

Load the reviewed Compose environment as in §4.1, then set:

```bash
cd <CHECKOUT_DIR>
read -rsp 'Admin or analyst bearer token: ' CS3_TOKEN; echo
export CS3_TOKEN
export CECUR_INDEXER_VERIFY_URL="${CECUR_INDEXER_VERIFY_URL:-https://127.0.0.1:9200}"
export CECUR_INDEXER_CA_FILE='<INDEXER_CA_FILE>'
export AGENT_ID='<RELAY_AGENT_ID>'
AGENT_KEY="$(sed -n 's/^CS3_INGEST_KEY=//p' /etc/cecur/forwarder.env)"   # if run on the relay
export EXPECTATIONS='<EXPECTATIONS.json>'
export EXPECTED_COUNT='<INTEGER_MATCHING_MANIFEST>'
```

If verification runs on the console host, transfer the relay key only through the approved secret channel; do not read a relay-local path that does not exist there. Use a host-reachable indexer URL and trusted CA. Never disable TLS verification to make production pass.

### 7.2 C2 — arrival

For each device:

1. Confirm relay service/health and packet arrival with a sanitized capture, for example `tcpdump -ni any 'port <SYSLOG_PORT>' -c 20` after placeholder substitution and privacy approval.
2. Trigger the benign event and record UTC time/token.
3. Query the authenticated hot cache and inspect `agentId`, `agentName`, `message`, `fields.source_ip`, and timestamp:

```bash
curl -fsS --get https://<CS3_FQDN>/api/cecur/logs \
  -H "Authorization: Bearer $CS3_TOKEN" \
  --data-urlencode 'search=<UNIQUE_OBSERVED_MESSAGE_TOKEN>' \
  --data-urlencode 'limit=100' | jq .
```

No relay packets → fix source/route/firewall before console debugging. Packets without the expected record → inspect parser, mappings, filters, and forwarder/console logs. Hot-cache success alone remains C2.

### 7.3 C3 — indexed and restart-surviving

Record the start **before** triggering all expectation events:

```bash
export C3_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Trigger and record every real device event after this timestamp.
```

Run after the events are observable:

```bash
cd <CHECKOUT_DIR>
on-prem/bin/verify-real-telemetry.sh \
  --url "https://<CS3_FQDN>/api/cecur/logs/ingest" \
  --ingest-key "$AGENT_KEY" --agent-id "$AGENT_ID" \
  --expectations "$EXPECTATIONS" --expect-count "$EXPECTED_COUNT" \
  --since "$C3_SINCE" --restart-console
```

The script sends a synthetic relay event and requires `success:true`, `indexed:true`, a log ID, and authenticated hot-cache visibility. It directly queries `cs3-logs` for every expectation, restarts only the console using `CS3_COMPOSE_DIR` (default `<CHECKOUT_DIR>/deployment/docker`), waits for health, and repeats the old-event queries. It fails closed on response/indexer/TLS/query/count/restart errors.

This proves earlier records survived a console restart. It does **not** prove renewed ingest or runtime fleet recovery.

### 7.4 C3+ — fresh post-restart operation

1. Inspect fleet immediately:

   ```bash
   curl -fsS -H "Authorization: Bearer $CS3_TOKEN" https://<CS3_FQDN>/api/fleet/summary | jq .
   ```

2. If the relay is absent or ingest fails, re-enroll it under change control and reload its new ID/key. A PostgreSQL row alone is not operability.
3. Start a **new** evidence window and trigger every required device event again:

   ```bash
   export C3_PLUS_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   # Trigger all device events again after this timestamp.
   ```

4. Rerun the full verifier **without** another restart and with the new timestamp:

   ```bash
   cd <CHECKOUT_DIR>
   on-prem/bin/verify-real-telemetry.sh \
     --url "https://<CS3_FQDN>/api/cecur/logs/ingest" \
     --ingest-key "$AGENT_KEY" --agent-id "$AGENT_ID" \
     --expectations "$EXPECTATIONS" --expect-count "$EXPECTED_COUNT" \
     --since "$C3_PLUS_SINCE"
   ```

The second full pass sends a fresh synthetic relay marker requiring `indexed:true` and requires fresh per-device OpenSearch matches. Do not substitute `--query-only`: that can be satisfied by old records and does not test new ingest. Record both passes, document IDs, fleet recovery, and all rollback/actions in `<CHANGE_ID>`.

## 8. Operations

### 8.1 Routine checks

| Cadence | Action |
|---|---|
| Continuous | Monitor `/api/health`, forwarder `/api/v1/health`, service/watchdog, indexer health/disk, buffer growth/drain, and unmapped relay fallback. |
| Daily | Review ingest/indexing failures, parser drops, unexpected event volume, incidents, and existing device monitoring. |
| Weekly | Review fleet summary drift, offline/pending agents, capacity, certificates, and failed authentication. |
| Monthly | Verify audit chain, review users/roles, inspect archive/snapshot jobs, and reconcile inventory/manifest. |
| Per policy/release | Restore rehearsal, certificate rotation, device/firmware/collector sample tests, C3+ canary, then waves. |

Use organization-approved thresholds; do not invent a universal CPU/EPS limit. Existing SNMP/performance/configuration-backup systems remain authoritative unless separately migrated.

### 8.2 Troubleshooting

| Symptom | Check | Action |
|---|---|---|
| No packets at relay | Device destination/source, transport, route, ACL/NAT | Restore approved network path; do not debug OpenSearch first. |
| Packets arrive; fallback relay identity | `fields.source_ip`, regex escaping, transport-qualified value, mapping order | Add/fix the observed sender rule; never assume management IP. |
| Parser/runtime failure | Exact parser definition, binary version, sanitized sample, journal | Fix bundle parser/config; dry-run alone is insufficient. |
| Secrets in `fields` | Raw-message retention and structured values | Remove raw key, stop affected flow, extend/test redaction, rotate exposed secrets. |
| HTTP 401 | Key enforcement, agent ID/key, runtime fleet membership | Re-enroll under change control; verify TLS and key mapping. |
| HTTP 413 | Batch/body size and default 1000-event limit | Reduce batch/body within approved console/proxy limits. |
| HTTP 429/503 | Backpressure, fleet limits, capacity | Pause waves, inspect health/capacity, allow buffer drain. |
| HTTP 201 but C3 fails | Response `indexed:false`, console/indexer logs | Treat as failed delivery; HTTP success need not be retried by Fluent Bit. |
| Events vanish after restart | Indexer enablement and direct indexed evidence | Enable/repair sink and rerun C3; hot cache/buffer are not C3. |
| Old events return; new ones fail | Fleet runtime membership and fresh ingest | Re-enroll if needed; perform second full C3+ pass. |
| Models absent | Correct runtime: Compose nodes vs `cs3-ollama.service` | Run approved `ollama-init`/bundle import; test both Compose nodes where used. |
| Preflight unexpectedly fails | Current process environment and host-side indexer URL/trust | Load reviewed env; set verification URL/CA; do not disable TLS. |
| Audit export appears incomplete | Bounded memory window and durable ledger | Export/query durable PostgreSQL evidence through approved backup/SOP. |

### 8.3 Backup, retention, and audit

Follow `deployment/operations/backup-restore.md`, `opensearch-cluster.md`, and `log-retention-archival.md`. Test PostgreSQL recovery, OpenSearch snapshot restore, and model recovery separately. The supplied ISM file assumes warm/cold tier allocation and a configured `cs3-cold` snapshot repository; policy presence does not prove those resources, snapshot success, or restore.

The ISM deletion at 365 days is not a seven-year/external archive implementation. Provision immutable/external archive storage if required, monitor it, and perform sampled restores. Treat `GET /api/audit/export` as a bounded operational export, not proof of complete ledger export.

### 8.4 Errow and unsupported actions

Use Errow only with explicit authorization, an approved window, and exact allowlisted scope. Configure its connector and inspect `GET /api/errow/status`; manage targets with `GET/POST /api/errow/allowlist` and `DELETE /api/errow/allowlist/:id`; submit scans through `POST /api/errow/run-scan`. Do not substitute stale `/targets`, `/jobs`, or `/scan` route examples.

Do not runbook sensor calibration/reboot, endpoint containment, incident creation, playbook generation, or action execution as working CS3 automation. Perform those activities through approved external systems and record the result separately.

## 9. Rollback and uninstall

### 9.1 Device/wave rollback `[SITE-VALIDATE]`

1. Stop the affected wave and disable only the newly added destination/configuration using the saved exact-version procedure.
2. Restore prior syslog severity, categories, source interface, and existing destinations from the pre-change record.
3. Remove only newly approved host/network firewall rules and relay mappings/listeners no longer needed.
4. Confirm existing monitoring and network stability; trigger baseline checks.
5. Preserve sanitized evidence and mark the device C0/C1 as appropriate—never leave an unverified device marked C3.

### 9.2 Relay rollback `[REPO]`

Back up configuration and required buffered evidence first. The installer uninstall is destructive:

```bash
cd <AGENT_BUNDLE_DIR>
./install-forwarder.sh --uninstall
```

It disables/removes the CS3 forwarder units and deletes `/etc/cecur` and `/var/lib/cecur-forwarder`, including operator fragments, credentials, certificates, and buffered data. It leaves the Fluent Bit package installed. Remove/revoke fleet credentials through the approved recovery process and verify device destinations are rolled back separately.

### 9.3 Console rollback `[REPO]`

For Compose, stop affected services from the correct project context and restore from tested backups/images:

```bash
cd <CHECKOUT_DIR>/deployment/docker
docker compose -f docker-compose.yml -f ../../on-prem/compose/docker-compose.onprem.yml --profile siem stop
```

Do not use `down -v`. Restore the approved console image/configuration, PostgreSQL/OpenSearch snapshots as required, then run health, audit-chain, fleet, C3, and fresh C3+ checks.

For the single-host launcher, removing `cs3-soc-console` and stopping `cs3-ollama.service` only stops components; it is **not** a complete Ollama binary/service/model/data uninstall or a full configuration rollback. Use the pre-install snapshot and a separately reviewed cleanup runbook. Model update/rollback guidance references an absent bundle workflow, so release-specific rollback artifacts must be supplied and tested.

## 10. Handoff checklist

- [ ] Approved release/image/collector versions and sanitized configurations recorded.
- [ ] DNS/NTP/TLS/firewall/credentials/backup/restore evidence attached.
- [ ] Both Compose model nodes verified, or the approved alternative model runtime documented.
- [ ] Inventory/source matrix/attribution map/expectation manifest reconciled.
- [ ] Real device parser, sender, redaction, transport, and outage results attached.
- [ ] C2 plus two full verification passes (restart C3, then fresh C3+) attached with OpenSearch IDs.
- [ ] Post-restart fleet recovery and IAM risk decision recorded.
- [ ] Capacity, buffer drain, disk-full, malformed-input, snapshot/archive, and restore gates passed or explicitly open with owners.
- [ ] No proposed proxy/firewall/vendor/relay fragment is described as native or production-certified.
- [ ] Operators have rollback, troubleshooting, retention, and escalation procedures.
