# Endpoint agents (forwarders) and bulk enrollment

Complete [`PREREQUISITES.md`](PREREQUISITES.md) before enrollment or installation. It defines the common identity, time, network, HTTPS/CA, package-integrity, secret-handling, and evidence requirements, plus Linux/Windows and VM-specific prerequisites.

| File | Purpose |
|---|---|
| `cs3-enroll.mjs` | Bulk enrollment CLI (Node ≥ 18, core modules only). Reads CSV/JSON, calls `POST /api/fleet/enroll/bulk` in batches ≤ 1000, writes one-time tokens to a 0600 file |
| `cs3-scan-agent.mjs` | On-host scan worker (Linux, Node ≥ 18, core modules only). Polls `GET /api/fleet/agent/tasks`, runs queued FIM / SCA / vulnerability jobs against the local host and posts measured results to `POST /api/fleet/agent/results`. Unsupported scans are reported as `failed` with the reason; nothing is fabricated |
| `install-forwarder.sh` | Linux installer: Fluent Bit + systemd unit + watchdog timer; claims the enrollment token |
| `Install-CecurForwarder.ps1` | Windows installer: Fluent Bit service + scheduled-task watchdog; claims the enrollment token |
| `cs3-forwarder-watchdog.sh` / `Test-CecurForwarder.ps1` | Health check + bounded auto-remediation (Linux / Windows) |
| `templates/fluent-bit-{linux,windows}.conf` | Forwarder configs (filesystem buffering, gzip, TLS verify, optional mTLS) |
| `templates/parsers.conf` | Linux parsers file (`json`), installed to `/etc/cecur/parsers.conf` and loaded by the Linux config via an absolute `Parsers_File` |
| `templates/gateway.d/` | Linux **gateway profile** fragments: OTLP listener (plain or mTLS), Lua normaliser, heartbeat, ESOC OTLP/gRPC egress, SIEM HTTPS egress, AI tier; `70-app-logs.conf.example` is an optional tail example |
| `templates/forwarder.env.example` | Reference for every variable in `/etc/cecur/forwarder.env` (edge and gateway) |
| `templates/fluentd-aggregator.conf` | Optional Fluentd aggregation tier built on the nursery OTLP and HTTP-output plugins |
| `systemd/` | `cecur-forwarder.service`, `cecur-forwarder-gateway.conf` (gateway `MemoryMax` drop-in), watchdog `.service` + `.timer` |

## Flow

```bash
# 1. Admin: enroll hosts (dry run first)
export CS3_TOKEN=...            # or CS3_USERNAME + CS3_PASSWORD
node cs3-enroll.mjs bulk --url https://soc.example.internal --file hosts.csv --group prod --dry-run
node cs3-enroll.mjs bulk --url https://soc.example.internal --file hosts.csv --group prod --out cs3-enrollment.json

# 2. Roll out in waves (Ansible) – or run the installers by hand / via MDM
ansible-playbook ../ansible/playbooks/deploy-forwarders.yml -e @../ansible/vars/onprem.yml \
    -e cs3_enrollment_file=$PWD/cs3-enrollment.json

# 3. Destroy the token file
shred -u cs3-enrollment.json
```

`hosts.csv` columns: `hostname` (required), `ip`, `platform` (`linux|windows|macos|container`), `osName`, `osVersion`, `arch`, `workloadType`, `group`.

## Scan agent (FIM / SCA / vulnerability)

Operators queue scans from the console (`POST /api/cecur/fim/scan`, `/sca/run`, `/vulnerabilities/scan` → `202` with a job). With no active enrolled agent the console answers `409`; it never returns canned results. `cs3-scan-agent.mjs` authenticates with the per-agent key from `/etc/cecur/forwarder.env` (`X-API-Key`, never argv):

```bash
install -m 0755 cs3-scan-agent.mjs /usr/local/lib/cecur/cs3-scan-agent.mjs
install -m 0644 systemd/cecur-scan-agent.service /etc/systemd/system/ && systemctl enable --now cecur-scan-agent
node cs3-scan-agent.mjs --once        # single poll, for testing
```

| Variable | Default | Meaning |
|---|---|---|
| `CS3_FIM_PATHS` | security-relevant `/etc` files | Comma-separated files/directories to baseline (SHA-256 + mode) |
| `CS3_FIM_BASELINE` | `/var/lib/cecur-scan/fim-baseline.json` | First run records the baseline (0 deviations); later runs report ADDED / MODIFIED / DELETED / PERMISSIONS_CHANGED |
| `CS3_SCAN_INTERVAL` | `30` | Poll interval, seconds |

SCA evaluates CIS Linux checks from local state (unreadable state is `MANUAL`, never `PASS`). Ubuntu vulnerability scans use `oscap` with Canonical's release-specific USN OVAL feed over verified HTTPS and require a package providing `oscap` (`libopenscap8` on Ubuntu 22.04), plus `bzip2` and `curl`; Debian uses `debsecan`, and RHEL-family hosts use `dnf updateinfo`. Ubuntu source packages use the installed source version reported by `dpkg`; USNs without a CVE reference retain their USN identifier. The supplied systemd unit permits `AF_NETLINK` because OpenSCAP's `system_info` probe requires netlink for interface inventory; removing it causes evaluation to fail before results are produced. Temporary OVAL data and results are removed after each job. Network gear in `PLB_Assets.csv` cannot run an agent and is shown as agentless; cover it with syslog relay and Errow.

## Gateway profile (Linux)

`install-forwarder.sh --profile gateway` turns a sensor node into an OpenTelemetry-compatible telemetry gateway: a local OTLP listener (HTTP and gRPC on one port), edge normalisation and redaction, a heartbeat plus self-metrics for anti-tamper monitoring, OTLP/gRPC mTLS egress to a central ESOC, HTTPS egress to a customer SIEM and an optional AI tier for Ollama nodes. Gateway flags are rejected without the profile, and a listener bound off-loopback requires mTLS.

```bash
CS3_SIEM_TOKEN=... ./install-forwarder.sh --console-url https://soc.example.internal --agent-id <agentId> \
    --profile gateway --esoc-host esoc.example.internal --esoc-cert client.crt --esoc-key client.key \
    --siem-url https://siem.example.internal/v1/events
```

Full design, variable reference, validation runbook and the optional Fluentd tier: [`../operations/fluent-telemetry-fabric.md`](../operations/fluent-telemetry-fabric.md). Re-run the installer with the same gateway flags to re-apply; omitting them reverts the host to the edge profile. The Windows installer has no gateway profile yet.

## Security properties

- Enrollment tokens are single use, expire (default 24 h, max 168 h) and are stored server-side only as SHA-256.
- The agent receives a **per-agent ingest key**; with `CS3_INGEST_REQUIRE_KEY=true` the console pins every event to that agent's id, so a compromised endpoint cannot impersonate another host.
- Installers refuse plaintext HTTP, pass the token via stdin/env (never argv), verify the Fluent Bit package checksum, and restrict config/key files to root / SYSTEM+Administrators.
- TLS: `--ca-file` for the internal PKI and optional `--pin-sha256` (SPKI pin). For mTLS client certificates see `../operations/mtls-certificate-pinning.md`; rotation: `../operations/certificate-rotation.md`.
- Gateway profile: the SIEM credential is read from `CS3_SIEM_TOKEN` / `--siem-token-file` (never argv), OTLP listeners off-loopback require client-certificate TLS 1.3, and the ESOC leg is mTLS TLS 1.3.
- The ingest endpoint accepts single events or JSON arrays (≤ `CS3_INGEST_MAX_BATCH`, default 1000), matching Fluent Bit's `Format json` batches.

Windows requirements: `curl.exe` (Windows 10 1803+/Server 2019+) and a locally supplied Fluent Bit Windows ZIP (air-gap friendly).
