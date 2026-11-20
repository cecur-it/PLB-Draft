# Endpoint asset and device prerequisites

Complete these checks **before bulk enrollment or forwarder installation**. This document applies to
endpoint assets; console, indexer, database, and model-host sizing remains in the root
[`README.md`](../../README.md#3-hardware--prerequisite-sizing) and the on-prem
[`02. VM & VyOS Prerequisites`](../../on-prem/Literature/02_VM_AND_VYOS_PREREQUISITES.md).

## 1. All endpoints

### Identity and inventory

- Use a unique, stable hostname and record its actual IP address, `platform`, `osName`, `osVersion`,
  `arch`, `workloadType`, and `group` in the enrollment inventory. Duplicate hostnames are rejected.
- Use the hostname the operating system reports, not merely a hypervisor display name. Windows
  computer names are limited to 15 characters; a longer Proxmox/VMware display name is permissible,
  but the Windows computer name used in inventory must still be valid and unique.
- Give each VM its own machine identity and MAC address. Do not clone an already enrolled endpoint or
  reuse another endpoint's agent ID, enrollment token, or ingest key.
- Patch the operating system and synchronize its clock with the site's approved NTP source. Time
  synchronization is necessary for TLS validation, token expiry, event correlation, and audit evidence.

### Network and TLS

- Provide outbound connectivity to the console's HTTPS host and port (TCP `443` by default). Normal
  forwarder and scan-agent operation requires no unsolicited inbound connection from the console.
- If the endpoint is on another subnet or VLAN, explicitly route and permit that connection through
  the site's firewall. Permit DNS only when required for name resolution and NTP according to site policy.
- Use an HTTPS URL whose hostname or IP address exactly matches the server certificate's SAN. The
  installers refuse plaintext HTTP console URLs.
- Trust the issuing CA through the operating-system trust store or supply the **public** CA certificate
  with `--ca-file` (Linux) / `-CaFile` (Windows). Never distribute the CA private key. Do not use
  `curl -k`, disable Fluent Bit `tls.verify`, or otherwise bypass certificate verification.
- Verify connectivity and certificate trust before minting a token. TCP reachability alone does not
  prove HTTPS trust.

### Installation media and evidence

- Obtain Fluent Bit from the configured trusted package source or supply the platform package and its
  publisher-provided SHA-256 digest. A new Windows ZIP installation refuses missing or malformed digests;
  the Linux installer warns for a missing local-package digest, and deployment acceptance still requires verification.
- Copy only the required installer, watchdog, template, parser, and optional scan-agent files to the
  endpoint. Preserve the repository's relative paths where an installer expects companion files.
- Keep a per-endpoint installation log containing timestamps, OS/network identity, package versions and
  hashes, commands/results, issues, and resolutions. Never record passwords, JWTs, enrollment tokens,
  ingest keys, private keys, or populated credential/configuration files.
- Take any clean-VM snapshot **before** introducing enrollment credentials. Use snapshots as recovery
  points, not as substitutes for backup or durable telemetry acceptance.

### Enrollment authority and secrets

- An administrator needs the `manage_fleet` permission and either `CS3_TOKEN` or
  `CS3_USERNAME`/`CS3_PASSWORD` supplied through the environment, never as command-line secrets.
- The bulk-enrollment CLI requires Node.js 18 or newer **on the machine where the CLI is run**. It does
  not need to be installed on every Windows endpoint.
- Dry-run the actual inventory first, then mint a separate one-time token for each agent. Tokens expire
  (24 hours by default; 168 hours maximum) and become invalid after a successful claim.
- Deliver each token only to its intended endpoint through an approved secret-transfer method. Delete
  the token output securely after all intended claims and evidence handling are complete.

## 2. Linux forwarder endpoints

Required for a new edge-forwarder installation:

- A supported systemd-based Linux distribution, Bash, and root access directly or through `sudo`.
- `curl`, CA certificates, standard file/process utilities, and `systemctl`.
- Fluent Bit already installed at the installer's expected location, an available trusted
  `apt`/`dnf` package, or a local `.deb`/RPM supplied with `--fluent-bit-pkg` and
  `--fluent-bit-sha256`. Local package installation requires `dpkg` or `rpm`; checksum verification
  requires `sha256sum`.
- Sufficient disk space for the OS, Fluent Bit, logs, and the configured filesystem buffer. Review the
  buffer limit in `templates/fluent-bit-linux.conf` against the expected event rate and outage window.
- The Linux installer, watchdog, Fluent Bit template, and `templates/parsers.conf` companion file.

Optional Linux scan agent:

- Node.js 18 or newer and the `cs3-scan-agent.mjs` plus systemd service files.
- Vulnerability results require a package providing `oscap` (`libopenscap8` on Ubuntu 22.04;
  `openscap-scanner` on releases with split scanner packaging), plus `bzip2` and `curl` on Ubuntu;
  `debsecan` on Debian; or `dnf updateinfo` on RHEL-family hosts. Ubuntu also needs outbound verified HTTPS access to
  `security-metadata.canonical.com` for the release-specific USN OVAL feed. Debian's tracker is not a valid
  Ubuntu OVAL/debsecan data source. Missing tooling, download failures, evaluation failures, and malformed
  results must produce a failed/unsupported result, never a fabricated pass. Retain `AF_NETLINK` in the scan
  unit's `RestrictAddressFamilies` allow-list: OpenSCAP's `system_info` probe uses netlink for interface
  inventory, and `AF_UNIX` alone does not satisfy that requirement.
- FIM and SCA coverage is the Linux behavior implemented by `cs3-scan-agent.mjs`; review its configured
  paths and checks before assigning compliance meaning to the output.

The forwarder's **gateway profile is Linux-only**. Its additional OTLP, mTLS, SIEM, and AI-tier
prerequisites are documented in
[`../operations/fluent-telemetry-fabric.md`](../operations/fluent-telemetry-fabric.md).

## 3. Windows forwarder endpoints

Required for a new installation:

- Windows 11, Windows 10 1803 or newer, or Windows Server 2019 or newer with PowerShell 5.1 or newer.
- An elevated Administrator PowerShell session, `curl.exe`, and the built-in archive, hashing, service,
  and scheduled-task capabilities used by the installer.
- A locally supplied Fluent Bit Windows ZIP and its publisher-provided 64-character SHA-256 digest.
  The installer requires `-FluentBitSha256` and verifies it with `Get-FileHash` before extraction.
- `Install-CecurForwarder.ps1`, `Test-CecurForwarder.ps1`, and
  `templates/fluent-bit-windows.conf`, preserving their relative locations.
- HTTPS CA trust or the public CA file passed with `-CaFile`; optionally use `-PinSha256` for SPKI pinning.

Node.js is **not** required for the Windows forwarder. The default template collects the `Security`,
`System`, `Application`, and `Microsoft-Windows-PowerShell/Operational` channels. Configure Windows
Audit Policy and PowerShell logging according to site requirements: the forwarder cannot collect events
that Windows does not generate.

The repository currently provides **no Windows equivalent** of the Linux FIM/SCA/vulnerability scan
agent and no Windows gateway profile. Windows acceptance must therefore distinguish event-forwarding
health from unsupported scan capabilities.

### Windows 11 VM provisioning baseline

Virtualization settings are separate from the CS3 installer's requirements. A practical Proxmox lab
starting point is:

| Setting | Recommended starting point |
|---|---|
| Machine / firmware | Q35, OVMF (UEFI), EFI disk, TPM 2.0 |
| CPU / memory | 1 socket, 4 cores, 8 GiB RAM |
| Disk | 100 GiB VirtIO SCSI |
| Network | VirtIO (paravirtualized), connected to the intended LAN bridge |
| Integration | VirtIO drivers ISO and QEMU Guest Agent |

These are planning defaults, not agent-enforced minima; resize from observed workload. Attach the
Windows installation ISO and the VirtIO drivers ISO, and configure the intended DVD as the first boot
device. During installation, the VirtIO network driver is under `NetKVM\w11\amd64` (or the compatible
`w10\amd64` directory on media without a Windows 11 directory). Record the actual driver and ISO versions
used in the installation log.

Two common Proxmox installation recovery points are:

- **`BdsDxe` DVD timeout followed by PXE/HTTP boot:** fully stop the VM, verify that the CD/DVD device
  contains the Windows ISO rather than no media or the VirtIO ISO, put that DVD first in the boot order,
  and temporarily disable network boot. Retry the corresponding `UEFI QEMU DVD-ROM` entry from the OVMF
  Boot Manager. Re-upload or replace the ISO if verified configuration still times out.
- **Windows OOBE offers no network and displays “Install driver”:** attach the VirtIO drivers ISO and
  install the Red Hat VirtIO Ethernet Adapter from the `NetKVM` directory. Once Windows has reached OOBE,
  the installation DVD can normally be changed to the VirtIO ISO without rebooting; alternatively attach
  a second CD/DVD device. Record which method and driver directory succeeded.

## 4. Other assets and agentless devices

The enrollment schema accepts `macos` and `container` inventory values, but the automated forwarder
installers in this directory are Linux and Windows only. Enrollment alone does not prove that a native
collector exists or telemetry is flowing; use a separately reviewed deployment path and validate it.

Network appliances and other PLB assets that cannot run an agent remain agentless. Collect genuine
syslog through a documented relay, preserve source attribution, and validate each expected device rather
than treating the relay's own test event as proof of fleet coverage.

## 5. Readiness gate

Do not claim an endpoint is onboarded until all applicable items are true:

- [ ] Actual hostname, IP, OS, architecture, and workload are recorded and match the enrollment inventory.
- [ ] Time, routing, DNS (if used), outbound HTTPS, and certificate verification succeed without bypasses.
- [ ] Required installer companions and checksum-verified Fluent Bit media are present.
- [ ] A unique, unexpired enrollment token is ready to be delivered securely.
- [ ] Unsupported platform capabilities are recorded rather than implied.
- [ ] Installation and acceptance logs have a secret-free destination.
- [ ] After installation, service/watchdog health, genuine event ingestion, `indexed:true`, direct
      OpenSearch evidence, restart durability, and the audit chain are accepted according to
      [`../../on-prem/Literature/04_VALIDATION_AND_ACCEPTANCE.md`](../../on-prem/Literature/04_VALIDATION_AND_ACCEPTANCE.md).
