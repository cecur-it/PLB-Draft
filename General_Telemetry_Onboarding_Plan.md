# General Telemetry Onboarding & Coverage Plan

**Status:** Generalized implementation template

**Companion:** [General_Playbook.md](General_Playbook.md)
**Required inputs:** approved device inventory, network design, change policy, device/vendor documentation, and a lab or isolated deployment

> This plan contains no site-specific hostnames, addresses, device counts, credentials, or firmware assumptions. Replace every `<PLACEHOLDER>` and complete every site-validation gate before production use. `[REPO]` describes this checkout; `[LOCAL-TEST]` describes synthetic local validation only; `[PROPOSED]` is not a shipped feature; `[SITE-VALIDATE]` requires target-environment evidence.

## 1. Objectives and non-negotiable outcomes

Onboard each approved telemetry source without weakening existing monitoring or claiming more than the evidence proves.

A deployment is ready for operational acceptance only when:

1. The inventory and proposed infrastructure are reconciled and owned.
2. Each source has a supported, tested transport and a recorded rollback.
3. A benign event from each source reaches the console hot cache (**C2**).
4. An event from each source is found directly in OpenSearch before and after a console restart (**C3 durability**).
5. A **fresh** post-restart event returns `indexed:true` and is found in OpenSearch, and fleet operability is checked.
6. Attribution, parser behavior, outage behavior, capacity, and security limitations are recorded explicitly.

HTTP 200/201, `success:true`, a relay queue, a hot-cache result, or a database row alone is not durable telemetry evidence.

## 2. Sources of truth and evidence hierarchy

| Artifact | Owner | Required content | Acceptance evidence |
|---|---|---|---|
| `<INVENTORY.csv>` | Asset owner | Stable device ID, hostname, management address, model, running/target OS, site, network, role, criticality, existing monitoring, backup owner | Reconciled export plus owner approval |
| `<SOURCE_MATRIX>` | Network/security operations | Emitted format, transport, destination port, source interface/address, event roles, severity, CLI/Dashboard path | Exact-version vendor reference plus target lab result |
| `<ATTRIBUTION_MAP>` | Telemetry operator | Observed sender endpoint, parsed hostname/device field, mapped `agentName`, NAT/proxy behavior | Sanitized packet/event captures and mapped records |
| `<EXPECTATIONS.json>` | Telemetry operator + reviewer | One entry per expected device/event identity | Two-person review; successful fail-closed verifier |
| `<CHANGE_RECORD>` | Change owner | Approval, commands/configuration, before/after evidence, rollback, operator, timestamps | Closed change with linked evidence |
| `<CAPACITY_RECORD>` | Platform owner | Events/day, event sizes, retention, disk/memory/CPU, outage budget | Load/soak test and approved thresholds |

Evidence strength, strongest first:

1. Target-like or production change-window execution with saved output.
2. Isolated execution of the exact configuration/version with synthetic input.
3. Repository source and configuration reading.
4. Vendor documentation or architectural inference.

Do not promote a lower evidence tier into target-environment certification. Retain the assessment's inline confidence annotations until the stated check is complete.

## 3. Architecture decision

### 3.1 Native building blocks `[REPO]`

- CS3 console and `POST /api/cecur/logs/ingest`.
- Optional OpenSearch sink for durable indexed logs.
- Host forwarder enrollment for supported `linux`, `windows`, `macos`, and `container` platform values.
- Linux gateway forwarder with filesystem buffering, local Fluent Bit health endpoint, systemd service/watchdog, and an output matching `host.*` and `v1_logs`.
- A shared Lua normalizer that accepts `message` or `log`, strips specified controls, truncates messages, maps known severity names, and redacts common secret patterns in the normalized message.
- A fail-closed verification script for synthetic ingest, direct OpenSearch queries, and optional console restart checks.

### 3.2 Proposed site architecture `[PROPOSED]` `[SITE-VALIDATE]`

```text
Supported host ── native forwarder ───────────────┐
                                                 │
Network appliance ── syslog ──> enrolled relay ──┼── HTTPS ──> TLS proxy ──> CS3 console
                                                 │                    │
Existing monitoring ── optional approved bridge ─┘                    ├── PostgreSQL
                                                                      └── OpenSearch
```

The relay is one enrolled fleet identity. Devices behind it do **not** become separately enrolled CS3 agents. Per-device `agentName`, parsed hostnames, `devname`-like text, and sender mappings are attribution fields, not cryptographic device identity. Protect the relay and its configuration accordingly.

For appliances, state only that **no supported native CS3 host-forwarder path is assumed**. A third-party collection package is a separate design requiring its own support and security review.

### 3.3 Native-versus-proposed register

| Capability | Status | Onboarding consequence |
|---|---|---|
| Host enrollment/forwarding | Shipped `[REPO]` | Use documented supported platforms and enrollment flow. |
| Gateway output, buffer, health endpoint | Shipped `[REPO]` | Test actual drain and failure behavior; queueing is not indexing. |
| Network-syslog fragment in `deployment/agents/templates/gateway.d/` | Not shipped | Treat the Playbook fragment as `[PROPOSED]`; add code/tests before calling it native. |
| Corrected `syslog` input example | `[LOCAL-TEST]` + `[PROPOSED]` | Synthetic RFC3164 UDP/TCP passed on Fluent Bit 5.1.5; every real format remains unverified. |
| Raw `udp`/`tcp` `Format none` sender attribution | Rejected for this design | Local 3.2.10, 4.0.0, and 5.1.5 tests did not emit `source_ip`; do not deploy that mapping. |
| SNMP polling, cloud-management API connector, monitoring bridge | Not shipped in CS3 | Optional integrations require separate design, implementation, and tests. |
| Nginx/firewall/vendor configuration | `[PROPOSED]` examples | Translate under network/security change control. |
| Per-device cryptographic identity through one relay | Not provided | Record attribution risk; use authenticated per-device/integration design if required. |

## 4. Coverage model

| Level | Meaning | Minimum evidence | Not proved |
|---|---|---|---|
| **C0 — Not onboarded** | No approved telemetry configuration | Inventory row and owner | Any delivery |
| **C1 — Configured** | Source and relay configuration saved under change control | Before/after configuration, running version, operator, rollback | Packet arrival or indexing |
| **C2 — Verified arrival** | A unique benign event reaches CS3 with expected recorded attribution | Event timestamp/token, packet/relay evidence, authenticated `GET /api/cecur/logs?search=<TOKEN>&limit=...` match, observed `agentName` and sender field | Durability, continuous delivery, authenticated identity |
| **C3 — Durable** | Per-device evidence is independently indexed and survives console restart | `indexed:true` for synthetic relay check; direct OpenSearch match for every expectation before/after restart; healthy console | Fresh post-restart ingest, fleet recovery, source outage behavior |
| **C3+ — Operable after restart** | C3 plus renewed service operation | Fresh post-restart source/relay event returns `indexed:true` and appears in OpenSearch; `/api/fleet/summary` checked; missing relay re-enrolled under change control | Long-term availability |
| **C4 — Enriched (optional)** | Additional metrics/availability/flow context | Explicit integration evidence and ownership | Required for initial C3 acceptance |

**Minimum rollout gate:** C3+ for every in-scope source. C4 is optional and separately funded/designed.

`GET /api/cecur/logs` is a bounded 300-row in-memory cache with a default result limit of 100 `[REPO]`. It is a C2 tool, not a durable search interface.

## 5. Inventory reconciliation gate

Do not copy an inventory into configuration without validation.

### 5.1 Required inventory template

```csv
device_id,hostname,management_ip,site,network,role,model,running_os,target_os,criticality,existing_monitoring,config_backup,owner,change_window
<DEVICE_ID>,<HOSTNAME>,<MANAGEMENT_IP>,<SITE>,<NETWORK>,<ROLE>,<MODEL>,<RUNNING_OS>,<TARGET_OS>,<CRITICALITY>,<MONITORING>,<BACKUP>,<OWNER>,<WINDOW>
```

### 5.2 Reconciliation checks

- [ ] Row count and unique stable device IDs match the approved export.
- [ ] Every device appears in the source matrix, attribution map, expectation manifest, and tracker exactly once.
- [ ] Proposed console/relay infrastructure is listed separately from existing assets.
- [ ] Model and OS names come from `show version`/Dashboard or an approved source; conflicts remain open until reconciled.
- [ ] Duplicate management/source addresses are explained as HA, NAT, shared management, or error.
- [ ] Blank required/target versions are **unknown**, not compliant.
- [ ] Source addresses are observed on the relay, not assumed to equal management addresses.
- [ ] Existing SNMP, metrics, configuration backup, and availability monitoring remain unchanged unless separately approved.
- [ ] Every row has an owner, change window, event trigger, and rollback.

**Stop:** unresolved identity/address conflicts that prevent independent per-device evidence block that device's wave.

## 6. Source capability matrix

Complete one row per device class/version, then confirm every device in that class.

| Field | Required value |
|---|---|
| Device class / exact running and target version | `<VENDOR_MODEL_OS>` |
| Configuration interface and path | `<CLI_OR_DASHBOARD_PATH>` |
| Syslog format/framing | `<RFC3164_RFC5424_VENDOR_OTHER>` |
| Transport and destination | `<UDP_OR_TCP> <RELAY_IP>:<PORT>` |
| Source interface and observed sender | `<INTERFACE>` / `<OBSERVED_ENDPOINT>` |
| Event roles/categories and starting severity | `<CATEGORIES>` / `<SEVERITY>` |
| Stable benign trigger and expected token | `<ACTION>` / `<MESSAGE_TOKEN>` |
| Parser and mapping | `<PARSER>` / `<RULE_ID>` |
| Rollback | `<EXACT_ROLLBACK>` |
| Evidence/confidence | `<COMMAND_OUTPUT_OR_VENDOR_REFERENCE>` |

Vendor-derived starting points:

- Cisco IOS/IOS XE custom-port syntax must be obtained from the exact running version (`logging host ?`) and tested. Use a standard-port fallback only after approving a   listener/privilege/firewall design.
  <!-- confidence: inference -->
- FortiOS vendor CLI references document `status`, `server`, `mode`, `port`, `facility`, `source-ip`, `format`, and severity filtering on the reviewed release. Confirm every field against the exact target version. `source-ip` chooses egress; it does not configure CS3 attribution.
  <!-- confidence: inference -->
- For a Meraki MR target earlier than 33.1, use UDP for this design; MR TCP requires MR 33.1 or later. Do not infer MS transport or sender behavior from MR documentation.
  <!-- confidence: inference -->
- Cloud-managed device delivery during Dashboard/internet loss is firmware/network-specific;   neither continuous delivery nor buffering is assumed.
  <!-- confidence: inference -->

These statements are not substitutes for exact-device execution.

## 7. Attribution and parser gate

### 7.1 Required design

1. Use the corrected **`syslog` input** example in the Playbook for a format supported by its selected parser; do not use raw `udp`/`tcp` `Format none` with `Source_Address_Key` for sender mapping.
2. Capture a sanitized sample from every device class and protocol before writing mappings.
3. Test parser acceptance, timestamp handling, message preservation, severity, and malformed/partial input behavior.
4. Map the **observed** sender endpoint. Fluent Bit 5.1.5 local testing produced values such as `udp://127.0.0.1:<ephemeral-port>` and `tcp://127.0.0.1:<ephemeral-port>`, not a bare IP `[LOCAL-TEST]`.
5. Use anchored regex conditions for the transport/IP form, or a separately tested normalization function. Do not use exact bare-IP equality against that observed value.
6. Repeat one mapping for every unique observed sender; record unmapped fallback behavior and alert on it.
7. Prefer unique source addresses. If addresses are shared, require a stable, unique, lab-verified message identity under normal and failover operation.
8. Do not add `Raw_Message_Key` without extending and testing redaction: local testing showed the existing normalizer can leave an added raw copy unredacted in `fields` `[LOCAL-TEST]`.

### 7.2 Corrected local evidence

The Playbook's proposed fragment was executed with synthetic RFC3164 messages on Fluent Bit 5.1.5. Dry-run succeeded; UDP and TCP outputs contained mapped `agentName:"TEST-DEVICE"`, transport-qualified `fields.source_ip`, and redacted password/Bearer values. This does not validate vendor messages, production TLS, OpenSearch, or the target Fluent Bit deployment.

### 7.3 Security boundary

Sender IP, parsed hostname, message tokens, and `agentName` can be spoofed on an untrusted network or by a compromised relay. UDP provides no transport authentication or guaranteed delivery. Restrict sender networks, protect relay configuration, and record that C3 proves recorded arrival/attribution only.

## 8. Expectation manifest

Create `<EXPECTATIONS.json>` from reviewed inventory and observed events:

```json
[
  {
    "device": "<STABLE_DEVICE_ID>",
    "message": "<UNIQUE_OBSERVED_MESSAGE_TOKEN>",
    "agentName": "<EXPECTED_MAPPED_NAME>",
    "sourceIp": "<OPTIONAL_REVIEWED_MATCH_TEXT>"
  }
]
```

Rules:

- One or more intentional entries per required device/event identity; `--expect-count` must exactly equal the array length.
- `message` must come from a real benign trigger, not an assumed hostname.
- `agentName` must match the tested relay mapping.
- `sourceIp` is optional in the verifier. Because the observed field includes transport and ephemeral port, leave it empty unless a stable match has been tested; retain the full observed sender in wave evidence.
- Do not use a dynamic source port as a permanent expectation.
- The manifest is static, not automatic discovery. Review it after inventory, NAT, parser, mapping, or firmware changes.

## 9. Standard per-device runbook

1. **Authorize:** confirm owner, scope, exact model/version, change window, event trigger, and rollback.
2. **Baseline:** save configuration, health, existing monitoring, current routes, and recent event volume.
3. **Confirm infrastructure:** console/indexer healthy; forwarder service and `/api/v1/health` healthy; required UDP/TCP listeners present; ingest key enforcement and indexing enabled.
4. **Confirm network:** routing, DNS where used, NTP, TLS trust, host/network firewall, source interface, and maximum approved event rate.
5. **Stage relay configuration:** dry-run the exact binary/config, parser-test sanitized samples, complete mapping, and confirm no unredacted raw copy.
6. **Configure one canary source:** apply the smallest approved change; do not alter unrelated monitoring.
7. **Prove transport:** capture relay packets and inspect forwarder logs/listeners. Lack of packets stops the wave before console debugging.
8. **Trigger a benign event:** record UTC time and unique token. Avoid disruptive failover or security events unless separately approved.
9. **Prove C2:** query the hot cache and save the matching record, mapped name, sender field, and event timestamp.
10. **Prove C3:** run the Playbook verifier with the reviewed wave manifest, direct OpenSearch credentials/trust, exact count, recorded `--since`, and `--restart-console`.
11. **Prove C3+:** check fleet summary, restore/re-enroll missing runtime fleet membership under change control, generate a fresh event, require `indexed:true`, and find its new ID in OpenSearch.
12. **Observe:** watch errors, buffer drain, event rate, CPU/memory/disk, parser drops, and unmapped fallback for the approved soak period.
13. **Record/rollback:** complete the tracker. Roll back on any stop criterion and verify baseline restoration.

## 10. Waves and stop criteria

| Wave | Scope | Entry gate | Exit gate |
|---|---|---|---|
| **0 — Lab** | Target-like console/indexer, relay, synthetic and sanitized device samples | Approved design and backups | Correct parser/mapping, redaction, C3+ synthetic evidence, rollback rehearsed |
| **1 — Canary** | One low-risk representative device | Wave 0 passed; production change approved | C3+, stable soak, no unresolved identity or capacity issue |
| **2 — Peer class** | Small batch sharing the validated class/version | Canary evidence reviewed | Every expectation passes; aggregate load within budget |
| **3 — Critical/shared** | Core, clustered, NAT/shared-address, high-volume sources | Unique attribution and rollback proven; separate windows | Independent C3+ per node and normal/failover behavior where required |
| **4 — Remaining fleet** | Approved batches by site/class | Prior wave stable | Full manifest C3+, operational handoff, evidence archived |

Stop and roll back the affected wave for any of:

- unresolved/duplicate attribution or unexpected fallback-to-relay identity;
- parser drops, malformed timestamps, unredacted secrets, or unexpected event content;
- `indexed:false`, missing direct OpenSearch evidence, or failed restart/fresh-event gate;
- repeated HTTP 401/413/429/503, TLS failures, or sustained output errors;
- buffer growth without drain, disk exhaustion, or capacity threshold breach;
- loss of existing monitoring, network/service impact, or failed rollback rehearsal.

## 11. Tracker template

| Device ID | Class/version | Wave | Owner | C1 change/evidence | C2 token/record | C3 query IDs | C3+ fresh ID/fleet check | Coverage | Blocker/rollback |
|---|---|---|---|---|---|---|---|---|---|
| `<DEVICE_ID>` | `<CLASS_VERSION>` | `<WAVE>` | `<OWNER>` | `<LINK>` | `<LINK>` | `<IDS>` | `<ID_AND_CHECK>` | `C0` | `<STATUS>` |

Store evidence without credentials or sensitive payloads. Link to sanitized configuration, packet metadata, console record, OpenSearch index/document IDs, and change record.

## 12. Risks and operational decisions

| Risk/decision | Required disposition before sign-off |
|---|---|
| Runtime fleet membership is not hydrated from PostgreSQL on console restart `[REPO]` | Test `/api/fleet/summary` and fresh ingest; re-enroll if required. Database rows are insufficient. |
| Registered-user persistence/IAM limitation `[REPO]` | Implement durable/external IAM or explicitly restrict/risk-accept a pilot, including offboarding and break-glass recovery. |
| OpenSearch sink can fail while HTTP reports success `[REPO]` | Require `indexed:true` and direct indexed-document evidence; monitor sink health. |
| Relay filesystem buffer | Size and test it, but never count it as C3 storage. Define disk-full and maximum-outage behavior. |
| UDP loss/spoofing | Restrict networks and quantify acceptable loss; use tested TCP/TLS design where required/supported. |
| Parser/version drift | Re-run sample, C2, and C3+ tests after collector or device firmware changes. |
| High-volume flows/traffic/URLs | Disabled initially unless capacity and security review approve them. |
| Heartbeat/availability | Syslog cadence is only a surrogate. Keep existing monitoring or separately implement an approved heartbeat bridge. |
| Retention/archive | ISM and external archive are separate controls; prove snapshot/archive and restore, not just policy presence. |
| Audit export | The API export is an in-memory window, not necessarily the full durable ledger; use durable backup/query procedures for compliance evidence. |

## 13. Final handoff package

- [ ] Approved inventory, source matrix, attribution map, and expectation manifest with version/confidence evidence.
- [ ] Installed versions and sanitized console/relay/indexer configuration.
- [ ] Full C2/C3/C3+ results and fresh post-restart OpenSearch document IDs.
- [ ] Fleet/IAM recovery result and risk decision.
- [ ] Outage, buffer drain, capacity, parser, malformed-input, and redaction results.
- [ ] Backup, restore, retention/archive, certificate rotation, and rollback evidence.
- [ ] Open gaps with owners/dates; no unresolved item silently relabeled as supported.
- [ ] Operational ownership, monitoring thresholds, update/revalidation cadence, and access to `General_Playbook.md`.
