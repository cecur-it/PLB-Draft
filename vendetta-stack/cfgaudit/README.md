# Cfgaudit for Vendetta

Cfgaudit is an optional, offline network-configuration assessment producer. The maintained Python source, CLI, rule engine, tests, and supplied sample configurations live here; no prebuilt executable, `.pyz`, or other unsigned binary is shipped. The samples are deliberately insecure test fixtures; never reuse their example credentials.

The initial Vendetta integration is deliberately limited to **manual file audits, findings, and run summaries**. It does not replace Vendetta SCA, collect device configurations, assert complete compliance, or feed Errow's SARIF/Vendetta alert pipelines.

## Capabilities and boundaries

- Cisco IOS, NX-OS, ASA, Palo Alto set-format, and FortiGate configuration parsing.
- 49 hardening checks plus two shadow-analysis rules. Native shadow analysis is available without services; the CLI can optionally use Batfish.
- Text, JSON, and HTML reports from `cfgaudit`; an optional Tkinter GUI from `cfgaudit-gui`.
- Append-only `cfgaudit.findings` and `cfgaudit.runs` NDJSON streams from `cfgaudit-adapter`.
- Dedicated OpenSearch indices and retention policies. No SARIF conversion, LLM triage, feedback, cloud retest, active response, Console, ESOC, or SIEM fan-out.

A run or asset marked `pass`/`fail` describes only the selected Cfgaudit checks. Framework references can be `direct`, `related`, or `indicative`; NIST SP 800-53 references are indicative. Native shadow analysis does not fully model object groups, FQDN/geo objects, schedules, negation, or some application semantics. Review parser coverage and findings against the actual device OS/version.

### Benchmark mapping provenance and limits

`MAPPINGS` in `cfgaudit/engine.py` records per-rule, per-vendor mappings. `direct` means the benchmark tests the same behavior; `related` means the same control area with a different scope or threshold. The supplied prototype cites Cisco IOS XE Router NDM STIG V3R4, Cisco NX-OS Switch NDM STIG, Cisco ASA NDM STIG, Palo Alto NDM V3R3/ALG V3R4, Fortinet FortiGate NDM V1R5 and Firewall STIGs, CIS Cisco IOS XE 16.x v2.2.0 L1, CIS Cisco NX-OS v1.1.0 L1, and CIS FortiGate 7.0.x v1.4.0. Re-check every reference against the benchmark release used for a deliverable; numbering varies between releases.

Coverage is incomplete. The prototype explicitly leaves some NX-OS, FortiGate, shadow, IOS, ASA, and Palo Alto mappings unverified or unmapped; an empty framework list is not evidence that a control does not apply.

## Install and run locally

Python 3.9 or newer is required. The CLI and adapter have no mandatory third-party runtime dependencies.

```bash
cd vendetta-stack/cfgaudit
python3 -m venv .venv
.venv/bin/python -m pip install .

.venv/bin/cfgaudit --list-rules
.venv/bin/cfgaudit samples/edge-rtr1.cfg --format json --output report.json
.venv/bin/cfgaudit samples/asa-fw1.cfg --min-severity High --fail-on Critical
```

The GUI is optional and uses the Tkinter supplied by the operating system/Python installation. It is not imported by the CLI or adapter and is not required on headless hosts.

```bash
.venv/bin/cfgaudit-gui
```

Batfish support is an optional CLI dependency, not an adapter dependency:

```bash
.venv/bin/python -m pip install '.[batfish]'
.venv/bin/cfgaudit samples/asa-fw1.cfg --shadow batfish --batfish-host localhost
```

## Produce NDJSON

```bash
.venv/bin/cfgaudit-adapter \
  --output-dir /secure/path/cfgaudit \
  --evidence redacted \
  samples/edge-rtr1.cfg samples/nxos-sw1.cfg
```

The adapter appends to two files and never emits a raw configuration:

| File | Logical stream | Contents |
|---|---|---|
| `findings.ndjson` | `cfgaudit.findings` | One record per failed selected check |
| `runs.ndjson` | `cfgaudit.runs` | One lifecycle/severity/per-asset summary per invocation |

Use `--evidence none` for hash-only evidence. The default `redacted` mode masks lines containing common password, community, token, key, and authorization material; redaction is defense in depth, not a guarantee that every secret form is recognized. Treat output as sensitive and restrict its directory and files. `--vendor`, `--min-severity`, `--shadow native|off`, and `--fail-on` are also available. The adapter supports native or disabled shadow analysis; Batfish remains available through the CLI.

New stream files are created with mode `0600`; writes flush and `fsync`. Replaying the same NDJSON is safe at the OpenSearch document level. Exit codes are `0` for a run with audited files (including partial runs with warnings), `1` when no file could be audited, and `2` when `--fail-on` is met.

### Record contracts and identity

JSON Schema Draft 2020-12 contracts are packaged at `cfgaudit/schemas/finding.schema.json` and `cfgaudit/schemas/run.schema.json`. They include asset identity, control/framework mappings, status, UTC timestamps, original config-byte SHA-256, canonical original-evidence SHA-256, and deterministic finding identity. Raw evidence is hashed before redaction, so changing evidence display mode does not change IDs.

- `asset.id = SHA256(lowercase(vendor) + NUL + lowercase(hostname))`
- `finding.key = SHA256(canonical_json({asset_id, control_id}))`
- `finding.id = SHA256(canonical_json({finding_key, evidence_sha256, schema_version}))`
- `doc_id = finding.id`; run `doc_id` is the invocation UUID.

Timestamps and run IDs are excluded from finding identity. An unchanged finding therefore has the same OpenSearch `_id` across runs, while each invocation has a separate run summary. A changed evidence hash intentionally produces a new finding ID; drift correlation is not enabled in this phase.

## Manual Compose ingestion

This phase supports Compose/manual file ingestion only; Kubernetes/Helm/Kustomize collection wiring is not enabled.

1. Create the host directory before starting Compose. Docker can otherwise create a missing bind-mount source as root-owned.
2. Arrange for the adapter to write and for Fluent Bit, running as UID/GID `10001`, to read. The simplest ownership model is to run both as that identity; alternatively use a shared group or ACL and explicitly grant read access after the adapter creates its `0600` files. The container mount is read-only, but host permissions still apply.
3. Generate only `findings.ndjson` and `runs.ndjson` in that directory; do not place raw configurations there.
4. Enable the input and restart Fluent Bit.

Example ownership model for a Linux host (the adapter installation and input configurations must also be readable by UID `10001`):

```bash
cd vendetta-stack
sudo install -d -o 10001 -g 10001 -m 0700 data/cfgaudit
sudo -u '#10001' -g '#10001' /path/to/venv/bin/cfgaudit-adapter \
  --output-dir "$PWD/data/cfgaudit" --evidence none /secure/configs/edge-rtr1.cfg
```

Set these values in `.env`:

```dotenv
CFGAUDIT_ENABLED=true
CFGAUDIT_REPORTS_DIR=./data/cfgaudit
```

Then run `docker compose up -d fluent-bit`. Enabling the integration with a missing/unreadable directory fails startup with environment error code `3`. The normal OpenSearch initialization/apply process installs the templates and ISM policies before Fluent Bit starts.

Validate in OpenSearch Dashboards Dev Tools:

```text
GET cfgaudit-findings-*/_search
{"size": 5, "query": {"term": {"finding.id": "<adapter doc_id>"}}}

GET cfgaudit-runs-*/_search
{"size": 5, "sort": [{"run.completed_at": "desc"}]}

GET _plugins/_ism/explain/cfgaudit-findings-*
GET _plugins/_ism/explain/cfgaudit-runs-*
```

Run the same audit twice and confirm that finding IDs repeat without duplicate logical findings, while run IDs remain distinct. Verify warnings and severity counts against local CLI output, confirm redaction/hash-only evidence, and confirm no Cfgaudit marker appears in `errow-*`, `vendetta-alerts-*`, or AI indices. Disable with `CFGAUDIT_ENABLED=false` and restart Fluent Bit; already indexed data remains governed by its retention policy.

## Storage and retention

| Stream | Daily index pattern | Hot | Warm | Cold | Delete |
|---|---|---|---|---|---|
| `cfgaudit.findings` | `cfgaudit-findings-*` | 0–90 days | 90–365 days | After 365 days and a successful snapshot | 2555 days |
| `cfgaudit.runs` | `cfgaudit-runs-*` | 0–30 days | 30–90 days | After 90 days and a successful snapshot | 365 days |

Cold allocation and snapshots require appropriately labeled nodes and the `vendetta-snapshots` repository. Mappings use `dynamic: false` and `ignore_malformed: false`; unknown source fields are retained but not indexed. Findings and runs use independent Fluentd buffers and no ingest pipeline.

## Validation gates

Dashboards and selective High/Critical alerting are deferred until ingestion, identity, evidence handling, and operational usefulness are validated. Scheduled collection and drift detection remain deferred until the audit engine proves accurate against representative **real customer configurations** for each supported vendor/OS version. That validation should include known-good and known-bad cases, expected findings, false positives/negatives, shadow-analysis limitations, and signed-off remediation review. No scheduler, device credential store, network collector, dashboard, alert route, or drift engine is included now.

## Tests

```bash
cd vendetta-stack/cfgaudit
.venv/bin/python -m pip install '.[test]'
.venv/bin/python -m pytest
.venv/bin/python tests/test_shadow.py

cd ..
tests/check-manifest.sh
fluent-bit/tests/validate.sh
fluent-bit/tests/test_legs.sh
fluentd/tests/validate.sh
fluentd/tests/test_routing.sh
opensearch/tests/run-tests.sh
```
