# 04. Validation & Acceptance — Proving No Mock Data and Durable Ingestion

This is the acceptance procedure referenced by `checklists/go-live-checklist.md`. Each step cites
the exact code path it exercises so the result is falsifiable, not a vibe check.

## 1. Prove demo mode is off

```bash
on-prem/bin/preflight-check.sh
```

Fails closed if `CS3_DEMO_MODE=true`. The seed data and simulated tick loop that this flag used to
control have been removed from the console, and `assertNoDemoMode()` (`server/profile.ts`) makes the
console itself refuse to start with the flag set. If this check passes, no code path in the running
console can be generating synthetic data.

## 2. Prove the console starts with zero seed data

On a freshly provisioned on-prem console (before any enrollment), `GET /api/cecur/agents` and
`GET /api/cecur/logs` should return only the single bootstrap admin context and no synthetic
agents/log history — contrast with `demo/demo-100226` where `generateInitial*()` pre-populates many
rows. There is no dedicated script for this because it is inherently a "before you do anything
else" observation; capture it in your go-live evidence (e.g. a screenshot or saved API response) if
your compliance framework requires attestation.

## 3. Prove a real endpoint can enroll and forward telemetry

```bash
on-prem/bin/enroll-real-endpoints.sh --url https://cs3.example.internal --file hosts.csv --group prod
# ... roll out the forwarder per Literature/03_REAL_ENDPOINT_ONBOARDING.md ...
on-prem/bin/verify-real-telemetry.sh --url https://cs3.example.internal/api/cecur/logs/ingest --ingest-key <per-agent key> --agent-id <enrolled agent id> --token "$CS3_TOKEN"
```

`verify-real-telemetry.sh` posts a uniquely marked event through the real ingest path
(`POST /api/cecur/logs/ingest`, authenticated with the forwarder's own per-agent key — not a shared
secret), requires both `success:true` and `indexed:true`, and confirms it is retrievable via `GET /api/cecur/logs` and directly in OpenSearch. HTTP 201/`success:true` with `indexed:false` is a failure, not a hot-cache-only pass.

## 4. Prove telemetry is durable (survives a restart), not just in the 300-row hot cache

`CS3_INDEXER_ENABLED=true` and host-reachable `CECUR_INDEXER_URL` (or `CECUR_INDEXER_VERIFY_URL`) plus credentials are mandatory; the verifier never skips direct OpenSearch checks. This is deliberately **not** done by re-polling `GET /api/cecur/logs` after restart, because that route only reads the in-memory hot cache. Production needs CA trust; `CECUR_INDEXER_TLS_INSECURE=true` is lab-only.

Use `--restart-console` for acceptance. The script queries evidence, restarts the console in `CS3_COMPOSE_DIR` (default `deployment/docker`), waits for `/api/health`, and repeats every direct query. The hot-cache marker disappearing after restart is expected; the OpenSearch marker must remain.

For PLB, a synthetic relay marker is only a path check. Review/lab-correct `on-prem/plb-c3-expectations.json`, record `--since` before triggering one event on every device, and run:

```bash
set -a; source deployment/docker/.env; set +a
export CECUR_INDEXER_VERIFY_URL=https://127.0.0.1:9200
export CS3_TOKEN=<admin-or-analyst-token>
export AGENT_KEY=<relay-ingest-key>
export C3_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# After C3_SINCE, trigger one documented event on every device.
on-prem/bin/verify-real-telemetry.sh \
  --url https://cs3.example.internal/api/cecur/logs/ingest \
  --ingest-key "$AGENT_KEY" --agent-id plb-syslog-relay-01 --token "$CS3_TOKEN" \
  --expectations on-prem/plb-c3-expectations.json --expect-count 18 \
  --since "$C3_SINCE" --restart-console
```

Every message/`agentName`/observed `fields.source_ip` expectation must match before and after restart. `--query-only` repeats direct OpenSearch evidence checks without another synthetic event. These matches prove arrival/recorded attribution, not authenticated device identity. Missing evidence, `indexed:false`, TLS/query errors, or restart/health failures block sign-off. Afterwards, inspect `/api/fleet/summary` and `/api/cecur/agents`: enrolled inventory must be hydrated from PostgreSQL after restart, with connectivity derived from recent keepalives. A missing agent is a fleet-persistence failure, not a reason to mint duplicate enrollment credentials. Prove a fresh event returns `indexed:true` and appears in OpenSearch; post-restart queries alone do not prove renewed ingest operability.

## 5. Prove scale (1,000+ endpoints)

Run the appropriate load scenario from `deployment/operations/testing/load-test-scenarios.md`
(`eps-loadgen.mjs` or `k6-ingest.js`, 100/1,000/10,000 EPS) against a staging console with the same
profile/indexer configuration as production, and record the results against
`deployment/operations/testing/sla-baseline-template.md`.

## 6. Prove the audit ledger is intact

```bash
# requires DATABASE_URL / CS3_PERSISTENCE=postgres
psql "$DATABASE_URL" -c "select cs3.verify_audit_chain();"   # NULL == intact
```

This is unrelated to log durability but is the other half of "no mock data, nothing silently
dropped" for a real on-prem install — see root `README.md` §10.1 and §6.4.2. In the Audit pane,
run **Verify Ledger** and confirm the displayed state matches `VERIFIED_INTACT`, `DEGRADED`, or
`TAMPER_DETECTED`; a degraded or tampered result must not use success styling. Check durable-chain,
pending, failed, and dropped-append evidence. Hash verification and NIST control mappings are not a
FIPS validation, compliance certification, or proof that unaudited actions never occurred.

## 7. Prove operator identity and avatar durability

With `CS3_PERSISTENCE=postgres`, create a non-admin account through the authorized registry flow,
sign in as that account, and upload a small genuine PNG, JPEG, or WebP photograph through **Edit
Profile → Choose image**. The server must decode and normalize the image to bounded 256 × 256 WebP;
sources over 2 MiB or 4096 pixels per side, arbitrary URLs, SVG, HTML payloads, malformed images, and
MIME/format mismatches are not accepted. Record the source file type, normalized avatar type/size,
and audit outcome without recording passwords or bearer tokens.

Recreate only the console, sign in again, and verify that the account, RBAC role, profile fields,
and normalized avatar remain present. Verify that a second operator cannot modify the first
operator's profile or avatar, and that the registry endpoints enforce their management permission.
A failed PostgreSQL write must be surfaced as a failed profile/account operation, not displayed as
"Database Persistent" success.

## 8. Verify telemetry, integration provenance, and contextual guidance

For one enrolled Linux endpoint, one enrolled Windows endpoint, and at least one agentless network
device, confirm that hostname/unique-IP associations lead to the same asset in Fleet, CECUR triage,
and Asset Fusion Graph. A duplicate management IP must remain ambiguous; no graph edge, attack
path, or root cause may be invented to fill the gap. Check that triage labels AI versus deterministic
provenance and reports the asset evidence supplied to the reasoning engine.

Confirm the Overview endpoint-log EPS identifies its 60-second hot-cache window, while the Header
sensor rate identifies the sensor-node source. Empty sensor inventory must produce `NO_SENSORS`, not
100% operational. ActivTrak must identify its current records as process-local, not provider-backed;
Sensor calibrate and reboot must remain unavailable until a real management channel exists. Errow
must report configuration separately, leave reachability and API-contract verification `UNVERIFIED`
until explicit checks exist, reject missing/unknown task statuses, and retain its target allowlist gate.

Open **Guide** from the Header on every operational pane. Confirm that the displayed purpose,
workflow, evidence source, limitations, and terminology match actual behavior. This is an operator
acceptance check: guidance must not advertise an external integration, remote action, or durable
state that the running deployment does not provide.

## 9. Validate Executive KPI provenance

Confirm the Executive pane reports the incident, MTTD, resolved-incident/MTTR, SCA-report, and
30-day alert sample counts behind its metrics. With no SCA reports or no alerts in the window, the
corresponding section must say that evidence is unavailable rather than imply full compliance or
zero risk. SCA scores describe reported benchmark results, not organization-wide certification.
Force or simulate a failed KPI request in staging and verify that the failure is visible in the
pane rather than only written to the browser console.
