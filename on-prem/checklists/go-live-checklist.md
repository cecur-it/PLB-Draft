# On-Prem Go-Live Checklist

Sign-off list for cutting a CS3 on-prem deployment over to production, real-endpoint traffic.
Every item below references a concrete script, doc, or command — this is not a vibe-based
checklist.

## Environment & demo-mode invariant

- [ ] `on-prem/bin/preflight-check.sh` passes against the production `.env` (`CS3_DEMO_MODE`
      unset/false, `CS3_PROFILE=onprem` or `airgap`, `CS3_INGEST_REQUIRE_KEY=true`, hosted model
      keys blank).
- [ ] Confirmed (manually, once) the freshly provisioned console returned zero seed agents/logs
      before any enrollment — `Literature/04_VALIDATION_AND_ACCEPTANCE.md` §2.

## Network & edge

- [ ] Network segmentation matches `deployment/operations/networking-architecture.md`.
- [ ] If VyOS fronts this deployment: `on-prem/vyos/bootstrap-vyos-edge.sh --dry-run` reviewed and
      approved, then applied without `--dry-run`; `show zone-policy` / `show firewall name
      DMZ-TO-INTERNAL` verified on the device.
- [ ] If not VyOS: the appropriate nftables template from `deployment/operations/firewall/` is
      applied and verified.
- [ ] mTLS / certificate pinning configured per `deployment/operations/mtls-certificate-pinning.md`
      (installers run with `--pin-sha256` / `-PinSha256` and an internal CA file).

## Real endpoint enrollment

- [ ] Every target satisfies `deployment/agents/PREREQUISITES.md`: actual identity/inventory, NTP, outbound HTTPS and verified CA trust, checksum-verified Fluent Bit media, companion files, supported capabilities, and secret-free evidence logging.
- [ ] At least one real endpoint enrolled via `on-prem/bin/enroll-real-endpoints.sh` (not the
      placeholder/sample heuristic-rejected file) and its forwarder installed and healthy
      (`deployment/agents/cs3-forwarder-watchdog.sh` / `Test-CecurForwarder.ps1` report healthy).
- [ ] `on-prem/bin/verify-real-telemetry.sh` passed with the enrolled `--agent-id`: ingest returned both `success:true` and `indexed:true`, and the marker is visible via `GET /api/cecur/logs` immediately after ingest. HTTP 201 alone is not a pass.

## Durable ingestion

- [ ] `CS3_INDEXER_ENABLED=true` and the OpenSearch `indexer` service (`--profile siem`) is up and
      reachable (`preflight-check.sh` step 5 passes).
- [ ] `on-prem/bin/verify-real-telemetry.sh` directly confirmed the marker in OpenSearch (`cs3-logs` alias) using host-reachable URL, credentials, and production CA trust.
- [ ] **Mandatory:** `--restart-console` completed; health recovered and all direct OpenSearch evidence checks passed after restart (`Literature/04_VALIDATION_AND_ACCEPTANCE.md` §4).
- [ ] **PLB:** the reviewed/lab-corrected `on-prem/plb-c3-expectations.json` passed with `--expect-count 18`, a pre-event `--since`, and `--restart-console`; every device matched before and after restart. A synthetic relay marker alone is insufficient.
- [ ] ISM retention policy confirmed applied (`deployment/operations/ism/cs3-logs-lifecycle.json`
      and the inlined copy in `server/integrations/opensearchSink.ts` are in sync).

## Persistence & audit

- [ ] `CS3_PERSISTENCE=postgres` with a reachable `DATABASE_URL`; `cs3.verify_audit_chain()`
      returns `NULL` (intact) — `Literature/04_VALIDATION_AND_ACCEPTANCE.md` §6.
- [ ] Backup/restore procedure tested at least once (`deployment/operations/backup-restore.md`,
      `deployment/ansible/playbooks/backup.yml`).
- [ ] Runtime limitations addressed: durable/external IAM implemented or production reliance explicitly blocked (registered users are in-memory); post-restart fleet checks/re-enrollment runbook tested because enrolled agents are not hydrated into runtime fleet views/actions; a fresh post-restart event returned `indexed:true` and was found directly in OpenSearch.

## Scale validation

- [ ] Load-tested at the expected steady-state EPS using
      `deployment/operations/testing/eps-loadgen.mjs` or `k6-ingest.js`
      (`deployment/operations/testing/load-test-scenarios.md`), recorded against
      `deployment/operations/testing/sla-baseline-template.md`.
- [ ] `CS3_FLEET_RATE_LIMIT` and `CS3_INGEST_MAX_BATCH` reviewed against actual fleet size and
      forwarder batching behavior (root `README.md` §6.4.1/§6.4.3).

## Operations readiness

- [ ] Certificate rotation scheduled (`deployment/operations/certificate-rotation.md`,
      `deployment/ansible/playbooks/rotate-certs.yml`).
- [ ] Model update/rollback procedure understood if local Ollama models are in use
      (`deployment/operations/model-update-rollback.md`).
- [ ] Monitoring and capacity-planning dashboards wired
      (`deployment/operations/monitoring.md`, `deployment/operations/capacity-planning.md`).
- [ ] Compliance mapping reviewed for applicable frameworks
      (`deployment/operations/compliance-mapping.md`) — engineering controls only, not an
      attestation.

## Sign-off

- [ ] Reviewed by: ___________________  Date: ___________
- [ ] Approved for production cutover: ☐ yes ☐ no (remediation required, see notes)
