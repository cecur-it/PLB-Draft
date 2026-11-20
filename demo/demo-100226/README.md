# CS3 ESOC Console

React/Vite operator console and Express API for CS3 telemetry, endpoint security, asset correlation,
RBAC, durable audit, and bounded agentic assistance. See the repository root for the supported
on-prem installation and validation workflow.

## Run Locally

**Prerequisites:** Node.js 20+ and npm


1. Install dependencies:
   `npm install`
2. Optionally set `INFERENCE_GATEWAY_URL` (cloud) or `OLLAMA_BASE_URL` (local) in [.env.local](.env.local); without a backend the deterministic engine answers
3. Run the app:
   `npm run dev`

## Container / Platform Install

This app is the CS3 ESOC Console. Build with `docker build -t cs3-soc-console .` (see `Dockerfile`) or install via the repository root launcher for `cloud`, `onprem`, or `airgap` profiles:

`node cs3-launcher.mjs --profile <cloud|onprem|airgap>` — see the top-level README, Section 4.1.

Copy `.env.example` to `.env` for local dev and fill in your own keys (none are committed).

## Real data only

The console never generates demo, mock or simulated data. Every panel renders telemetry from enrolled endpoints (logs, alerts, scan results) and the asset inventory in `PLB_Assets.csv` (`PLB_ASSETS_CSV` to override the path). A fresh console is empty. `CS3_DEMO_MODE=true` fails startup.

- **Scans**: `POST /api/cecur/fim/scan`, `/sca/run` and `/vulnerabilities/scan` queue jobs for enrolled agents (`202`) or return `409` when none is active. `deployment/agents/cs3-scan-agent.mjs` runs them on the host and reports measured results; failures and timeouts are shown as such.
- **Errow**: `UNCONFIGURED` rejects scans; a remote failure or missing/unknown task status is recorded as a `FAILED` job. Results are only what the remote service returned.
- **AI**: `Literature/07_AGENTIC_LLM_ARCHITECTURE.md` and `Consumption/INFERENCE_GATEWAY.md`.

## Operator workflows

- **Profile photo:** open the operator menu → **Profile** → **Edit Profile** → **Choose image**.
  PNG, JPEG, and WebP input up to 2 MiB and 4096 pixels per side is decoded and normalized server-side
  to a bounded 256 × 256 WebP image; arbitrary image URLs and SVG/HTML uploads are not accepted. With
  PostgreSQL persistence enabled, the account and normalized avatar survive console recreation.
- **Account creation:** an administrator opens **Personnel** → **Create Operator**. The
  `manage_users` permission is enforced server-side, and creating an operator does not replace the
  administrator's session. Signed-out users cannot self-register. Public API and optional Firestore
  profile copies exclude credential hashes and unknown persisted fields.
- **Contextual guidance:** open **Guide** in the Header for the active pane's purpose, evidence
  sources, safe workflow, limitations, and terminology. Guidance is opened on demand; it does not
  interrupt normal console operation.
- **Telemetry interpretation:** Header sensor rate and Overview hot-cache endpoint-log EPS have
  different sources and meanings. SSE connectivity does not establish event throughput, and empty
  or stale coverage is not evidence of healthy posture. Asset correlation retains hostname/IP match
  evidence and duplicate-IP ambiguity instead of inventing topology or causality. Log triage labels
  AI versus deterministic provenance; the fallback does not invent MITRE classifications or root
  causes when no behavior assessment is available.
- **Executive and audit evidence:** Executive KPIs expose their incident, response-time, SCA, and
  alert sample counts. Audit verification distinguishes intact, degraded, and tampered states and
  reports durable-chain/append-backlog evidence. NIST control mappings and SHA-256 linkage are not
  compliance certification or FIPS validation.
- **External integrations:** ActivTrak local records are not a live provider connection. Sensor
  remote actions require a real management channel. Errow configuration alone does not prove service
  reachability or API-contract compatibility, and target allowlisting remains mandatory.

The operator acceptance procedure is in
[`../../on-prem/Literature/04_VALIDATION_AND_ACCEPTANCE.md`](../../on-prem/Literature/04_VALIDATION_AND_ACCEPTANCE.md).
