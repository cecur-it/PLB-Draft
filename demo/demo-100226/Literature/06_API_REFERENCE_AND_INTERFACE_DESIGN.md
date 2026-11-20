# 06. API Reference & Interface Design
## RESTful Endpoints, Server-Sent Events (SSE), and Schema Specification

---

## 1. API Architecture Overview

The CS3 Backend exposes a modular, RESTful API layer coupled with a persistent Server-Sent Events (SSE) stream for real-time telemetry updates. The API adheres to OpenAPI 3.0 standards and aligns with the Vendetta-compatible v4.14.7 API specification structure.

### Base URL & Protocol
* **Base URL**: `http://localhost:3000/api`
* **Transport**: HTTPS / TLS 1.3
* **Content-Type**: `application/json`
* **Authentication**: Bearer Token via `Authorization: Bearer <TOKEN>` header

---

## 2. Authentication & Identity (`/api/auth`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Public | Authenticates credentials; returns user profile and bearer token. |
| `GET` | `/api/auth/me` | Authenticated | Returns currently authenticated user session and role capabilities. |
| `POST` | `/api/auth/switch-role` | Authenticated | Switches current session role for testing RBAC clearance. |
| `POST` | `/api/auth/logout` | Authenticated | Terminates active session. |

#### Request Example (`POST /api/auth/login`):
```json
{
  "username": "<username>",
  "password": "<password>"
}
```
#### Response Example:
```json
{
  "token": "<signed JWT>",
  "user": {
    "id": "<user id>",
    "username": "<username>",
    "name": "<display name>",
    "role": "analyst"
  }
}
```

---

## 3. Real-Time Telemetry & SSE (`/api/live`)

| Method | Endpoint | Protocol | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/live/stream` | `text/event-stream` | Persistent Server-Sent Events connection pushing events derived from real ingestion (no timer-driven data). |
| `GET` | `/api/live/telemetry` | `application/json` | Polling fallback for retrieving instantaneous sensor and incident counts. |

---

## 4. SIEM & SOAR Incidents (`/api/incidents`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/incidents` | All Roles | Lists all security incidents with filtering by status and severity. |
| `GET` | `/api/incidents/:id` | All Roles | Retrieves complete incident details, telemetry trace, and timeline. |
| `POST` | `/api/incidents/:id/status` | Analyst, Admin | Updates incident lifecycle status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`). |
| `POST` | `/api/incidents/:id/ai-analyze`| Analyst, Admin | Generates root cause analysis and impact breakdown through the inference gateway (deterministic engine when no backend is available). |
| `POST` | `/api/incidents/:id/playbook-step` | Analyst, Admin | Updates the status of a playbook step. |

---

## 5. Cecur SIEM / XDR Core Engine (`/api/cecur`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/cecur/status` | Analyst, Admin, Auditor | Retrieves engine health, decoders list, active rules count, and AI status. |
| `GET` | `/api/cecur/agents` | Analyst, Admin, Auditor | Lists all enrolled endpoints, OS details, IP addresses, and sync statuses. |
| `GET` | `/api/cecur/rules` | Analyst, Admin, Auditor | Returns rules catalog with MITRE tactics and compliance tags. |
| `GET` | `/api/cecur/alerts` | Analyst, Admin, Auditor | Lists parsed alerts filtered by level and rule ID. |
| `POST` | `/api/cecur/logs/ingest` | Ingest Key / Auth | Ingestion gateway for raw log streams. Parses via decoders and emits alerts. |
| `POST` | `/api/cecur/agents/:id/action` | Analyst, Admin | `scan_fim` / `run_sca` queue a real scan job for the agent. Containment commands (isolate, quarantine) return `501`: no enforcement control plane is wired. |
| `POST` | `/api/cecur/fim/scan` | Analyst, Admin | Queues a FIM scan job for every active agent (or one `agentId`). `202` with the jobs; `409` when no agent is active. Never returns canned results. |
| `POST` | `/api/cecur/sca/run` | Analyst, Admin | Queues an SCA job (same semantics). |
| `POST` | `/api/cecur/vulnerabilities/scan` | Analyst, Admin | Queues a vulnerability scan job (same semantics). |
| `GET` | `/api/cecur/scan-jobs` | Analyst, Admin, Auditor | Scan job status: `queued`, `running`, `completed`, `failed`, `timeout`, with summary or error. |
| `GET` | `/api/fleet/assets` | Analyst, Admin, Auditor | `PLB_Assets.csv` inventory linked to real telemetry (agent/syslog/none coverage). |
| `GET` | `/api/fleet/agent/tasks` | Per-agent `X-API-Key` | Agent claims its queued scan jobs. |
| `POST` | `/api/fleet/agent/results` | Per-agent `X-API-Key` | Agent posts measured results (`completed`) or the reason it could not scan (`failed`). Accepted only for the agent's own running job. |

---

## 6. CS3 Sensor Grid (`/api/sensors`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/sensors` | Analyst, Admin, Auditor | Lists registered sensor nodes (empty until sensors report; none are generated). |
| `POST` | `/api/sensors/:id/calibrate`| Analyst, Admin | Returns `501`: no sensor control channel is wired; audited as an error. |
| `POST` | `/api/sensors/:id/reboot` | Admin Only | Returns `501` (see calibrate). |

---

## 7. Asset Fusion Topology (`/api/fusion`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/fusion` | Analyst, Admin | Returns nodes built from the `PLB_Assets.csv` inventory (plus enrolled agents not in the CSV) with real coverage, alert and vulnerability data. No links or attack paths are fabricated; `source`/`sourceError` report inventory load status. |

---

## 8. errow Offensive Reconnaissance (`/api/errow`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/errow/status` | Admin Only | Returns connector mode (`LIVE` or `UNCONFIGURED`), base URL, and available tools. |
| `GET` | `/api/errow/allowlist` | Admin Only | Lists authorized reconnaissance target entries in `db.targetAllowlist`. |
| `GET` | `/api/errow/jobs` | Admin Only | Lists recent and running offensive scan jobs. |
| `POST` | `/api/errow/scan` | Admin Only | Triggers scoped scan (`nmap`, `nuclei`, `gobuster`, `subfinder`) against an allowlisted host. `503` when the connector is `UNCONFIGURED`. If the remote call fails the job is recorded as `FAILED` with the real error and audited; results are only ever those returned by the remote Errow service. |

---

## 9. Operational Audit Trail (`/api/audit`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/audit` | All Roles | Lists chronological audit events (filters by actor, action, panel, status). |
| `POST` | `/api/audit/export` | Admin, Auditor | Exports cryptographic compliance audit report (JSON/CSV). |

---

## 10. System (`/api/system`)

| Method | Endpoint | Clearance | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/system/environment-status` | All Roles | Real configuration status of inference, Errow, indexer and persistence. |

The former `POST /api/system/reseed` was removed along with all seeded demo data; `CS3_DEMO_MODE=true` now fails startup.
