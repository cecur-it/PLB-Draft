# 01. Architecture & System Design
## CS3 (CECUR-IT Cyber Security Operations Console) Full-Stack System Design

---

## 1. Executive Summary

The **CS3 Platform** is engineered as a unified Security Operations Center (SOC), Extended Detection & Response (XDR), and Security Orchestration, Automation, and Response (SOAR) architecture. The platform unifies high-velocity event telemetry, user behavior analytics (UBA / ActivTrak), offensive threat reconnaissance (errow), asset topology fusion graphs built from the PLB asset inventory, and inference-gateway LLM reasoning into a single cohesive pane of glass.

---

## 2. High-Level System Topology

```
+----------------------------------------------------------------------------------------+
|                                    CLIENT TIER                                         |
|                                                                                        |
|   React 18 + TypeScript + Tailwind CSS + Lucide Icons + Three.js / Canvas 2D / SSE     |
|   - Real-time Console Panels: Overview, Incidents, Cecur SIEM, ActivTrak, Sensor Grid  |
|   - Advanced Modules: 3D Asset Fusion, errow Recon, Operational Audit, CISO KPI |
|   - Authentication Context, Role Switching, Dynamic Modals, Real-Time Toasts           |
+-------------------------------------------+--------------------------------------------+
                                            |
                                            | HTTPS REST & SSE (/api/*)
                                            v
+----------------------------------------------------------------------------------------+
|                                   APPLICATION TIER                                     |
|                                                                                        |
|   Express.js / Node.js Backend Server (Port 3000)                                      |
|   +----------------------------------------------------------------------------------+ |
|   | Security & Middleware Layer:                                                     | |
|   | - Token-based Session Verification (Bearer / Cookie)                             | |
|   | - Server-Side Role-Based Access Control (RBAC/RBAM) & Clearance Gating           | |
|   | - Audit Logging Interceptor (Immutable Actor Actions)                            | |
|   +----------------------------------------------------------------------------------+ |
|   | Core Functional Engines:                                                         | |
|   | - CecurEngine: Multi-format Log Decoders, MITRE ATT&CK Rules Engine              | |
|   | - Inference Gateway Dispatcher: vLLM / Ollama + Deterministic Heuristics        | |
|   | - Sensor Grid: registered sensor nodes only (no generated data)                 | |
|   | - Asset Fusion: PLB_Assets.csv inventory linked to real telemetry               | |
|   | - Errow Connector: Scoped Safe Reconnaissance Execution Engine               | |
|   | - ActivTrak Bridge: Insider Risk Scoring & Productivity Deviation Analysis       | |
|   | - SSE Live Stream Broadcaster: Real-time Telemetry Loop (3500ms Interval)       | |
|   +----------------------------------------------------------------------------------+ |
+-------------------------------------------+--------------------------------------------+
                                            |
                     +----------------------+----------------------+
                     |                                             |
                     v                                             v
+-----------------------------------------+   +------------------------------------------+
|       IN-MEMORY ACTIVE DATA STORE       |   |       CLOUD FIRESTORE PERSISTENCE        |
| - High-throughput Incident Cache        |   | - User Profiles & Credentials            |
| - Sensor Grid Metrics & Live Status     |   | - Immutable Transaction Billing Records  |
| - Target Recon Allowlist & Job Queue    |   | - Retainer Subscription Verification     |
| - In-Memory Actor Audit Trails          |   | - Security Rules Gated by UID & Roles    |
+-----------------------------------------+   +------------------------------------------+
```

---

## 3. Core Functional Components

### 3.1. Cecur SIEM / XDR Core Engine (`server/engine/cecurEngine.ts`)
The `CecurEngine` serves as the central log parsing and signature detection engine. It maintains:
* **Plug-in Decoders**: Six specialized decoders that parse heterogeneous raw syslog streams into standardized JSON envelopes.
* **Rules Catalog**: Rules mapped to numeric severity levels (1 to 15), MITRE ATT&CK tactics/techniques, and multi-regulatory compliance frameworks (PCI DSS, NIST 800-53, HIPAA, GDPR).
* **Live Ingestion**: Ingests raw log lines via `/api/cecur/logs/ingest`, executes regex extractions, triggers detection rules, updates severity scoring, and spawns actionable alerts.
* **Active Response (SOAR)**: Evaluates automated containment actions such as IP host isolation, firewall drop-rule insertion, process termination, and account locking.

### 3.2. Real-Time Telemetry & SSE Engine (`server.ts`)
* **Server-Sent Events (SSE)**: `/api/live/stream` (alias `/api/events`) maintains persistent HTTP connections with frontend clients and pushes only events derived from real ingestion (agent logs, alerts, scan results). There is no simulation or ticking loop and no seeded data; an empty system renders empty states.
* **Fallback Polling**: Dashboards fall back to `/api/live/telemetry` if SSE connections encounter a network partition.

### 3.3. Inference Pipeline (`server/ai/cecurAI.ts`)
* **Single path**: `queryAI` → `routeInference` → `InferenceGateway` (vLLM/LiteLLM on `cloud`, Ollama on `onprem`/`airgap`/`edge`), with JSON-schema, dangerous-output and script-field guardrails. See [`07_AGENTIC_LLM_ARCHITECTURE.md`](./07_AGENTIC_LLM_ARCHITECTURE.md) and `Consumption/INFERENCE_GATEWAY.md`.
* **Deterministic Heuristic Engine**: answers whenever no backend is configured or reachable (and by default on air-gap); responses are labelled with the engine used.

### 3.4. Asset Fusion Topology (`server/fusion.ts`)
* **Nodes**: built from `PLB_Assets.csv` (plus enrolled agents not in the file), linked to telemetry by hostname/management IP. Threat level comes from real open alerts and critical vulnerabilities.
* **No fabricated edges**: the inventory contains no topology links, so none are drawn. Blast-radius simulation and the generated threat export brief were removed.

### 3.5. errow Offensive Reconnaissance Connector (`server/connectors/errowClient.ts`)
* **Target Allowlist Gate**: All reconnaissance actions are strictly bounded to approved target identifiers (`db.targetAllowlist`). Any probe against unapproved IP/hostname is rejected at the API layer.
* **Safe Tool Profiles**: Restricted to defensive reconnaissance: `nmap_scan`, `nuclei_scan`, `gobuster_scan`, and `subfinder_scan`.
* **Hybrid Execution**: Connects to live Errow REST server if `ERROW_BASE_URL` is configured; otherwise the connector reports `UNCONFIGURED` and scans are rejected. A remote failure is recorded as a `FAILED` job with the real error. Nothing is simulated.

### 3.6. ActivTrak Insider Threat & Behavioral Analytics (`server/routes/activtrak.ts`)
* Evaluates insider risk indicators, anomalous off-hours authentication, privileged data staging, and productivity metric deviations.
* Provides risk-tiered user scoring (Low, Medium, High, Critical) with automated policy enforcement and compliance tracking.

---

## 4. Architectural Design Principles

| Principle | Implementation in CS3 |
| :--- | :--- |
| **Strict Defense-in-Depth** | Multi-layer validation: client-side view filters, server middleware RBAC clearance checks, input parameter sanitization, and database-level security rules. |
| **Zero Mock Infrastructure** | Real API endpoints, live event loops, structured JSON outputs, valid status codes, and deterministic fallback logic for all operational actions. |
| **Low Latency & High Throughput** | In-memory hot caching for sensor and incident telemetry; batch-buffering log writes before committing to durable Firestore storage. |
| **Air-Gap Readiness** | Graceful degradation of LLM and threat intelligence modules to local heuristic engines when external internet egress is blocked. |
| **Immutable Auditability** | Every user action (calibration, reboot, rule modification, scan trigger, incident status change) is logged with actor metadata, IP address, timestamp, and result status. |
