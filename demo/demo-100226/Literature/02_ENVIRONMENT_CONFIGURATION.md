# 02. Environment Configuration
## CS3 Platform Runtime, Networking, and Environment Variables

---

## 1. Overview & Runtime Constraints

The **CS3 (CECUR-IT Cyber Security Operations Console)** backend is built on Node.js (v18+) and Express with TypeScript, seamlessly integrating with the Vite frontend build pipeline.

### Container & Networking Rules
1. **Single Public Port Constraint**: The container exposes **Port 3000** exclusively. All ingress HTTP, REST API, Server-Sent Events (SSE), and static frontend assets are reverse-proxied through `0.0.0.0:3000`.
2. **Server-Side API Security**: Secret API credentials (inference gateway, Errow, ActivTrak, Firebase Admin) **must never** be exposed to the browser or prefixed with `VITE_`.
3. **Dual Development & Production Server**: In development mode, Express directly mounts Vite middleware (`middlewareMode: true`) for instantaneous hot execution. In production mode, Express serves pre-built static assets from `/dist` with full SPA route fallback.

---

## 2. Environment Variables Matrix

All configurable environment variables must be declared in `.env.example` to document deployment requirements without committing sensitive credentials.

| Variable Name | Required? | Default / Example | Scope | Functional Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `PORT` | Built-in | `3000` | Server | HTTP port bound by Express server (must be 3000 for container ingress). |
| `NODE_ENV` | Optional | `development` / `production` | Platform | Controls Vite middleware attachment vs. static `/dist` bundle serving. |
| `CS3_PROFILE` | Optional | `cloud` / `onprem` / `airgap` | Server | Deployment profile; selects the inference backend (see `Consumption/INFERENCE_GATEWAY.md`). |
| `INFERENCE_GATEWAY_URL` | Cloud profile | `https://llm.internal/v1` | Server | OpenAI-compatible vLLM/LiteLLM gateway. On `onprem`/`airgap`, `OLLAMA_BASE_URL` is used instead. |
| `INFERENCE_MODEL_TRIAGE` / `INFERENCE_MODEL_FORENSIC` | Optional | model name | Server | Model per role. Unset or unreachable means the deterministic engine answers and is labelled as such. |
| `PLB_ASSETS_CSV` | Optional | `../../PLB_Assets.csv` | Server | Asset inventory (source of truth for endpoints/assets). |
| `CS3_AGENT_STALE_SECONDS` | Optional | `300` | Server | Seconds without a keepalive before an agent is reported disconnected. |
| `CS3_SCAN_QUEUED_TTL_MINUTES` / `CS3_SCAN_RUNNING_TTL_MINUTES` | Optional | `60` / `30` | Server | Expiry for unclaimed / unfinished scan jobs (reported as `timeout`). |
| `ERROW_BASE_URL` | Optional | `https://errow.internal:8000` | Server | Target URL of active errow reconnaissance server daemon. |
| `ERROW_API_KEY` | Optional | `hex_secret_token_...` | Server | Authorization bearer token for Errow REST API. |
| `ACTIVTRAK_BASE_URL` | Optional | `https://api.activtrak.com/v1` | Server | ActivTrak Insider Risk API gateway endpoint. |
| `ACTIVTRAK_API_KEY` | Optional | `at_sec_...` | Server | API authentication key for ActivTrak cloud service. |
| `ACTIVTRAK_ACCOUNT_ID` | Optional | `act-org-7821` | Server | Organization / Account identifier within ActivTrak tenant. |
| `SOC_INGEST_API_KEY` | Optional | `cecur-ingest-key-prod-01` | Server | Pre-shared key for validating edge forwarder log streams. |
| `FIREBASE_PROJECT_ID` | Optional | `cecur-it-soc` | Shared | Google Cloud / Firebase project ID for Firestore persistence. |

---

## 3. Configuration Setup & Bootstrapping

### 3.1. Local Development Setup
Create a `.env` file in the project root:

```bash
# Server & Runtime Configuration
PORT=3000
NODE_ENV=development

# AI inference (Optional - without a backend, deterministic heuristics answer and are labelled as such)
CS3_PROFILE=onprem
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1

# External Security Services (Optional - an unconfigured connector reports UNCONFIGURED; nothing is simulated)
ERROW_BASE_URL=https://errow.internal:8000
ERROW_API_KEY=your_errow_api_key
ACTIVTRAK_BASE_URL=https://api.activtrak.com/v1
ACTIVTRAK_API_KEY=your_activtrak_key
ACTIVTRAK_ACCOUNT_ID=act-org-7821

# Ingestion Security Secret
SOC_INGEST_API_KEY=cecur-ingest-key-prod-01
```

### 3.2. Lazy Configuration
Backends are resolved per request (`server/inference/gateway.ts`), so a missing or later-added variable never crashes startup; an unconfigured integration reports `UNCONFIGURED` and the UI says so. `CS3_DEMO_MODE=true` is the one setting that fails startup, because the platform no longer generates demo data.

---

## 4. Production Build & Start Configuration

The production build pipeline compiles both client and backend TypeScript in a single atomic pass:

```json
{
  "scripts": {
    "dev": "tsx server.ts",
    "build": "vite build && esbuild server.ts --bundle --platform=node --format=cjs --packages=external --sourcemap --outfile=dist/server.cjs",
    "start": "node dist/server.cjs"
  }
}
```

### Key Build Mechanics:
1. `vite build`: Compiles React TypeScript components, styles, and assets into `/dist`.
2. `esbuild server.ts`: Bundles the Express server, backend routes, engines, and utilities into `/dist/server.cjs`.
3. `--packages=external`: Leaves native Node modules (e.g., `express`, `@google/genai`) to be resolved at runtime from `node_modules`.
4. `--sourcemap`: Emits accurate line mappings for debugging runtime exceptions in production containers.
