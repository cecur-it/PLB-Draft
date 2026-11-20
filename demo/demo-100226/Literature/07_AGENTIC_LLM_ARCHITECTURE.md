# 07. Agentic LLM Architecture
## Inference Gateway Reasoning, Guardrails, and Script Validation

> The runtime contract is [`Consumption/INFERENCE_GATEWAY.md`](../Consumption/INFERENCE_GATEWAY.md); this chapter describes how the agentic features use it. Earlier revisions described a Gemini → DeepSeek dual-agent dispatcher (`queryDualAI`, `analyzeIncidentWithAI`, `generateSOARPlaybook`). Those providers and functions no longer exist.

---

## 1. Architectural Philosophy

The CS3 platform assists SOC analysts with log triage, vulnerability remediation guidance, FIM and compliance interpretation, and incident analysis. Every AI call goes through a single path, and every input is **real telemetry** from enrolled endpoints (logs, alerts, FIM events, vulnerabilities, SCA results). No demo, mock or simulated records are fed to a model.

```
 caller (server/ai/cecurAI.ts)
        |
        v
   queryAI(prompt, system, role, { schema, scripts })
        |  returns '' on any failure -> caller uses its deterministic logic
        v
   routeInference()            server/inference/router.ts
        |  - data-classification policy (cui/classified never leave onprem/airgap/edge)
        |  - airgap: deterministic engine is the primary path
        |  - input sanitisation + <untrusted_data> framing
        v
   InferenceGateway            server/inference/gateway.ts
        |  cloud   -> vLLM/LiteLLM (INFERENCE_GATEWAY_URL)
        |  onprem / airgap / edge -> Ollama (OLLAMA_BASE_URL)
        v
   checkOutput()               server/inference/guardrails.ts
        |  JSON-Schema (Ajv) -> dangerous-output scan -> script-field validation -> optional guard model
        v
   structured JSON  (or fallback: true -> deterministic engine answers)
```

There is no external SaaS model provider and no provider key in the console. When no backend is configured or reachable, features answer from their deterministic logic and the response is labelled with the engine that produced it (`engineUsed`: `CECUR-IT Inference (<model>)` or `Cecur Heuristics`).

---

## 2. Dispatcher (`server/ai/cecurAI.ts`)

```typescript
async function queryAI(
  prompt: string,
  systemInstruction: string,
  role: 'triage' | 'forensic' = 'triage',
  opts: { schema?: object; scripts?: ScriptField[] } = {}
): Promise<string>
```

* `role` selects the model: `triage` (`INFERENCE_MODEL_TRIAGE`) or `forensic` (`INFERENCE_MODEL_FORENSIC`).
* Returns `''` when inference is not configured, the gateway fails, or a guardrail rejects the answer; callers then use deterministic logic.
* `scripts` declares which top-level output fields the model is explicitly asked to author as scripts (section 4).

---

## 3. Agentic Capabilities

| Function | Role | Purpose |
|---|---|---|
| `analyzeLogAnomalyWithAI` | triage | Log anomaly triage and MITRE ATT&CK correlation |
| `generateVulnerabilityRemediationAI` | triage | Patch steps plus `bashScript`, `powerShellScript`, `ansiblePlaybook` for a real finding |
| `analyzeFIMEventWithAI` | triage | Interpret a file-integrity deviation reported by an agent scan |
| `analyzeComplianceGapsWithAI` | triage | Explain failed SCA checks for a standard |
| `generateIncidentAnalysisWithAI` | forensic | Root cause, impact, MITRE mapping and recommended actions for an incident |

Inputs are records already in the platform's stores (ingested events, agent scan results, incidents). With no such record there is nothing to analyse and the API returns an empty or unavailable state rather than synthetic content.

---

## 4. Guardrails and Script Validation

1. **Input**: control/bidi characters, chat-template tokens and code fences are stripped, input is truncated (8000 chars), flagged against an injection-pattern list and wrapped in `<untrusted_data>` with a system rule to treat it as data.
2. **Schema**: output must satisfy the request's JSON Schema.
3. **Dangerous-output scan**: free-text output fields are scanned for executable constructs (`rm -rf`, pipe-to-shell, encoded PowerShell, shebangs, ...). A hit discards the answer (`fallback: true`).
4. **Script fields** (`input.scripts`): fields the model is *asked* to write as scripts are not blanket-rejected for a shebang. `validateScript` checks them separately:
   * `bash`: an optional first-line interpreter header from an allow-list (`#!/bin/bash`, `#!/usr/bin/bash`, `#!/usr/bin/env bash`, `#!/bin/sh`, `#!/usr/bin/env sh`); any other interpreter, or a shebang on a later line, is rejected.
   * `powershell` / `ansible`: no shebang; Ansible must parse as YAML.
   * All kinds: a **rollback section** is required (`# rollback`, `rollback()` / `function rollback` for shell and PowerShell; `rescue:` or `rollback` for Ansible), the script is capped at 20,000 characters, and every other dangerous-output pattern still applies.
   * Free-text fields outside the declared script fields keep the strict scan.
5. **Guard model** (optional, `INFERENCE_MODEL_GUARD`): an unsafe verdict or an outage fails closed.

A rejected answer is never surfaced; the deterministic engine answers and the violation list is returned in `guardrail.violations`. Pattern lists are heuristics, not proof; scripts are re-validated downstream before any execution.

---

## 5. Operational Constraints

1. **Mandatory rollback** in every model-authored script (enforced in code, section 4).
2. **Analyst in the loop**: the console never executes model-authored scripts. Execution requires an authenticated `analyst` or `admin` and happens outside the console.
3. **Metering**: every non-fallback response is recorded in the GPU-second `GasLedger`.
4. **No simulated data**: if inference is unavailable the UI shows the heuristic engine label or an unavailable state, never fabricated model output.
