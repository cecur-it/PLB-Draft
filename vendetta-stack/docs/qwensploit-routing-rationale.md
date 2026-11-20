# Security model routing rationale, rollback and acceptance record

> Filename kept for link stability: the tier no longer contains a security fine-tune. Security and Errow run on the **agentic** tier
> (`nemotron-3-nano:30b`) with the **reasoning** class (`gemma4:31b`) as its only fallback; CVE/ATT&CK/playbook knowledge is expected from the
> tool loop plus a retrieval index, not from a tuned checkpoint. `qwensploit-v2:9b` (as shipped by the earlier integration) is kept as an optional
> evaluation model only. Its registry entry conservatively sets `multimodal: false` until an mmproj blob is verified in the pulled artifact.

This page is the ISSO-facing artefact: **why** each task class maps to each model, the deprecated aliases, the rollback rehearsal and the
acceptance log. Model tags are never hard-coded by callers — the role variables below are the contract.

Traces: CONTRACT §4.2–§4.5, §10, §11.

## 1. Model inventory (what exists and who may be behind it)

| Tier (`models.json`) | Tag | Role | Why it exists |
|---|---|---|---|
| `agentic` | `nemotron-3-nano:30b` | triage, **security**, **Errow primary**, MCP tool planning | Reliable function calling is the security capability here: every security answer is a `toolCalls` proposal, so the tool loop — not a tuned checkpoint — carries the domain knowledge. 3.5B active params keep alert storms and long agentic runs affordable. |
| `entry` | `gemma4:26b` | forensic default, edge | Good structured synthesis at 16 GB VRAM; the only model an edge node must carry. |
| `frontier` | `gemma4:31b` | forensic upgrade, `deep`, **security/Errow fallback** | Multi-hop root-cause work, `proposedDetectionRule`/`proposedRemediation`, large context — the capability to climb to when the agentic tier is gone. |
| `eval` (optional) | `qwensploit-v2:9b` | `cybersecurity-reasoning-eval` | Optional ablation/evaluation model. Not pulled by default and **not** in any production chain, so a deployment can run without it. |
| — | `INFERENCE_MODEL_GUARD` (default `gemma4:26b`) | output guard/judge | Safety-shaped adjudication on a different model than the one that answered (see §3). |

The security seat moved off the fine-tune because the tool-calling matrix (`nmap`, `nuclei`, `bbot`, `trufflehog`, …) is the actual workflow
lever, and a 30B agentic generalist plans it better than a 9B tuned model. The cost is verbosity and occasional prose leakage, handled in §4.

## 2. Routing matrix and rationale

| Task class | Chain (first → last) | Why this order |
|---|---|---|
| `errow` | `INFERENCE_MODEL_ERROW_SECURITY` → `_DEEP` | Errow is a security tool: the agentic model plans the tool chain, and the 31B reasoning class is the only substitution that does not lose analytical depth. Nothing else is in the chain. |
| `security` | `_SECURITY` → `_DEEP` | Same first tier for `/security` (vuln analysis, secure-code review). The chain **stops at `_DEEP`** — a security task that degrades to the triage/entry model silently loses depth, so `_FORENSIC`/`_TRIAGE` are never security fallbacks. |
| `triage` | `_TRIAGE` → `_FORENSIC` | Triage is high-volume classification with tool proposals: the agentic model first, the mid forensic model as continuity. The chain terminates in deterministic heuristics. |
| `forensic` | `_FORENSIC` → `_TRIAGE` | Root-cause quality matters more than latency; the agentic generalist keeps the run alive. |
| `deep` | `_DEEP` → `_FORENSIC` → `_TRIAGE` | Long-context synthesis starts at the 31B model; the others are continuity only. |
| passthrough (`/v1/chat/completions` with a raw allowed tag) | — | No routing. Metered only; caller owns the choice. |

Aliases allow pinning a class without a raw tag: `cs3-security` / `cs3-vuln-analysis` → `security`, `cs3-errow-security` / `cs3-errow` → `errow`,
`cs3-triage`, `cs3-reasoning` / `cs3-forensic`, `cs3-reasoning-deep` / `cs3-deep`. Errow therefore sets `errow_LLM=openai/cs3-errow-security`.

`_SECURITY`, `_TRIAGE` and `_ERROW_SECURITY` resolve to the same tag by default. The chains are therefore expressed per role, not per distinct
model, and each role keeps its own budget, thinking flag and cache flag — the tag being shared never merges two task classes.

### Deprecated aliases

| Current | Deprecated (still honoured) |
|---|---|
| `INFERENCE_MODEL_TRIAGE` | `OLLAMA_PRIMARY_MODEL` |
| `INFERENCE_MODEL_FORENSIC` | `OLLAMA_FALLBACK_MODEL` |
| `INFERENCE_MODEL_SECURITY` | `OLLAMA_SECURITY_MODEL` |

The `OLLAMA_*_MODEL` names are read by the gateway, `pull-models.sh` and the Errow entrypoint; `INFERENCE_*` wins when both are set. They are
kept as deploy-time compatibility shims and are no longer the documented contract — retire them once no old `.env` can still be on a host.

## 3. What the security tier must never do

* **Never the guard or judge.** `INFERENCE_MODEL_GUARD` must differ from both security roles (config refuses to start otherwise). The guard asks
  a different model whether the answer is safe; re-using the answering model makes the check self-referential.
* **Never the final word on a degraded run.** An Errow/security run that answered from `_DEEP` sets `degraded_model_fallback: true`; that answer
  is execution continuity, needs analyst review, and must not be reported as a security assessment.
* **Never `think`.** `security`/`errow` answer tool proposals, so the budget belongs to the answer, not to a reasoning trace.
* **Never silently substitute.** `security`/`errow` fail closed with a typed error rather than fabricating a heuristic analysis.

## 3a. The agentic wire path

A security model is only as good as the tool loop in front of it, and the loop is fragile in ways a checkpoint cannot fix. Three things had to be
true at the gateway before `nemotron` could work at all, and they are the reason the seat cannot later be swapped back to a fine-tune without
re-verification:

* **Native tool calls, not JSON prose.** The gateway used to rebuild every prompt and force `response_format: json_object`. The agent got JSON
  back, logged `ended a turn without a lifecycle tool call`, and burned a forced continuation per turn (125+ per scan). On `errow` and on any
  call carrying `tools[]` the caller now owns the conversation — `messages` (assistant `tool_calls` turns included) and `tools` pass through
  verbatim, `response_format` is dropped, and the answer comes back as `tool_calls` with `finish_reason: tool_calls`. Analysis calls without tools
  keep strict JSON, so triage/forensic records never gain invented fields.
* **Bare arguments.** The model wrote the tool name back into its own arguments (`"cmd": "exec_command cmd=\"curl …\""`), so every sandbox call
  exited 127. A one-line gateway system preface fixes it: after the change, a live scan made 12 shell calls with 0 × 127.
* **One approval per run, not per turn.** The human-approval gate stays (a mutating proposal without `X-CS3-Approval` is 403
  `approval_required`) — that is acceptance test 8. But an agent loop re-proposes `execute_command` every turn, so Errow sends the token from
  `CS3_APPROVAL_TOKEN_FILE`. Launching the scan is the approval; the gate still blocks any caller that has no token.

## 4. Failover and honest degradation

Chains are walked only on real failures (5xx, connection, timeout, schema violation, dangerous output, `gpu_maintenance`), each reason counted
in `llm_gateway_failover_total{from,to,reason}` and logged. `x-cs3-model` reports what actually answered; `degraded_model_fallback` is true only
for the security/Errow tail.

The agentic model regularly needs more room than a 512-token cap for a triage object: at 512 it truncated mid-JSON on roughly half the records and
forced a schema fallback every time. `MAX_TOKENS_DEFAULT.triage` is therefore **1024** (still bounded; measured 384–652 tokens on the lab feed).
`security` stays at 2048 and `errow` at 4096 because a tool proposal is short but a scan plan is not.

In the **airgap** profile `pull-models.sh` never pulls, so a missing security model is a *deploy-time* fact: provision it from the bundle
(`scripts/build-airgap-bundle.sh`) or accept the downgrade. In **direct** airgap mode (Errow pointed straight at `ollama`, no gateway) there is no
automatic fallback at all and the run errors out — see `errow/RUNTIME.md` for re-pointing the run.

## 5. Rollback rehearsal (run before closing the change)

Rehearse in staging on the same host class; record the output. The change is configuration-only, so application rollback is an env revert, and the
`eval` tier may simply be left uninstalled.

### 5.1 Application rollback (previous contract: security on the 9B eval model)

```bash
cp .env .env.bak
# 1. point the security roles back at the eval model and restore the old Errow default
#    (on macOS/BSD sed takes an explicit empty -i suffix: sed -i '' 's/…/…/' .env)
sed -i 's/^INFERENCE_MODEL_SECURITY=.*/INFERENCE_MODEL_SECURITY=qwensploit-v2:9b/' .env
sed -i 's/^INFERENCE_MODEL_ERROW_SECURITY=.*/INFERENCE_MODEL_ERROW_SECURITY=qwensploit-v2:9b/' .env
sed -i 's/^errow_LLM=.*/errow_LLM=openai\/qwensploit-v2:9b/' .env
docker compose up -d --wait llm-gateway errow
# 2. baseline proves itself: triage and security answer, header is the eval model again
curl -fsS -H "Authorization: Bearer $TOKEN" https://127.0.0.1:9101/health | jq .status
curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"model":"cs3-security","messages":[{"role":"user","content":"ssh brute force"}]}' \
  https://127.0.0.1:9101/v1/chat/completions -D- -o /dev/null | grep -i '^x-cs3-model'
```

### 5.2 Full withdrawal (also removes the model)

```bash
docker compose exec ollama-1 ollama rm qwensploit-v2:9b     # bundle-store copy is untouched
docker compose up -d --wait llm-gateway ollama-1 errow       # drops it from the preload set
```

Then revert the commit that retargeted the chains so `scripts/validate-models-json.sh` and the errow `llm-providers.yaml` policy agree again
(`errow/tests/test_entrypoint.sh`).

### 5.3 Stop criterion

If a reverted stack does not answer `/health` `ok` and a triage request within the change window, escalate to the platform owner. Never use
`docker system prune -a` as rollback — it destroys unrelated host data.

## 6. Acceptance log

Status legend: **auto** = covered by a repo test (command shown), **manual** = live model/lab target, run at handover. Change record
`CHG-2026-11-19-NEMOTRON`. The change prompt defines exactly **18** rows; the healthcheck row that the earlier draft carried as "19" is
reconciled here as row **18** (its source was `scripts/tests/cases/60_health.sh`, not the prompt) and the old rows 18/19 shift accordingly.

| # | Test | How | Status |
|---|---|---|---|
| 1 | Security model installed | `ollama list` shows the security tag with the shipped quantization | manual |
| 2 | `toolCalls` structure | tool-definition prompt through `/v1/chat/completions` (`cs3-security`) | manual |
| 3 | Security class selects the agentic model | `-d '{"model":"cs3-security",…}'` → `x-cs3-model: nemotron-3-nano:30b` | auto — `test_security_routing.py` |
| 4 | Triage still selects the agentic model | `cs3-triage` → `x-cs3-model: nemotron-3-nano:30b` | auto — `test_failover.py::test_triage_model_answers_with_the_contracted_prompt_and_sampling` |
| 5 | Fallback is typed, never silent mis-route | `MOCK_DOWN_MODELS` on the security tag | auto — `test_security_routing.py::test_exhausted_chain_fails_closed_with_a_typed_error` |
| 6 | Cache hit on repeated triage, security never cached | identical triage twice; second `meta.cache_hit` | auto — `test_security_routing.py::test_security_findings_are_never_cached_but_triage_is` |
| 7 | Judge is not a security model | config refuses `INFERENCE_MODEL_GUARD=<security tag>` | auto — `test_security_routing.py::test_guard_model_must_differ_from_security_models` |
| 8 | Mutating tool call without approval | `POST /security` `isolate_host` → 403 `approval_required` | auto — `test_security_routing.py::test_mutating_tool_call_requires_a_human_approval_token` |
| 9 | Token budget | `MAX_TOKENS_DEFAULT` 2048 (security) / 1024 (triage) sent to the backend | auto — `test_security_routing.py` budget tests |
| 10 | CS3 rollback restores baseline | §5.1 | manual (transcript archived) |
| 11 | Errow route selects the agentic model | `model: cs3-errow-security` → `x-cs3-model` | auto — `test_security_routing.py::test_errow_alias_answers_with_openai_shape_and_headers` |
| 12 | Errow falls back to `gemma4:31b` | down security tag → header `gemma4:31b`, `degraded_model_fallback: true` | auto — `test_security_routing.py::test_errow_falls_to_gemma4_and_flags_the_degraded_run` |
| 13 | Both broken → fail closed, degraded flag, review | down security tag and `_DEEP` → typed error / degraded, no substitution to the entry model | auto — same test as #12 |
| 14 | Errow degrades loudly, never silently | missing security model → warning names model and profile, `DEGRADED` in the banner | auto — `errow/tests/test_entrypoint.sh` |
| 15 | Smoke scan with the security route | `errow --mode scan -- --target … -m quick` | manual |
| 16 | Safe defaults | `errow_TELEMETRY=false`, `MCP_LIVE=false`, `ERROW_FEEDBACK_LIVE=false` | auto — `errow/tests/test_stack_config.py` |
| 17 | Artifact integrity | SHA-256 of `errow_runs/smoke/*` into the change record; `report.json` parses | manual |
| 18 | Errow rollback restores prior contract | §5.1, then a smoke run answers from the previous model | manual (transcript archived). Healthcheck coverage of a missing security model: `scripts/tests/cases/60_health.sh` |


Live verification for this build is archived in [`change-records/CHG-2026-11-19-NEMOTRON/ACCEPTANCE.md`](change-records/CHG-2026-11-19-NEMOTRON/ACCEPTANCE.md)
(18/18 PASS with headers, router log, rollback transcript and SHA-256 manifest). The `auto` column above names the regression test that keeps
each row honest after handover; the change record holds the one-off live transcript. Credential-shaped lab tokens and the PDF decryption
password are redacted or omitted from the repository copy; the encrypted PDF and its hash remain as evidence.
## 7. Open risks carried forward

* Security quality now depends on the **tool loop**, not a tuned checkpoint: the CVE/ATT&CK/playbook retrieval index (OpenSearch) is designed
  but not yet wired into the gateway prompt — today the model relies on its own priors plus MCP tool output.
* The agentic model is verbose; the 1024-token triage cap is empirical and must be re-measured if the triage prompt grows.
* The 31B fallback is execution continuity only, never a security judgement.
* Direct airgap mode (no gateway) has no automatic fallback.
* `qwensploit-v2:9b` in the `eval` tier is unexercised by production traffic; keep its digest pinned or drop the tier.
* The agentic model malforms the 16-parameter `create_vulnerability_report` call more readily than a tuned security model: two
  scoping runs filed nothing until the instruction file listed every required parameter and mandated a tool call on every turn.
  Ship the instruction file with the profile and treat a 0-finding run as a harness suspect, not automatically a clean target.
* Acceptance proves routing and fallback behaviour, **not** model correctness.
