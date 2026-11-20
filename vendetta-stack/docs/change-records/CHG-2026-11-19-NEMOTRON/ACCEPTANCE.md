# §9 acceptance table — CHG-2026-11-19-NEMOTRON

Live host: macOS 15.8.2 arm64, Docker 29.9.3, Ollama 0.40.5, Errow profile
**Local CLI** (cloud profile locally). Router: gateway 9101 (live) / 9107-9108
(staging, rollback). Lab target: OWASP Juice Shop, `http://127.0.0.1:3000`
(host) / `http://host.docker.internal:3000` (sandbox).

Design as re-scoped by the owner mid-change: security and Errow run on the
agentic tier (`nemotron-3-nano:30b`) with `gemma4:31b` as the single fallback;
`qwensploit-v2:9b` is an optional eval tier. Header name in this build is
`X-CS3-Model` (the spec's `x-litellm-model` was the LiteLLM-era name; the
gateway emits `X-CS3-Model` / `X-CS3-Task-Class` / `X-CS3-Degraded-Model-Fallback`).

| # | Test | Result | Evidence |
|---|---|---|---|
| 1 | Security model installed | PASS — production tags present; Qwensploit eval tag present with Q4_K_M | `01-ground-truth/host.txt` |
| 2 | `toolCalls` structure via `cs3-security` | PASS — native `tool_calls`, no prose wrapper | `04-live-tests/b-t2.json`, `h-t2.txt` |
| 3 | `cs3-security` route selection | PASS — `X-CS3-Model: nemotron-3-nano:30b` | `04-live-tests/h-t3.txt` |
| 4 | `cs3-triage` route selection | PASS — `X-CS3-Model: nemotron-3-nano:30b` | `04-live-tests/h-t4.txt` |
| 5 | Typed fallback, never silent mis-route | PASS — exhausted chain → typed error | `04-live-tests/b-t5.json` |
| 6 | Triage cached, security never cached | PASS — 2nd triage `cache_hit`, security re-generated | `04-live-tests/b-t6*` |
| 7 | Judge is not a security model | PASS — guard `gemma4:26b` | `04-live-tests/b-t7*`, `03-router-audit/health-live.json` |
| 8 | Mutating tool call without approval → 403 | PASS — HTTP 403 `approval_required` | `04-live-tests/h-t8.txt`, `b-t8*.json` |
| 9 | Token budget respected | PASS — triage capped 1024, security 2048/errow 4096 | `04-live-tests/b-t9*.json` |
| 10 | CS3 rollback restores baseline | PASS — eval entry removed, routes still pass, file restored byte-identical | `06-rollback/models.json.sha256.*`, `04-live-tests/rb-t10-*.h` |
| 11 | `cs3-errow-security` route selection | PASS — `X-CS3-Model: nemotron-3-nano:30b` | `04-live-tests/h-t11.txt` |
| 12 | Primary broken → `gemma4:31b`, degraded | PASS — header `gemma4:31b`, `degraded_model_fallback: true` | `04-live-tests/h-t12.txt`, `b-t12.json` |
| 13 | Primary and fallback broken → fail closed + review | PASS — typed error/degraded flag, `needs_analyst_review`; no third-model substitution | `04-live-tests/h-t13.txt`, `b-t13.json` |
| 14 | Airgap direct mode fails closed | PASS — 404 `model 'qwensploit-v2:9b' not found`, no substitution | `04-live-tests/errow-t14.log` |
| 15 | Errow smoke scan completes | PASS — 3 findings (2 critical, 1 high), run `completed` | `05-errow-smoke/host-docker-internal-3000_a9b5/`, `04-live-tests/errow-tool-transcript.md` |
| 16 | Telemetry / live-remediation defaults off | PASS — `errow_TELEMETRY=false`, `MCP_LIVE=false`, `ERROW_FEEDBACK_LIVE=false` | `04-live-tests/errow-entrypoint-test.txt`, `05-errow-smoke/host-docker-internal-3000_a9b5/run.json`, `06-rollback/env.errow.rollback` |
| 17 | Artifact integrity | PASS — SARIF + report.json parse, SHA-256 manifest | `05-errow-smoke/SHA256SUMS.txt`, `05-errow-smoke/host-docker-internal-3000_a9b5/report.json`, `05-errow-smoke/host-docker-internal-3000_a9b5/report.pdf.enc` |
| 18 | Errow rollback restores prior contract | PASS — reverted to `errow_LLM=openai/nemotron-3-nano:30b`, run completed; re-applied, run completed | `06-rollback/*` |

Notes carried with the table:

* Row 18 detail: `CS3_MODEL_ERROW_SECURITY` unset does **not** 404 the
  `cs3-errow-security` alias — the alias is compiled into `ROLE_ALIASES` and
  degrades to the role default. The rollback target is the env var, not the
  alias; this is intentional (no orphaned route possible) and recorded so an
  auditor reading §10.2 is not surprised.
* Row 15: scan exit code is **2** with `--fail-on` semantics — findings met the
  severity threshold. Not an error; run status is `completed`.
* Row 15 findings are genuine (SQLi ×2, path traversal on `/ftp/`), executed
  through the Caido proxy in-sandbox (4 × HTTP 200 on proxied requests). The
  credential-shaped lab JWT in the linked tool transcript is redacted in this
  repository copy; request/response structure and routing evidence are retained.
* Final wrap-up: production Errow's allow-list contains only
  `nemotron-3-nano:30b` and `gemma4:31b`; Qwensploit is explicitly rejected.
  Default preloads include both production security models. Qwensploit's
  registry entry remains digest-pinned and is conservatively `multimodal: false`.
* Test 9: triage cap is 1024, not the spec's 512 — nemotron emits a JSON
  envelope that truncated at 512 (see §11 risk 1).

Exactly 18 rows. No row 19 exists in this change record; the draft's earlier
"row 19" was the `scripts/tests/cases/60_health.sh` healthcheck case and is
folded into rows 14/18.

## Supplementary: script regression suite

Not acceptance evidence on its own, but recorded so the handover states what the
harnesses do on this host class (macOS 15.8 arm64, bsdtar, /bin/bash 3.2):

* `vendetta-stack/scripts/tests/test_scripts.sh` — **1254 checks, 0 failed**.
* Portability defects the run exposed in shipped scripts were fixed rather than
  papered over in mocks: `tar --occurrence` (bsdtar lacks it → `verify-bundle.sh`
  probes for the flag), BSD `sed -i` without a suffix (health loopguard fixtures),
  GNU `date -d` (renewal-window assertion), `/proc/sys/vm/max_map_count` absent on
  macOS (preflight expectation), and the model fixtures that still assumed the
  pre-pivot model set / pre-pinned `models.json` (sentinel).
* Two mock-service shutdown deadlocks (main-thread `Event`/`shutdown()` and repeated
  `SIGTERM` re-entering the Python signal handler) were fixed in
  `scripts/tests/mock_stack.py` and `scripts/tests/mock_authd.py`; a leaked listener
  on 127.0.0.1:9103 made the `health_container_ip` precondition flaky.
