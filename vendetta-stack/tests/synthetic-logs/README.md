# Synthetic log fixtures

Realistic, secret-free fixtures shared by `tests/validate-pipeline.py`, `tests/smoke-test.sh`
and `errow/feedback-loop/`. All files are valid JSON (`jq empty`). The lab target is always
`scan-target.vendetta.lab` (`10.77.0.20`), the only host the MCP policy allows.

| File | Shape / source | Used for |
|---|---|---|
| `vendetta-alert.json` | Raw analysisd alert (rule 5763, level 10, sshd brute force, MITRE T1110) with `@timestamp` added. | `POST /vendetta.alerts`, gateway `/triage`, injection-probe base (override `full_log` / `data.srcuser`). |
| `vendetta-fim.json` | Syscheck alert (rule 550, level 7, `syscheck_entry_modified`) for `/var/www/scan-target/routes/search.js`. | `POST /vendetta.fim`; `vendetta-to-errow.sh` trigger source. |
| `errow-finding.sarif.json` | SARIF 2.1.0 produced by the real `errow/errow/report/sarif.py` `build_sarif_report()`: 3 results (HIGH SQLi `CWE-89`, MEDIUM XSS `CWE-79`, LOW `CWE-200`, none with a CVE). No PoC script bodies. | Dropped as `findings.sarif`; input of `schema-validate.py sarif` and `errow-to-vendetta.sh`. |
| `errow-run.json` | `run.json` as written by `scan_setup._persist_run_record` + `ReportState` (status, `targets_info`, `llm_usage`, `scan_results`). | Dropped as `run.json` -> `errow-runs` stream. |
| `errow-llm-request.json` | One `LlmRequestEvent.to_dict()` (`llm/request_log.py`): route litellm, model `openai/nemotron-3-nano:30b`, host `llm-gateway:9101`, non-streaming, sizes and tokens only (no prompt bodies). | `errow-llm-logs-*` shipper stream. |
| `errow-threat-model.json` | `.state/threat_models.json` (dict keyed by normalized target `scan-target.vendetta.lab:8080`; `content`, `written_at`, `written_by`, one amendment). | Dropped as `.state/threat_models.json` -> `errow-threat-models`. |
| `errow-mcp-tool-call.json` | A `cs3.ai.tool_call` event (contract 4.3): dry-run `nmap -sT` on `scan-target.vendetta.lab`, genesis of chain `llm-gateway-0` (`seq` 0, `prev_hash` = 64 zeros). `hash = sha256(prev_hash + canonical_json(event without hash))` with sorted keys and `(",", ":")` separators - verified valid. | Audit-chain checks, `errow-mcp-*` ingest. |
| `ai-incident-analysis.json` | Valid `AIIncidentAnalysis` (contract 4.2) incl. `toolCalls` for the nmap call above. | `schema-validate.py ai`, gateway output-schema tests. |

Regenerate the SARIF fixture only through `build_sarif_report()` so it stays byte-compatible with
Errow's real output; recompute the `hash` of `errow-mcp-tool-call.json` if any field changes
(see `errow/feedback-loop/tests/` for the verification helper logic).
