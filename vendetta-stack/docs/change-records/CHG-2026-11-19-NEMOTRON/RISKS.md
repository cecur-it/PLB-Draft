# §11 open risks — CHG-2026-11-19-NEMOTRON

1. **Triage budget raised 512 → 1024.** At 512 the triage envelope truncated
   mid-JSON on long generations; the contract now ships 1024. Re-validate if the
   triage prompt grows.
2. **Security quality rides on the tool loop, not a tuned checkpoint.** Both
   security classes are served by a general agentic model; the OpenSearch
   CVE/ATT&CK/playbook index that is meant to carry domain knowledge is designed
   but not yet wired into the prompt — today the model relies on its own priors
   plus MCP tool output.
3. **Errow findings depend on instruction quality.** With this agentic tier the
   report tools (`create_vulnerability_report`, 16 required parameters) are easy
   for a 30B model to malform: two scoping runs filed 0 findings before the
   instruction file spelled out the parameter list and the "every turn must call
   a tool" rule. Ship the instruction file with the profile, and treat
   `findings == 0` as a possible harness defect, not automatically a clean target.
4. **`code_locations` is passed as a JSON string by nemotron** and the tool
   rejects it (expects a list). Workaround: omit the field. Upstream fix would be
   a coercion in the reporting tool.
5. **Eval tier is opt-in and usually absent.** `qwensploit-v2:9b` has a real
   SHA-256 pin in `models.json` but is pulled only on request. A host that never
   runs the opt-in pull has no eval model, and airgap direct mode against it fails
   closed (test 14) rather than substituting.
6. **Fallback is execution-continuity only.** A run served by `gemma4:31b` is
   flagged degraded and needs analyst review; it is not equivalent evidence.
7. **Qwensploit context length / multimodal** are still unconfirmed for the eval
   tier. The registry conservatively marks `multimodal: false`; no mmproj blob was
   verified in this pass, so this record makes no image-capability claim.
8. **Caido patches are upstream-local.** The sandbox fixes (deadline-bounded guest
   login, loopback bridge) live in mounted/edited upstream files; an image rebuild
   from a clean Errow tree silently drops them until they are upstreamed.
9. **No git baseline.** The working copy is not a git repository, so §10.1's
   `git checkout <PRE_CHANGE_COMMIT>` rehearsal was done by file backup +
   SHA-256 comparison instead of git.
