# CHG-2026-11-19-NEMOTRON

## Outcome

The live acceptance record is **18/18 PASS**. Production security and Errow use
`nemotron-3-nano:30b`, with `gemma4:31b` as the only fallback. Qwensploit is a
digest-pinned, optional evaluation model; it is not pulled by default and is not
permitted by the production Errow provider policy.

Start with [`ACCEPTANCE.md`](ACCEPTANCE.md), then see
[`RISKS.md`](RISKS.md) and the ISSO-facing
[routing rationale](../../qwensploit-routing-rationale.md). Ground truth,
installer output, router audits, request/response headers, smoke artifacts, and
rollback transcripts are preserved in the numbered directories.

## Repository-copy sanitization

The original capture under `/tmp/cs3live/e/CHG-2026-11-19-NEMOTRON/` was left
unchanged. This durable repository copy deliberately differs as follows:

- `05-errow-smoke/host-docker-internal-3000_a9b5/report.pdf.password` is omitted;
  the encrypted PDF and its SHA-256 remain. Authorized operators must retain the
  decryption secret in the approved secret store, not source control.
- `05-errow-smoke/host-docker-internal-3000_a9b5/.state/agents.db` is omitted
  because the SQLite state contained a credential-shaped lab JWT. The JSON agent
  state remains for task status; `run.json`, `report.json`, and `errow.log` record
  the `openai/cs3-errow-security` route.
- The same lab JWT in `04-live-tests/errow-tool-transcript.md` is replaced by
  `<redacted-lab-jwt>`.

Raw ground-truth output remains a point-in-time snapshot. In particular, its
registry excerpt predates the final conservative `multimodal: false` correction;
the current registry and final routing rationale are authoritative. The
acceptance row-16 reference to a nonexistent `matrix.txt` was replaced with the
actual entrypoint, run-state, and rollback evidence.

`MANIFEST.sha256` covers every file in this repository copy except itself.
`05-errow-smoke/SHA256SUMS.txt` covers the retained smoke artifacts except itself;
neither manifest contains entries for omitted files. Verify from this directory:

```bash
sha256sum -c MANIFEST.sha256
(cd 05-errow-smoke && sha256sum -c SHA256SUMS.txt)
```

## Wrap-up validation

The final source and generated manifests were checked with the gateway security
suite (21 tests), Errow configuration suite (14 tests), Ollama pull/entrypoint
suite (74 checks), registry validator suite (50 checks), hardware planner (17
tests), Errow entrypoint suite (131 assertions), targeted enrollment/health
regressions (91 checks), and the full shell regression suite (1254 checks, zero
failures; transcript in `07-doc/test-scripts.txt`). Compose rendering,
release-mode registry validation, and Helm/Kustomize synchronization checks also
pass.
