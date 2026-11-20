# Claims Audit

Log of capability/standards claims reworded to match what is implemented (DOC-001, DOC-003, DOC-004).

| # | Location | Original claim | Change |
|---|---|---|---|
| 1 | Root spec (`CECUR-IT ... Unified SOC Console.txt`) §1, §3.3, §7 | "OpenAPI v4.14.7 standard/schema" | `spec-v4.14.7.yaml` is the upstream Wazuh v4.14.7 REST API described in OpenAPI **3.0.0**. Claim reworded; filename kept (referenced by NOTICE/.dockerignore). |
| 2 | Root spec §2 | "zero-day surface mapping" | "external attack-surface mapping" |
| 3 | `src/data/legalLiterature.ts` §5.3 | "zero-day threat models" | Reviewed; appears inside a disclaimer of immunity, left for legal review. |
| 4 | Forwarder docs | "TLS 1.3 with mutual certificate verification (mTLS)" | mTLS is opt-in; installers now accept a client cert/key pair (`--client-cert`/`-ClientCert`) and enable it. |
| 5 | Forwarder docs | "< 25 MB" vs `MemoryMax=100M` | Budget vs hard cap stated; unit now sets `MemoryMax=100M`. |
| 6 | Forwarder docs | `Deploy-CecurForwarder.ps1` with `--apikey` on service command line | Marked illustrative/superseded by `Install-CecurForwarder.ps1`. |
