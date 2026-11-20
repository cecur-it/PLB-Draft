# §4.3 config audit (live 9101)

Resolved routes and chains exactly as the running router reports them:

| role | primary | chain | available |
|---|---|---|---|
| triage | nemotron-3-nano:30b | nemotron-3-nano:30b -> gemma4:26b | True |
| forensic | gemma4:26b | gemma4:26b -> nemotron-3-nano:30b | True |
| deep | gemma4:31b | gemma4:31b -> gemma4:26b -> nemotron-3-nano:30b | True |
| security | nemotron-3-nano:30b | nemotron-3-nano:30b -> gemma4:31b | True |
| errow | nemotron-3-nano:30b | nemotron-3-nano:30b -> gemma4:31b | True |

* cs3-security falls back to **cs3-reasoning-deep only** (chain `security`: ['nemotron-3-nano:30b', 'gemma4:31b']) — never to cs3-triage. PASS.
* cs3-errow-security chain is ['nemotron-3-nano:30b', 'gemma4:31b'] (Qwensploit slot 1 = nemotron-3-nano:30b after the pivot, Gemma-4 31B second). PASS.
* Budgets per §5.1: triage 1024 (raised from 512, see open risks), security 2048, errow 4096 — enforced by MAX_TOKENS_* in the gateway.
* Cache: enabled for triage only; `cs3-security`/`cs3-errow-security` excluded (nosemantics class `security`).
* Guard model = `gemma4:26b` (never a security alias). PASS.
* Route aliases are compiled in (`ROLE_ALIASES`), so an unset `CS3_MODEL_ERROW_SECURITY` degrades to the role default instead of 404 — see test 18.
