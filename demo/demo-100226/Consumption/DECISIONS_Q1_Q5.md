# Decision Record: Open Decisions Q1–Q5 (Inference Migration)

Status: proposed defaults, pending human overseer sign-off.

| # | Decision |
|---|---|
| Q1 | Ollama API surface as developer standard; vLLM behind the gateway in `cloud`, Ollama for `edge`/`onprem`/`airgap` (D1). |
| Q2 | Edge = deterministic engine (primary in `airgap`, D4); site node = quantized forensic model; edge escalates to the site node over a one-way/diode channel. |
| Q3 | No fine-tuning in v1 (D3). Prompt/RAG only; `fineTune()` stub only (INF-010). |
| Q4 | Gemma/Nemotron licenses are not assumed cleared for the DIB set. Counsel reviews the exact checkpoints; Tier 3/DIB marketing blocked until INF-004 passes; keep a permissively licensed fallback model. |
| Q5 | Both customer-supplied (`onprem`/`airgap`) and provider GPU pool (`cloud`); minimum VRAM per profile/role documented in AG-007; capacity and break-even analysis before cloud GA (D5). |
