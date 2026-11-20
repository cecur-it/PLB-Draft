# 02 — install path

Installer flow: `vendetta-stack/ollama/pull-models.sh` (invoked by `install.sh` and the compose/helm entrypoints) selects the canonical upstream and aliases the deterministic tag.

```
```

Real pull transcript tail (5.8 GB weights + 921 MB vision/patch blob, sha256 verified, `success`):

```
verifying sha256 digest ⠙ [K[?25h[?2026l[?2026h[?25l[A[A[A[A[1Gpulling manifest [K
verifying sha256 digest [K
writing manifest [K
success [K[?25h[?2026l
success
pulling 886a916b8f37: 100% ▕██████████████████▏  479 B                         [K
verifying sha256 digest ⠙ [K[?25h[?2026l[?2026h[?25l[A[A[A[A[1Gpulling manifest [K
pulling 2eb53a090487: 100% ▕██████████████████▏ 5.8 GB                         [K
pulling 1aa1b0076b41: 100% ▕██████████████████▏ 921 MB                         [K
pulling 886a916b8f37: 100% ▕██████████████████▏  479 B                         [K
verifying sha256 digest [K
success [K[?25h[?2026l
success
```

Registry entry with the real digest:

```json
 "id": "qwensploit-v2:9b",
 "tier": "eval",
 "optional": true,
 "quantization": "Q4_K_M",
 "upstream": "hf.co/xtools-at/Qwensploit-V2-9B-CyberSecurity-Qwen3.5-GGUF:Q4_K_M",
 "sha256": "2eb53a090487b2b2e4391b88f6109fe64ba32f5c95ddbd9196bc54204b88ef53"
```

## Live re-check of the pull path (idempotent, digest-verified)

```
$ ./pull-models.sh --models qwensploit-v2:9b --dry-run   # CS3_PROFILE=cloud
[pull-models] profile=cloud release=false models: qwensploit-v2:9b
[pull-models] qwensploit-v2:9b: stored weights match the pinned SHA-256 2eb53a090487...
[pull-models] qwensploit-v2:9b already present — skipping (idempotent).
```

The pull is generic: models.json carries `upstream`, the script pulls from it and registers the approved local id. The eval tier is opt-in (`--models qwensploit-v2:9b` or `--models all`); the base install pulls primary/fallback/security only.
