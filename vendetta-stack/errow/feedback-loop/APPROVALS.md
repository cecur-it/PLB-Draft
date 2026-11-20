# Errow feedback-loop approval ledger

Traces: CONTRACT §6 (G9 offensive safety), `errow-to-vendetta.sh`, `approval.py`.

`errow-to-vendetta.sh` acts on Vendetta (host isolation, SOAR ticket, retest request) only when **both** gates are open:

1. `ERROW_FEEDBACK_LIVE=true` in the environment of the process running the script, and
2. a **signed, unexpired approval line** for the finding's fingerprint exists in this file.

Without either gate the script prints `DRY-RUN: would ...` lines and changes nothing. The ledger ships **empty**: this
repository contains no real approvals, and lines shown inside code fences below are ignored by the verifier.

This ledger is the **only** approval path to the manager. Both live active-response legs check it through the same verifier
(`approval.py`, driven by `action_gate.py`):

| Leg | Caller | Verifier |
|---|---|---|
| Errow finding -> `errow-to-vendetta.sh` -> `PUT /active-response` | errow-feedback webhook, `POST /errow-finding` | `approval.py verify` in-process |
| Vendetta alert (Fluentd `@VENDETTA_EXECD`) -> `POST /approved-action` | Fluentd, delivered to errow-feedback | `action_gate.Gate`, which shells out to `approval.py verify` |

The Fluentd leg used to call the manager directly and never consulted this file; it now has no credential of its own and cannot
act unless the gate approves. Both legs additionally require the agent to match `VENDETTA_EXECD_AGENT_REGEX` (the manager
`000` is always refused).

## Line format

One approval per line, starting in column 0 (outside code fences):

```
APPROVAL fingerprint=<64 hex> approver=<id> expires=<YYYY-MM-DDTHH:MM:SSZ> sig=<64 hex>
```

| Field | Rule |
|---|---|
| `fingerprint` | the SARIF `partialFingerprints.primaryLocationLineHash` of the finding (`errow.fingerprint` in the alert); 64 lowercase hex |
| `approver` | `[A-Za-z0-9._@-]{1,64}`; optionally restricted with `ERROW_FEEDBACK_APPROVERS=alice,bob` |
| `expires` | ISO-8601 UTC with the literal `Z`, to the second; must be in the future and at most `ERROW_FEEDBACK_APPROVAL_MAX_DAYS` (default 30) ahead |
| `sig` | lowercase hex `HMAC-SHA256(key, "errow-feedback-approval-v1\nfingerprint=<fp>\napprover=<id>\nexpires=<iso>")` |

`key` is the approver's own key file, `$ERROW_FEEDBACK_APPROVAL_KEYS_DIR/<approver>.key` (default directory:
`<approval-dir>/keys`, mounted at `/run/approval/keys`), at least 32 characters, mode 0600. Authority is per approver: a
line is only valid if `sig` verifies with **that approver's** key, so one person's key cannot sign for another.

## Approver keys, thresholds and custody

```
umask 077
python3 errow/feedback-loop/approval.py keygen --approver alice     # writes keys/alice.key, 0600, 64 hex
```

- **Threshold.** `ERROW_FEEDBACK_APPROVAL_THRESHOLD` distinct approvers (default **2** = dual control) must have signed
  the same fingerprint before either leg acts. One line from one approver is not enough.
- **Custody follows the approver.** Generate the key on the approver's own workstation, sign there, and append only the
  resulting *line* to this file. The key is then copied once to the host directory that is mounted read-only into
  `errow-feedback` — verification needs the key material, but no one else ever needs write access to it. One approver
  holding a copy of another's key file collapses the separation again.
- **Rotation.** `keygen` refuses to overwrite an existing key without `--force`; after a rotation, re-sign the still-open
  fingerprints with the new key and revoke the old one. A key rotation invalidates every line that approver signed.
- **Shared key fallback.** The single shared key `ERROW_FEEDBACK_APPROVAL_KEY_FILE` still works and still counts as one
  authority, but it clamps the effective threshold to the number of authorities present. A deployment with only the
  shared key therefore runs at threshold 1 — no dual control — and `scripts/bootstrap.sh --check` warns about exactly
  that. Give every approver a key and keep the shared key only as a break-glass signer.
- **Mode.** Keys and the containing directories are checked for loose modes (`bootstrap.sh --check` fails on a key looser
  than 0600). Mounts are read-only, so a loose *host* mode is the thing to fix.

If a key is missing, too short, or unreadable, every live action is denied (fail closed).

## Signing and verifying

```
# print a line valid for 4 hours (max 168) and append it after review
python3 errow/feedback-loop/approval.py sign --fingerprint <fp> --approver alice --ttl-hours 4 \
  --keys-dir secrets/approval/keys >> errow/feedback-loop/APPROVALS.md

# check what the script will decide (exit 0 approved, 1 not approved/threshold unmet, 2 configuration error)
python3 errow/feedback-loop/approval.py verify --fingerprint <fp> --file errow/feedback-loop/APPROVALS.md \
  --keys-dir secrets/approval/keys
```

Use `--expires 2026-12-01T00:00:00Z` instead of `--ttl-hours` for an explicit expiry. An approval covers all three
actions for that one fingerprint; it does not cover other findings, other hosts, or hosts outside
`ERROW_FEEDBACK_ALLOWED_TARGETS`.

## Operations

- Mount this file at `/opt/feedback-loop/APPROVALS.md` read-only (compose bind mount / K8s ConfigMap or Secret). Override the
  location with `ERROW_FEEDBACK_APPROVALS_FILE`.
- Expired and malformed lines are ignored; prune them during review. Every decision is logged to
  `/var/log/feedback-loop/feedback.log` (`DENIED fingerprint=... reason=...` or `LIVE: ...`).
- Approving a finding's `partialFingerprints.primaryLocationLineHash` covers **both** legs: the Errow webhook and the Fluentd
  execd leg carry the same value (`errow.fingerprint` in the derived alert), so one line authorises at most one action per leg.
- Revoke early by deleting the line (or rotating the key, which invalidates all lines at once).
- Each executed action leaves a marker in `$FEEDBACK_DIR/state/`, so repeating an approved run never repeats the action.
- Kubernetes: the approval Secret is mounted at `/run/approval` (`defaultMode 0440`), so add each key as a Secret key
  named `keys/<approver>.key` and set `ERROW_FEEDBACK_APPROVAL_THRESHOLD` (chart value `config.approvalThreshold`). The
  CA there is cert-manager's `/pki/ca.crt`, so no pin runs are needed; in compose, pin the manager certificate instead
  (`scripts/pin-manager-cert.sh`) and point `VENDETTA_API_CA_FILE` at the bundle. Without a usable bundle the gate
  refuses every live action with `503`.
