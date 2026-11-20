# Manager API contract (what this stack depends on)

Traces: CONTRACT §6 (live actions need the live gate, a signed approval and the agent allow-list), README §"Assumptions
and known limits" (the bundled manager is a stand-in), `errow/feedback-loop/APPROVALS.md`,
`scripts/pin-manager-cert.sh`, `scripts/verify-manager.sh`.

The bundled manager uses the Vendetta-compatible stand-in image `wazuh/wazuh-manager:4.9.2` by default
(`VENDETTA_MANAGER_IMAGE` overrides it). Nothing in this stack
calls a management API besides the two calls below, so a replacement only has to satisfy exactly these — anything
else in the image is unused by CS3.

## Required surface

| # | Call | Used by | Contract |
|---|---|---|---|
| 1 | `POST /security/user/authenticate` | `errow/feedback-loop/lib.sh`, `action_gate.py` → `vapi_token()` | Basic auth with `VENDETTA_API_USER` + `VENDETTA_API_PASSWORD_FILE`; JSON answer with `data.token`; the token is sent as `Authorization: Bearer …` and is fetched once per invocation |
| 2 | `PUT /active-response?agents_list=<ids>` | both live legs | Bearer JWT; JSON body whose `command` is `ERROW_FEEDBACK_AR_COMMAND` (default `!host-isolate.sh`); `alert.data.errow_fingerprint` and `.errow_run` are carried through for traceability; `agents_list` is the resolved agent id(s) |

Both calls are TLS-only. The manager must present a certificate whose SAN covers **`vendetta-manager`** (the name
containers verify), and that certificate must be **pinned** — see below.

`host-isolate` must be registered on the manager side with the agent-side script from
`vendetta/active-response/host-isolate.sh` in the `command`/`active-response` block, or call 2 returns a `command`
error that the gate surfaces as a failed action. `vendetta/ossec-hooks.conf` is where that registration lives.

## Agent identity

`agents_list` accepts agent **ids**, resolved from a hostname or IP by
`GET /agents?select=id,name,ip&limit=500` (`errow/feedback-loop/lib.sh::vapi_agents`). Duplicate IPs and the manager
itself (`000`) are excluded by the caller, not by the manager: an agent id that resolves ambiguously is refused
rather than guessed. The id is additionally filtered by `VENDETTA_EXECD_AGENT_REGEX`, shared with the Fluentd execd
gate so both live legs allow exactly the same agents.

## TLS trust and pinning

`action_gate.py` builds its SSL context from `VENDETTA_API_CA_FILE` and **fails closed** (503) when the file is
missing or unusable. It never falls back to the system store: a CA that silently degrades widens the trust scope
without anyone noticing.

The stand-in image creates `/var/ossec` at first boot and lets authd generate its own self-signed certificate, so
nothing chains to `pki/ca.crt` until it is pinned:

```bash
scripts/pin-manager-cert.sh                    # probe, inspect, write pki/manager-ca-bundle.crt
scripts/verify-manager.sh
```

* The bundle is `pki/ca.crt` + the pinned leaf. It is additive — the private CA is never replaced — so a later
  pki-issued manager certificate still verifies.
* Pinning an untrusted/self-signed certificate, or one without the `vendetta-manager` SAN, needs `--yes`; a changed
  certificate needs `--force`.
* `vendetta-manager`'s own `pki/vendetta-manager.crt` is issued by `bootstrap.sh` but **mounted nowhere yet** (staging
  gap). Until it is, authd's self-signed certificate is what gets pinned. This is the one place the stand-in is
  visible to callers.

## Swapping in a real manager

1. Set `VENDETTA_MANAGER_IMAGE` and keep ports 1514/1515/1516/55000 and the `alerts.json` layout (or adapt the
   Fluent Bit `tail` path).
2. Satisfy the two calls above, including `data.token` and the `!host-isolate.sh` command registration.
3. Serve a certificate that chains to `pki/ca.crt` with SAN `vendetta-manager` and re-run
   `scripts/pin-manager-cert.sh --force`, then `scripts/verify-manager.sh`.
4. Re-run `errow/feedback-loop/tests/test_feedback_loop.sh` and `tests/test_action_gate.py` against the new manager
   before trusting it with `ERROW_FEEDBACK_LIVE=true`.

**Race with approval lines.** `approval.py keygen` and `sign` run on the host, never in the manager, so a manager
swap never invalidates the ledger.

## Image architecture

The stand-in is **amd64-only**; on arm64 hosts run it with Docker's emulation (compose does this automatically on
Apple silicon, and warns). A native-arch replacement removes the emulation cost.
