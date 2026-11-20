#!/usr/bin/env bash
# tests/test_manager_leg.sh — the manager leg must render only when enabled, must carry both directions, must keep the
# vendetta.* streams out of a feedback loop, and must fail closed on retry. Pure shell against entrypoint.sh
# --render-only, so it needs no fluent-bit binary and no containers beyond a bash 5 base.
set -uo pipefail

STACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRY="$STACK/fluent-bit/entrypoint.sh"
OUT=$(mktemp -d)
LEG="$OUT/50-manager.conf"
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() {
  printf 'FAIL %s\n' "$1" >&2
  fail=1
}

render() {
  rm -rf "${OUT:?}/"*
  env FLB_CONF_DIR="$STACK/fluent-bit" "$@" "$ENTRY" --render-only "$OUT" >/tmp/render.out 2>&1
}

# has <extended-regex>: asserts the rendered leg matches it.
has() {
  grep -Eq -- "$1" "$LEG"
}

# 1. off by default -------------------------------------------------------------------------------------------
render CS3_MANAGER_ENABLED=false CS3_MANAGER_HOST=vendetta-manager
[[ -f "$LEG" ]] && bad "leg rendered while disabled" || ok "leg absent while disabled"

# 2. enabled renders one leg with both directions --------------------------------------------------------------
render CS3_MANAGER_ENABLED=true CS3_HOST=console.example CS3_MANAGER_HOST=vendetta-manager CS3_INGEST_KEY=k
if [[ -f "$LEG" ]]; then ok "leg rendered when enabled"; else
  bad "leg not rendered"
  cat /tmp/render.out >&2
fi
has '^[[:space:]]*URI +/api/cecur/manager/alerts$' && ok "outbound leg targets the manager alert route" || bad "outbound route missing"
has '^[[:space:]]*Port +\$\{CS3_MANAGER_PORT\}$' && ok "inbound leg targets the manager" || bad "inbound leg missing"
has '^[[:space:]]*Match_Regex +\^\(host\\.\(syslog\|auth\|audit\|network\|endpoint\)\)\$$' && ok "inbound leg takes exactly the host streams" || bad "inbound leg matches wrong tags"
has '^[[:space:]]*Match_Regex +\^\(manager\\.alerts\)\$$' && ok "outbound leg takes only manager alerts" || bad "outbound leg matches wrong tags"
has '^[[:space:]]*Header +X-API-Key \$\{CS3_INGEST_KEY\}$' && ok "ingest key is sent" || bad "ingest key header missing"

# The vendetta.* streams are already manager output; feeding them back would loop.
if has 'Match_Regex.*vendetta\.'; then
  bad "leg also matches a vendetta.* stream (feedback loop)"
else
  ok "no vendetta.* stream in the leg"
fi

# Fail closed: unsent alerts must persist and never be dropped.
has '^[[:space:]]*Retry_Limit +False$' && ok "outbound retries forever" || bad "outbound can drop alerts"
has '^[[:space:]]*storage\.type +filesystem$' && ok "buffer survives a restart" || bad "buffer is memory-only"

# 3. missing required variables are rejected ------------------------------------------------------------------
render CS3_MANAGER_ENABLED=true CS3_HOST=console.example CS3_INGEST_KEY=k
if grep -q 'requires CS3_MANAGER_HOST' /tmp/render.out; then ok "missing manager host is rejected"; else bad "missing manager host accepted"; fi

render CS3_MANAGER_ENABLED=true CS3_HOST=console.example CS3_MANAGER_HOST=m CS3_INGEST_KEY=k CS3_MANAGER_PORT=0
if grep -q 'CS3_MANAGER_PORT must be 1-65535' /tmp/render.out; then ok "bad port is rejected"; else bad "bad port accepted"; fi

rm -rf "$OUT"
exit "$fail"
