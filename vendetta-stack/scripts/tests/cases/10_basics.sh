# shellcheck shell=bash
# Cases: --help / unknown flags for every script, static hygiene (shebang, strict mode, traces header).

ALL_SCRIPTS=(bootstrap enroll-agent enroll-errow enroll-ollama rotate-certs backup-opensearch build-airgap-bundle verify-bundle healthcheck sync-mcp-policy)

case_help() {
  local s f want
  for s in "${ALL_SCRIPTS[@]}"; do
    f="$REAL_SCRIPTS/$s.sh"
    check "$s.sh is executable" test -x "$f"
    t_run "$s.sh --help" 0 "$f" --help
    out_has "$s.sh --help documents exit codes" '[Ee]xit codes?'
    out_has "$s.sh --help shows usage" '[Uu]sage'
    # healthcheck.sh reserves 0/1/2 for healthy/degraded/unhealthy (usage error 64); verify-bundle.sh uses 1 for usage/IO, 2 for integrity
    case "$s" in healthcheck) want=64 ;; verify-bundle) want=1 ;; *) want=2 ;; esac
    t_run "$s.sh rejects an unknown option" "$want" "$f" --definitely-not-an-option
  done
}

case_hygiene() {
  local f name
  for f in "$REAL_SCRIPTS"/*.sh "$REAL_SCRIPTS"/lib/*.sh "$HERE"/test_scripts.sh "$HERE"/cases/*.sh; do
    name="${f#"$REAL_SCRIPTS"/}"
    case "$name" in validate-models-json.sh) continue ;; esac
    if [[ "$f" == */lib/* || "$f" == */cases/* ]]; then
      check "$name is a sourced file (shellcheck shell=bash)" grep -q '^# shellcheck shell=bash' "$f"
      continue
    fi
    check "$name starts with '#!/usr/bin/env bash'" test "$(head -n 1 "$f")" = '#!/usr/bin/env bash'
    check "$name uses strict mode" grep -q '^set -euo pipefail' "$f"
    check "$name sets IFS=\$'\\n\\t'" grep -qF "IFS=\$'\\n\\t'" "$f"
    check "$name has an ERR trap" grep -q "^trap 'echo \"FAILED at line \$LINENO\" >&2' ERR" "$f"
    check "$name has a Traces header" grep -q '^# Traces: ' "$f"
    check_not "$name has no TODO/FIXME/placeholder markers" grep -Eiq 'TODO|FIXME|XXX-|placeholder' "$f"
  done
}
