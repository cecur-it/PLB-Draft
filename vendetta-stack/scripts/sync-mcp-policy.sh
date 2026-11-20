#!/usr/bin/env bash
#
# sync-mcp-policy.sh — keep the two copies of the MCP tool policy byte-identical.
#
# Traces: PROMPT §3 Phase 3 scripts/sync-mcp-policy.sh; CONTRACT §4.5 (llm-gateway/mcp_policy.yaml is the source of
#         truth; errow/mcp/policy.yaml is a byte-identical copy) and §9 (ownership).
#
# --check  (default)  compare the two files byte-for-byte; exit 1 on drift or when a file is missing.
# --write             copy the llm-gateway policy over the errow copy (atomic, mode 0644); exit 0 when in sync.
#                     --direction errow-to-gateway reverses the copy (use only when the Errow copy was the one edited).
# --dry-run           with --write: report what would be copied without writing.
#
# Exit codes: 0 identical (or synced) | 1 drift / missing file | 2 usage

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

trap 'vs_cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
sync-mcp-policy.sh — verify/sync llm-gateway/mcp_policy.yaml <-> errow/mcp/policy.yaml (byte-identical).

Usage: scripts/sync-mcp-policy.sh [--check | --write] [--direction gateway-to-errow|errow-to-gateway]
                                  [--dry-run] [--gateway-file F] [--errow-file F] [--stack-dir DIR] [-q] [-h]

  --check       (default) exit 1 when the files differ or one is missing
  --write       copy the source of truth (llm-gateway by default) over the other copy
  --dry-run     with --write: show the action only

Exit codes: 0 identical/synced | 1 drift or missing file | 2 usage
EOF
}

ACTION="check"
DIRECTION=gateway-to-errow
GW_FILE=""
ER_FILE=""

while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --check) ACTION="check"; shift ;;
    --write) ACTION="write"; shift ;;
    --dry-run) VS_DRY_RUN=1; shift ;;
    -q|--quiet) VS_QUIET=1; shift ;;
    --direction) vs_need "$@"; DIRECTION=$2; shift 2 ;;
    --direction=*) DIRECTION=${1#*=}; shift ;;
    --gateway-file) vs_need "$@"; GW_FILE=$2; shift 2 ;;
    --errow-file) vs_need "$@"; ER_FILE=$2; shift 2 ;;
    --stack-dir)
      vs_need "$@"
      [[ -d "$2" ]] || die "$EX_USAGE" "stack dir not found: $2"
      STACK_DIR="$(cd "$2" && pwd)"
      shift 2 ;;
    *) die "$EX_USAGE" "unknown option: $1 (see --help)" ;;
  esac
done
case "$DIRECTION" in gateway-to-errow|errow-to-gateway) ;; *) die "$EX_USAGE" "--direction must be gateway-to-errow or errow-to-gateway" ;; esac
if ((VS_DRY_RUN)) && [[ "$ACTION" != write ]]; then die "$EX_USAGE" "--dry-run only applies to --write"; fi

GW_FILE="${GW_FILE:-$STACK_DIR/llm-gateway/mcp_policy.yaml}"
ER_FILE="${ER_FILE:-$STACK_DIR/errow/mcp/policy.yaml}"

for f in "$GW_FILE" "$ER_FILE"; do
  if [[ ! -f "$f" && "$ACTION" == check ]]; then die "$EX_FAIL" "policy file missing: $f"; fi
done

if [[ -f "$GW_FILE" && -f "$ER_FILE" ]] && cmp -s -- "$GW_FILE" "$ER_FILE"; then
  log_ok "MCP policy copies are byte-identical (sha256 $(vs_sha256 "$GW_FILE"))"
  exit "$EX_OK"
fi

if [[ "$ACTION" == check ]]; then
  log_err "MCP policy drift: $GW_FILE and $ER_FILE differ"
  if vs_have diff; then diff -u -- "$GW_FILE" "$ER_FILE" >&2 || true; fi
  log_err "fix: scripts/sync-mcp-policy.sh --write   (copies llm-gateway/mcp_policy.yaml over errow/mcp/policy.yaml)"
  exit "$EX_FAIL"
fi

if [[ "$DIRECTION" == gateway-to-errow ]]; then SRC=$GW_FILE; DST=$ER_FILE; else SRC=$ER_FILE; DST=$GW_FILE; fi
[[ -f "$SRC" ]] || die "$EX_FAIL" "source policy file missing: $SRC"
if ((VS_DRY_RUN)); then log_dry "would copy $SRC -> $DST"; exit "$EX_OK"; fi
mkdir -p "$(dirname "$DST")"
vs_atomic_write "$DST" 0644 <"$SRC"
cmp -s -- "$SRC" "$DST" || die "$EX_FAIL" "copy verification failed for $DST"
log_ok "synced $SRC -> $DST"
exit "$EX_OK"
