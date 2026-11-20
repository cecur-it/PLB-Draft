#!/usr/bin/env bash
#
# check-allowlists.sh — detect drift between the three Errow target allow-lists.
#
# Traces: CONTRACT §4.5 (MCP policy + additive MCP_TARGETS_FILE), §6 (feedback loop), errow/README.md (target safety).
#
# The lists are ERROW_ALLOWED_TARGETS (errow entrypoint), the errow-mcp / llm-gateway target set (errow/mcp/policy.yaml
# `targets` + the additive MCP_TARGETS_FILE yaml) and ERROW_FEEDBACK_ALLOWED_TARGETS (feedback loop). ERROW_TARGETS is the
# single source of truth: both env lists default from it, an explicit per-service value wins. The .env file is parsed, never
# sourced. Checked: feedback ⊆ ERROW_ALLOWED_TARGETS, ERROW_ALLOWED_TARGETS ⊆ MCP targets, feedback ⊆ MCP targets.
#
# Exit codes: 0 consistent | 1 drift | 2 usage / unreadable input

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat <<'EOF'
check-allowlists.sh — report drift between ERROW_ALLOWED_TARGETS, the errow-mcp targets and ERROW_FEEDBACK_ALLOWED_TARGETS.

Usage: scripts/check-allowlists.sh [--env FILE] [--targets-file FILE] [--policy FILE] [--stack-dir DIR] [-q] [-h]

  --env FILE           env file to read (default: $STACK/.env, else .env.example); parsed, never sourced
  --targets-file FILE  MCP_TARGETS_FILE yaml {hostnames,cidrs,domains,repo_paths} (default: MCP_TARGETS_FILE from the env
                       file, resolved inside MCP_TARGETS_DIR (default ./errow/config); unset = no extension)
  --policy FILE        baseline MCP policy (default: errow/mcp/policy.yaml)
  -q, --quiet          only print problems

Resolution: ERROW_ALLOWED_TARGETS and ERROW_FEEDBACK_ALLOWED_TARGETS default to ERROW_TARGETS (default
scan-target.vendetta.lab); an explicit non-empty value wins. Reports a host pattern that is in the feedback list but not in
ERROW_ALLOWED_TARGETS, or in either of them but not covered by the errow-mcp hostnames/domains/cidrs.

Exit codes: 0 consistent | 1 drift | 2 usage or unreadable input
EOF
}

ENV_IN=""
TARGETS_FILE=""
POLICY_FILE=""

while (($#)); do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    -q | --quiet) VS_QUIET=1; shift ;;
    --env) vs_need "$@"; ENV_IN=$2; shift 2 ;;
    --targets-file) vs_need "$@"; TARGETS_FILE=$2; shift 2 ;;
    --policy) vs_need "$@"; POLICY_FILE=$2; shift 2 ;;
    --stack-dir)
      vs_need "$@"
      [[ -d "$2" ]] || die "$EX_USAGE" "stack dir not found: $2"
      STACK_DIR="$(cd "$2" && pwd)"
      shift 2 ;;
    *) die "$EX_USAGE" "unknown option: $1 (see --help)" ;;
  esac
done

if [[ -z "$ENV_IN" ]]; then
  ENV_IN="$STACK_DIR/.env"
  if [[ ! -f "$ENV_IN" ]]; then
    ENV_IN="$STACK_DIR/.env.example"
    log_warn "no .env found; checking .env.example"
  fi
fi
[[ -r "$ENV_IN" ]] || die "$EX_USAGE" "cannot read env file: $ENV_IN"
POLICY_FILE="${POLICY_FILE:-$STACK_DIR/errow/mcp/policy.yaml}"
[[ -r "$POLICY_FILE" ]] || die "$EX_USAGE" "cannot read policy file: $POLICY_FILE"

# yaml_list <file> <key> [parent] — items of a block (`- x`) or flow (`[x, y]`) list; with a parent, the key is read from
# inside that top-level mapping. Quotes are stripped; comments ignored.
yaml_list() {
  awk -v key="$2" -v parent="${3:-}" '
    function clean(s) { sub(/[ \t]+#.*$/, "", s); gsub(/^[ \t]+|[ \t]+$/, "", s); gsub(/^["\047]|["\047]$/, "", s); return s }
    /^[ \t]*(#|$)/ { next }
    {
      match($0, /^ */); ind = RLENGTH; line = substr($0, ind + 1)
      if (parent != "" && ind == 0) { inparent = (line ~ "^" parent ":"); inkey = 0; next }
      if (parent != "" && !inparent) { next }
      if (line ~ "^" key ":") {
        inkey = 1; keyind = ind; rest = clean(substr(line, length(key) + 2))
        if (rest ~ /^\[/) {
          gsub(/^\[|\]$/, "", rest); n = split(rest, a, ",")
          for (i = 1; i <= n; i++) { v = clean(a[i]); if (v != "") print v }
          inkey = 0
        }
        next
      }
      if (inkey && line ~ /^- /) { v = clean(substr(line, 3)); if (v != "") print v; next }
      if (inkey && ind <= keyind) { inkey = 0 }
    }' "$1"
}

lower() { printf '%s' "${1,,}"; }

# within <name> <suffix>: name == suffix or a subdomain of it
within() { [[ "$1" == "$2" || "$1" == *".$2" ]]; }

# pattern_covers <allowed-entry> <entry>: both are exact hosts or "*.suffix" globs ("*.s" matches subdomains only)
pattern_covers() {
  local a=$1 t=$2
  [[ "$a" == "$t" ]] && return 0
  [[ "$a" == \*.* ]] || return 1
  local s=${a#\*.}
  if [[ "$t" == \*.* ]]; then
    within "${t#\*.}" "$s"
  else
    [[ "$t" == *".$s" ]]
  fi
}

ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  printf '%s' $(((a << 24) | (b << 16) | (c << 8) | d))
}

is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  ((BASH_REMATCH[1] < 256 && BASH_REMATCH[2] < 256 && BASH_REMATCH[3] < 256 && BASH_REMATCH[4] < 256))
}

ip_in_cidr() { # ip cidr
  local ip=$1 net=${2%/*} bits=${2#*/} mask
  is_ipv4 "$net" && [[ "$bits" =~ ^[0-9]+$ ]] && ((bits <= 32)) || return 1
  mask=$(((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
  (( ($(ip_to_int "$ip") & mask) == ($(ip_to_int "$net") & mask) ))
}

MCP_HOSTNAMES=()
MCP_DOMAINS=()
MCP_CIDRS=()

mcp_covers() { # entry
  local t=$1 h d c
  for h in "${MCP_HOSTNAMES[@]}"; do pattern_covers "$h" "$t" && return 0; done
  for d in "${MCP_DOMAINS[@]}"; do
    d=${d#\*.}
    if [[ "$t" == \*.* ]]; then within "${t#\*.}" "$d" && return 0; else within "$t" "$d" && return 0; fi
  done
  if is_ipv4 "$t"; then
    for c in "${MCP_CIDRS[@]}"; do ip_in_cidr "$t" "$c" && return 0; done
  fi
  return 1
}

split_list() { # comma list -> lowercase, trimmed, one entry per line
  local e
  IFS=',' read -r -a _parts <<<"$1"
  for e in "${_parts[@]}"; do
    e=${e//[[:space:]]/}
    [[ -n "$e" ]] && printf '%s\n' "${e,,}"
  done
  return 0
}

DEFAULT_TARGET="scan-target.vendetta.lab"
get() { vs_env_file_get "$ENV_IN" "$1"; }

base="$(get ERROW_TARGETS)"
base="${base:-$DEFAULT_TARGET}"
allowed_raw="$(get ERROW_ALLOWED_TARGETS)"
feedback_raw="$(get ERROW_FEEDBACK_ALLOWED_TARGETS)"
allowed_raw="${allowed_raw:-$base}"
feedback_raw="${feedback_raw:-$base}"
mapfile -t ALLOWED < <(split_list "$allowed_raw")
mapfile -t FEEDBACK < <(split_list "$feedback_raw")

if [[ -z "$TARGETS_FILE" ]]; then
  tf="$(get MCP_TARGETS_FILE)"
  if [[ -n "$tf" ]]; then
    tdir="$(get MCP_TARGETS_DIR)"
    tdir="${tdir:-./errow/config}"
    [[ "$tdir" == /* ]] || tdir="$STACK_DIR/$tdir"
    case "$tf" in
      /etc/vendetta/mcp/*) TARGETS_FILE="$tdir/${tf#/etc/vendetta/mcp/}" ;;
      /*) TARGETS_FILE="$tf" ;;
      *) TARGETS_FILE="$tdir/$tf" ;;
    esac
  fi
fi
if [[ -n "$TARGETS_FILE" && ! -r "$TARGETS_FILE" ]]; then
  die "$EX_USAGE" "MCP targets file not readable: $TARGETS_FILE"
fi

mapfile -t MCP_HOSTNAMES < <(yaml_list "$POLICY_FILE" hostnames targets)
mapfile -t MCP_DOMAINS < <(yaml_list "$POLICY_FILE" domains targets)
mapfile -t MCP_CIDRS < <(yaml_list "$POLICY_FILE" cidrs targets)
if [[ -n "$TARGETS_FILE" ]]; then
  mapfile -t -O "${#MCP_HOSTNAMES[@]}" MCP_HOSTNAMES < <(yaml_list "$TARGETS_FILE" hostnames)
  mapfile -t -O "${#MCP_DOMAINS[@]}" MCP_DOMAINS < <(yaml_list "$TARGETS_FILE" domains)
  mapfile -t -O "${#MCP_CIDRS[@]}" MCP_CIDRS < <(yaml_list "$TARGETS_FILE" cidrs)
fi
for i in "${!MCP_HOSTNAMES[@]}"; do MCP_HOSTNAMES[i]=$(lower "${MCP_HOSTNAMES[i]}"); done
for i in "${!MCP_DOMAINS[@]}"; do MCP_DOMAINS[i]=$(lower "${MCP_DOMAINS[i]}"); done

log_info "env file: $ENV_IN"
log_info "ERROW_ALLOWED_TARGETS          = ${allowed_raw}"
log_info "ERROW_FEEDBACK_ALLOWED_TARGETS = ${feedback_raw}"
log_info "errow-mcp hostnames=[${MCP_HOSTNAMES[*]}] domains=[${MCP_DOMAINS[*]}] (policy ${POLICY_FILE}${TARGETS_FILE:+ + ${TARGETS_FILE}})"

drift=0
report() { # entry from to
  log_err "$1 is in $2 but missing from $3"
  drift=1
}

for e in "${FEEDBACK[@]}"; do
  covered=0
  for a in "${ALLOWED[@]}"; do pattern_covers "$a" "$e" && { covered=1; break; }; done
  ((covered)) || report "$e" ERROW_FEEDBACK_ALLOWED_TARGETS ERROW_ALLOWED_TARGETS
done
for e in "${ALLOWED[@]}"; do
  mcp_covers "$e" || report "$e" ERROW_ALLOWED_TARGETS "the errow-mcp targets (policy.yaml + MCP_TARGETS_FILE)"
done
for e in "${FEEDBACK[@]}"; do
  mcp_covers "$e" || report "$e" ERROW_FEEDBACK_ALLOWED_TARGETS "the errow-mcp targets (policy.yaml + MCP_TARGETS_FILE)"
done

if ((drift)); then
  log_err "allow-list drift: set ERROW_TARGETS (and add the host to the MCP_TARGETS_FILE yaml for real targets)"
  exit "$EX_FAIL"
fi
log_ok "allow-lists are consistent"
exit "$EX_OK"
