#!/usr/bin/env bash
# test_scripts.sh — functional tests for every script in scripts/ (no containers, no network beyond loopback).
#
# Each case copies the relevant parts of the stack into a scratch tree, drives the real scripts against it
# (PATH shims stand in for docker/cosign/step/ss, scripts/tests/mock_stack.py and mock_authd.py stand in for the
# services) and asserts on exit codes, output and the files produced. Scratch data lives under
# $STACK/.scratch/test.<pid> (git-ignored) and is removed on exit; nothing is written to /tmp.
#
# Usage: scripts/tests/test_scripts.sh [--list] [--only case1,case2] [--keep] [-v] [-h]
#
# Traces: PROMPT §3 Phase 3 scripts/tests/test_scripts.sh
#
# Portability (the suite also runs on macOS/bsd): stay on POSIX tar/sed/date/sha256 flags there — no
# `sed -i` without a suffix, no bare `date -d`, no `tar --occurrence/--printf`, and trim `wc -l` output with
# `tr -d ' '` (BSD pads it). Cases that restrict PATH prepend $(plain_path_dir) for a modern bash+sha256.
#
# Exit codes: 0 all tests passed | 1 at least one test failed | 2 usage | 4 a required tool is missing

# shellcheck disable=SC2317  # the helpers are called from the sourced tests/cases/*.sh files, which shellcheck cannot follow
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASH_BIN="$(command -v bash || echo /bin/bash)" # macOS /bin/bash is 3.2: scripts need mapfile/declare -A
REAL_SCRIPTS="$(dirname "$HERE")"
REAL_STACK="$(dirname "$REAL_SCRIPTS")"
WORK="${VS_TEST_WORK_ROOT:-$REAL_STACK/.scratch}/test.$$"
KEEP=0
VERBOSE=0
ONLY=""
LIST=0
TESTS_RUN=0
TESTS_FAILED=0
FAILED_NAMES=()
CURRENT_CASE=""
MOCK_PIDS=()
declare -a CASES=()

if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then C_RED=$'\033[31m' C_GRN=$'\033[32m' C_DIM=$'\033[2m' C_OFF=$'\033[0m'; else C_RED="" C_GRN="" C_DIM="" C_OFF=""; fi

usage() {
  cat <<'EOF'
test_scripts.sh — functional tests for scripts/*.sh

Usage: scripts/tests/test_scripts.sh [--list] [--only case1,case2] [--keep] [-v] [-h]

  --list           print the available cases and exit
  --only A,B       run only these cases (names as printed by --list)
  --keep           keep the scratch directory (printed at the end) for debugging
  -v, --verbose    print the output of failing commands in full
  -h, --help       this text

Required tools: bash ≥ 4.4, openssl, jq, curl, python3, tar, gzip, sha256sum, shellcheck is NOT needed.
Exit codes: 0 all passed | 1 a test failed | 2 usage | 4 required tool missing
EOF
}

cleanup() {
  local pid
  for pid in "${MOCK_PIDS[@]:-}"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "${MOCK_PIDS[@]:-}"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
  if ((KEEP)); then
    echo "scratch kept: $WORK" >&2
  else
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- assertions ------------------------------------------------------------------------------------------
pass() { TESTS_RUN=$((TESTS_RUN + 1)); printf '  %sok%s   %s\n' "$C_GRN" "$C_OFF" "$1" >&2; }
fail() {
  TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); FAILED_NAMES+=("$CURRENT_CASE: $1")
  printf '  %sFAIL%s %s\n' "$C_RED" "$C_OFF" "$1" >&2
  if [[ -n "${2:-}" ]]; then printf '       %s\n' "$2" >&2; fi
  if ((VERBOSE)) && [[ -s "${T_OUT:-}" ]]; then sed 's/^/       | /' "$T_OUT" >&2; fi
  return 0
}

# t_run <label> <expected-rc> <cmd…> — runs the command, output to $T_OUT, asserts the exit code. Always returns 0.
T_OUT=""
T_RC=0
t_run() {
  local label=$1 want=$2
  shift 2
  T_OUT="$WORK/out.$((++OUT_SEQ))"
  T_RC=0
  "$@" >"$T_OUT" 2>&1 </dev/null || T_RC=$?
  if [[ "$T_RC" == "$want" ]]; then pass "$label (rc $T_RC)"; else fail "$label" "expected rc $want, got $T_RC: $(tail -n 3 "$T_OUT" | tr '\n' '|' | cut -c1-300)"; fi
  return 0
}
OUT_SEQ=0

# out_has <label> <ERE> / out_lacks <label> <ERE> — assertions on the last t_run output
out_has() { if grep -Eq -- "$2" "$T_OUT"; then pass "$1"; else fail "$1" "output lacks /$2/: $(tail -n 3 "$T_OUT" | tr '\n' '|' | cut -c1-300)"; fi; return 0; }
out_lacks() { if grep -Eq -- "$2" "$T_OUT"; then fail "$1" "output unexpectedly matches /$2/"; else pass "$1"; fi; return 0; }

# check <label> <cmd…> — passes when the command succeeds
check() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label" "command failed: $*"; fi
  return 0
}
# check_not <label> <cmd…> — passes when the command fails
check_not() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then fail "$label" "command unexpectedly succeeded: $*"; else pass "$label"; fi
  return 0
}
eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "expected '$2' got '$3'"; fi; return 0; }
# BSD stat has no -c; its -f format prints the octal mode via %Lp
file_mode() { stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"; }
mode_is() { eq "$1" "$2" "$(file_mode "$3")"; }

# --- fixtures ---------------------------------------------------------------------------------------------
# new_tree <name> — scratch copy of the stack parts the scripts operate on; sets TREE and S (=TREE/scripts)
new_tree() {
  TREE="$WORK/$1"
  S="$TREE/scripts"
  mkdir -p "$TREE/llm-gateway" "$TREE/errow/mcp" "$TREE/errow/config"
  cp -a "$REAL_SCRIPTS" "$S"
  rm -rf -- "$S"/tests/.work.* "$S"/tests/__pycache__
  cp -a "$REAL_STACK/ollama" "$TREE/ollama"
  cp -a "$REAL_STACK/fluent-bit" "$TREE/fluent-bit"
  cp -a "$REAL_STACK/opensearch" "$TREE/opensearch"
  cp -a "$REAL_STACK/llm-gateway/mcp_policy.yaml" "$TREE/llm-gateway/mcp_policy.yaml"
  cp -a "$REAL_STACK/errow/mcp/policy.yaml" "$TREE/errow/mcp/policy.yaml"
  rm -rf -- "$TREE"/ollama/ollama-lb/workers.d "$TREE"/ollama/ollama-lb/workers.hosts
  mkdir -p "$TREE/home"
}

# make_model_store <dir> <id> <seed> — fake Ollama store entry (manifest + config blob + weight blob); prints the weight sha256
make_model_store() {
  local dir=$1 id=$2 seed=$3 name tag w wsum csum mdir
  name=${id%%:*}
  tag=${id##*:}
  mdir="$dir/manifests/registry.ollama.ai/library/$name"
  mkdir -p "$dir/blobs" "$mdir"
  w="$dir/blobs/.tmp.$$"
  printf 'weights-%s-%s\n' "$id" "$seed" >"$w"
  wsum="$(sha256sum <"$w" | cut -d' ' -f1)"
  mv -f "$w" "$dir/blobs/sha256-$wsum"
  printf '{"model_format":"gguf","id":"%s"}\n' "$id" >"$w"
  csum="$(sha256sum <"$w" | cut -d' ' -f1)"
  mv -f "$w" "$dir/blobs/sha256-$csum"
  jq -n --arg c "sha256:$csum" --arg w "sha256:$wsum" \
    '{schemaVersion: 2, mediaType: "application/vnd.docker.distribution.manifest.v2+json",
      config: {mediaType: "application/vnd.docker.container.image.v1+json", digest: $c, size: 60},
      layers: [{mediaType: "application/vnd.ollama.image.model", digest: $w, size: 40}]}' >"$mdir/$tag"
  printf '%s' "$wsum"
}

pin_models_json() { # <models.json> <id> <sha256>
  jq --arg id "$2" --arg s "$3" '(.models[] | select(.id == $id) | .sha256) = $s' "$1" >"$1.new"
  mv -f "$1.new" "$1"
}

# fixture_models <tree> <store-dir> — store with every model of the tree's models.json, pins written into models.json
fixture_models() {
  local tree=$1 store=$2 id sha
  while IFS= read -r id; do
    sha="$(make_model_store "$store" "$id" fixture)"
    pin_models_json "$tree/ollama/models.json" "$id" "$sha"
  done < <(jq -r '.models[].id' "$tree/ollama/models.json")
}

BASE_TREE=""
# new_tree_pki <name> — new_tree plus secrets/ and pki/ copied from a once-generated base (keeps the suite fast)
new_tree_pki() {
  if [[ -z "$BASE_TREE" ]]; then
    new_tree base-pki
    bootstrap_tree || return 1
    BASE_TREE=$TREE
  fi
  new_tree "$1"
  cp -a "$BASE_TREE/secrets" "$TREE/secrets"
  cp -a "$BASE_TREE/pki" "$TREE/pki"
  if [[ -d "$BASE_TREE/pki-archive" ]]; then cp -a "$BASE_TREE/pki-archive" "$TREE/pki-archive"; fi
}

# bootstrap_tree — secrets + PKI via the real bootstrap script (no preflight, no .env)
bootstrap_tree() {
  "$S/bootstrap.sh" --skip-preflight --no-env -q >"$WORK/bootstrap.$$.out" 2>&1 || { cat "$WORK/bootstrap.$$.out" >&2; return 1; }
}

# shims_dir <name> — fresh directory for PATH shims; prints its path
shims_dir() { mkdir -p "$WORK/shims.$1"; printf '%s' "$WORK/shims.$1"; }

# plain_path_dir — extra PATH entry for the cases that restrict PATH to /usr/bin:/bin. It holds only a modern
# bash (macOS /bin/bash is 3.2: no mapfile/declare -A) and a sha256 tool (macOS keeps sha256sum in /sbin).
plain_path_dir() {
  local d="$WORK/bin.plain"
  if [[ ! -x "$d/bash" ]]; then
    mkdir -p "$d" && ln -sf "$BASH_BIN" "$d/bash"
    local h
    for h in sha256sum shasum; do
      if [[ -n "$(command -v "$h" 2>/dev/null)" ]]; then ln -sf "$(command -v "$h")" "$d/$h"; break; fi
    done
  fi
  printf '%s' "$d"
}

write_shim() { # <dir> <name> — stdin becomes an executable PATH shim
  cat >"$1/$2"
  chmod 0755 "$1/$2"
}

tree_hashes() { # <dir>… — sha256 of every regular file below the directories, sorted by path
  local d
  for d in "$@"; do
    [[ -d "$d" ]] || continue
    (cd "$d" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum)
  done
}

wait_file() { # <file> [tries]
  local f=$1 n=${2:-100}
  while ((n-- > 0)); do
    if [[ -s "$f" ]]; then return 0; fi
    sleep 0.1
  done
  echo "timed out waiting for $f" >&2
  return 1
}

# start_mock <name> <spec.json> — mock_stack.py in the background; ports in $WORK/<name>.ports, requests in $WORK/<name>.req
start_mock() {
  rm -f -- "$WORK/$1.ports" "$WORK/$1.req"
  timeout 600 python3 "$HERE/mock_stack.py" --config "$2" --ports-file "$WORK/$1.ports" --request-log "$WORK/$1.req" >"$WORK/$1.log" 2>&1 &
  MOCK_PIDS+=("$!")
  # shellcheck disable=SC2034  # read by the sourced test cases
  MOCK_LAST_PID=$!
  wait_file "$WORK/$1.ports"
  : >>"$WORK/$1.req"
}
mock_port() { jq -r --arg n "$2" '.[$n]' "$WORK/$1.ports"; }
stop_mock() { # <pid>
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}
req_count() { # <mock> <jq-select-expression> — number of logged requests matching
  jq -s --argjson dummy 0 "[.[] | select($2)] | length" "$WORK/$1.req"
}

# --- runner -----------------------------------------------------------------------------------------------
parse_args() {
  while (($#)); do
    case "$1" in
      --list) LIST=1 ;;
      --only) [[ $# -ge 2 ]] || { echo "--only needs a value" >&2; exit 2; }; ONLY=$2; shift ;;
      --keep) KEEP=1 ;;
      -v | --verbose) VERBOSE=1 ;;
      -h | --help) usage; exit 0 ;;
      *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
  done
}

load_cases() {
  local f fn before after
  for f in "$HERE"/cases/*.sh; do
    before="$(declare -F | awk '{print $3}')"
    # shellcheck source=/dev/null
    source "$f"
    after="$(declare -F | awk '{print $3}')"
    while IFS= read -r fn; do
      if [[ "$fn" == case_* ]] && ! grep -qxF -- "$fn" <<<"$before"; then CASES+=("${fn#case_}"); fi
    done <<<"$after"
  done
}

main() {
  local t tool wanted
  parse_args "$@"
  for tool in openssl jq curl python3 tar gzip sha256sum awk; do
    command -v "$tool" >/dev/null 2>&1 || { echo "required tool missing: $tool" >&2; exit 4; }
  done
  load_cases
  if ((LIST)); then printf '%s\n' "${CASES[@]}"; exit 0; fi
  mkdir -p "$WORK"
  chmod 0700 "$WORK"
  # keep the caller's environment from leaking into the scripts under test
  unset CS3_PROFILE OPENAI_API_KEY ANTHROPIC_API_KEY GEMINI_API_KEY AZURE_OPENAI_API_KEY ERROW_CLOUD_ENABLED STACK_DIR SECRETS_DIR PKI_DIR ENV_FILE \
    PKI_DAYS PKI_CA_DAYS VS_WORK_ROOT OLLAMA_PRELOAD_MODELS MCP_TARGETS_FILE MCP_ALLOWED_CLIENTS OPENSEARCH_URL OPENSEARCH_USER \
    OPENSEARCH_PASSWORD_FILE BACKUP_PASSPHRASE_FILE BACKUP_DIR STACK_VERSION OLLAMA_PINNED_VERSION ENROLL_GATEWAY_URL MCP_ALLOWED_CLIENTS
  export VS_NO_SLEEP=1 NO_COLOR=1 HOME="$WORK/home" LC_ALL=C.UTF-8
  mkdir -p "$HOME"
  for t in "${CASES[@]}"; do
    if [[ -n "$ONLY" ]]; then
      wanted=0
      for tool in $(tr ',' '\n' <<<"$ONLY"); do [[ "$tool" == "$t" ]] && wanted=1; done
      ((wanted)) || continue
    fi
    CURRENT_CASE=$t
    printf '%s== %s%s\n' "$C_DIM" "$t" "$C_OFF" >&2
    "case_$t" || fail "case $t aborted" "a helper command failed unexpectedly (rc $?)"
  done
  printf '\n%d checks, %d failed\n' "$TESTS_RUN" "$TESTS_FAILED" >&2
  if ((TESTS_FAILED)); then
    printf 'failed:\n' >&2
    printf '  - %s\n' "${FAILED_NAMES[@]}" >&2
    exit 1
  fi
  exit 0
}

main "$@"
