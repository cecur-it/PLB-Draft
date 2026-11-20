# shellcheck shell=bash
# shellcheck disable=SC2034  # constants/globals below are consumed by the scripts that source this library
#
# scripts/lib/common.sh — shared helpers for every vendetta-stack operator script.
#
# Traces: PROMPT §3 Phase 3 scripts/lib/common.sh; CONTRACT §0 (shell rules), §2 (names/ports/secrets),
#         CS3 §3.3 (air-gap parity), CS3 deployment/agents/install-forwarder.sh (conventions).
#
# Provides: strict mode, colored logging (no color when stderr is not a tty or NO_COLOR is set),
# exit-code constants, cleanup registry, work-dir allocation (never /tmp: $STACK/.scratch), retry with
# exponential backoff, curl wrapper that never puts secrets on argv, secret-file helpers, compose
# detection, the FailClosed (CS3_PROFILE onprem/airgap + cloud LLM keys) check, and arg normalisation.
#
# Source it; do not execute it:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=lib/common.sh
#   source "$SCRIPT_DIR/lib/common.sh"

if [[ -n "${VS_COMMON_LOADED:-}" ]]; then return 0; fi
VS_COMMON_LOADED=1

set -euo pipefail
IFS=$'\n\t'
set -o errtrace

# ---------------------------------------------------------------------------------------------------
# Exit codes shared by all scripts (each script documents the subset it uses in --help / README).
# ---------------------------------------------------------------------------------------------------
readonly EX_OK=0        # success
readonly EX_FAIL=1      # runtime failure / degraded
readonly EX_USAGE=2     # bad usage or unreadable input
readonly EX_POLICY=3    # policy refusal (FailClosedError, sentinel in --release, missing signature, ...)
readonly EX_PREREQ=4    # missing prerequisite (tool, version, kernel setting, port in use, ...)
readonly EX_NOTREADY=5  # --check found problems / remote system refused

VS_NAME="$(basename "${0:-script}" .sh)"
VS_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VS_SCRIPTS_DIR="$(dirname "$VS_COMMON_DIR")"
STACK_DIR="${STACK_DIR:-$(dirname "$VS_SCRIPTS_DIR")}"
STACK_DIR="$(cd "$STACK_DIR" && pwd)"
SECRETS_DIR="${SECRETS_DIR:-$STACK_DIR/secrets}"
PKI_DIR="${PKI_DIR:-$STACK_DIR/pki}"
# Archived key material (previous certificate sets, old CA, mkcert CAROOT). Must stay OUTSIDE pki/: compose mounts the whole
# pki/ tree at OpenSearch's config/certs, and its security setup dies on any subdirectory uid 1000 cannot read.
VS_PKI_ARCHIVE_ENV="${PKI_ARCHIVE_DIR:-}"   # an explicit override survives a script's --stack-dir re-rooting
PKI_ARCHIVE_DIR="${PKI_ARCHIVE_DIR:-$STACK_DIR/pki-archive}"
ENV_FILE="${ENV_FILE:-$STACK_DIR/.env}"
COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-vendetta-stack}"

VS_DRY_RUN=0
VS_QUIET=0
VS_VERBOSE=0

# Secrets that bootstrap.sh generates (CONTRACT §2) — one file each under $SECRETS_DIR.
readonly VS_SECRET_NAMES=(opensearch_admin_password llm_gateway_token errow_api_token grafana_admin_password feedback_webhook_token vendetta_api_password cs3_approval_token)

# ---------------------------------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------------------------------
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_BLD=""; C_RST=""
fi
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  O_RED=$'\033[31m'; O_GRN=$'\033[32m'; O_YEL=$'\033[33m'; O_RST=$'\033[0m'
else
  O_RED=""; O_GRN=""; O_YEL=""; O_RST=""
fi

log_info()  { if ((VS_QUIET)); then return 0; fi; printf '%s[%s]%s %s\n' "$C_BLU" "$VS_NAME" "$C_RST" "$*" >&2; }
log_step()  { if ((VS_QUIET)); then return 0; fi; printf '%s[%s] ==>%s %s%s%s\n' "$C_BLU" "$VS_NAME" "$C_RST" "$C_BLD" "$*" "$C_RST" >&2; }
log_ok()    { if ((VS_QUIET)); then return 0; fi; printf '%s[%s][ ok ]%s %s\n' "$C_GRN" "$VS_NAME" "$C_RST" "$*" >&2; }
log_warn()  { printf '%s[%s][warn]%s %s\n' "$C_YEL" "$VS_NAME" "$C_RST" "$*" >&2; }
log_err()   { printf '%s[%s][FAIL]%s %s\n' "$C_RED" "$VS_NAME" "$C_RST" "$*" >&2; }
log_debug() { if ((VS_VERBOSE)); then printf '%s[%s][dbg ]%s %s\n' "$C_DIM" "$VS_NAME" "$C_RST" "$*" >&2; fi; }
log_dry()   { printf '%s[%s][dry ]%s %s\n' "$C_YEL" "$VS_NAME" "$C_RST" "$*" >&2; }

# die <exit-code> <message...>
die() { local code=$1; shift; log_err "$*"; exit "$code"; }

# run <cmd...> — executes, or only prints the command under --dry-run.
run() {
  if ((VS_DRY_RUN)); then log_dry "$*"; return 0; fi
  "$@"
}

# ---------------------------------------------------------------------------------------------------
# Cleanup registry (EXIT trap is installed by each script: trap 'vs_cleanup' EXIT)
# ---------------------------------------------------------------------------------------------------
VS_CLEANUP_PATHS=()
VS_CLEANUP_HOOKS=()

vs_register_cleanup() { VS_CLEANUP_PATHS+=("$1"); }
vs_on_exit() { VS_CLEANUP_HOOKS+=("$1"); }

vs_cleanup() {
  local rc=$? p h
  trap - ERR
  # bash 3.2 treats an empty array as unset under `set -u`, so expand defensively
  for h in ${VS_CLEANUP_HOOKS[@]+"${VS_CLEANUP_HOOKS[@]}"}; do eval "$h" >/dev/null 2>&1 || true; done
  for p in ${VS_CLEANUP_PATHS[@]+"${VS_CLEANUP_PATHS[@]}"}; do
    if [[ -n "$p" && -e "$p" ]]; then rm -rf -- "$p" 2>/dev/null || true; fi
  done
  return "$rc"
}

# vs_work_root — directory for scratch data. Never /tmp: $STACK/.scratch (git-ignored), else a per-user cache.
vs_work_root() {
  local cand
  for cand in "${VS_WORK_ROOT:-}" "$STACK_DIR/.scratch" "${XDG_RUNTIME_DIR:-}/vendetta-stack" "$HOME/.cache/vendetta-stack"; do
    [[ -n "$cand" && "$cand" != "/vendetta-stack" ]] || continue
    if (umask 077; mkdir -p "$cand") 2>/dev/null && [[ -w "$cand" ]]; then
      chmod 0700 "$cand" 2>/dev/null || true
      printf '%s' "$cand"
      return 0
    fi
  done
  return 1
}

# vs_mkwork <label> — creates a 0700 scratch directory (atomic mkdir, no mktemp), registers it for cleanup and
# stores it in VS_WORK (call it directly, not in $(...), so the cleanup registration survives).
VS_WORK=""
vs_mkwork() {
  local label=${1:-work} root d i
  root="$(vs_work_root)" || die "$EX_PREREQ" "no writable scratch directory (set VS_WORK_ROOT)"
  for i in 1 2 3 4 5 6 7 8; do
    d="$root/$label.$$.$RANDOM$RANDOM"
    if (umask 077; mkdir "$d") 2>/dev/null; then
      vs_register_cleanup "$d"
      VS_WORK=$d
      return 0
    fi
  done
  die "$EX_PREREQ" "cannot allocate a scratch directory under $root"
}

# ---------------------------------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------------------------------
vs_have() { command -v "$1" >/dev/null 2>&1; }

# vs_join <separator> <items...> — join without depending on IFS (which is newline/tab in every script).
vs_join() {
  local sep=$1 out="" first=1 i
  shift
  for i in "$@"; do
    if ((first)); then out=$i; first=0; else out+="$sep$i"; fi
  done
  printf '%s' "$out"
}

# vs_require <cmd>... — exit EX_PREREQ naming every missing tool.
vs_require() {
  local missing=() c
  for c in "$@"; do vs_have "$c" || missing+=("$c"); done
  if ((${#missing[@]})); then die "$EX_PREREQ" "missing required tool(s): $(vs_join " " "${missing[@]}")"; fi
}

vs_ts() { date -u +%Y%m%dT%H%M%SZ; }
vs_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
# Portable date conversions: GNU date has -d, BSD date does not (-d is a DST offset there and needs -j -f).
vs_date_to_epoch() { # <YYYY-MM-DD HH:MM:SS | openssl notAfter string> → epoch seconds
  local s=$1
  date -u -d "$s" +%s 2>/dev/null && return 0
  date -j -u -f '%Y-%m-%d %H:%M:%S' "$s" +%s 2>/dev/null && return 0
  date -j -u -f '%b %d %T %Y %Z' "$s" +%s 2>/dev/null
}
vs_epoch_to_iso() { # <epoch> → ISO-8601 UTC
  date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -j -u -r "$1" +%Y-%m-%dT%H:%M:%SZ
}

# vs_normalize_args "$@" → NORM_ARGS (expands --opt=value into --opt value)
NORM_ARGS=()
vs_normalize_args() {
  NORM_ARGS=()
  local a
  for a in "$@"; do
    if [[ "$a" == --*=* ]]; then NORM_ARGS+=("${a%%=*}" "${a#*=}"); else NORM_ARGS+=("$a"); fi
  done
}

# vs_need "$@" — inside an option case: fail when the option has no value.
vs_need() { if (($# < 2)); then die "$EX_USAGE" "option $1 requires a value"; fi; }

vs_is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }
# host[:port] where host is a DNS name, an IPv4 address or a bracketed IPv6 literal (used inside [[ =~ ]], left unquoted)
VS_HOSTPORT_RE='([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?'
vs_is_https_hostport() { [[ "${1:-}" =~ ^https://$VS_HOSTPORT_RE$ ]]; }
vs_valid_port() { [[ "${1:-}" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
vs_valid_name() { [[ "${1:-}" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$ ]]; }

# vs_version_ge <have> <need> — true when have >= need (dotted versions, leading v ignored)
vs_version_ge() {
  local have=${1#v} need=${2#v}
  [[ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n 1)" == "$need" ]]
}

vs_sha256() {
  if vs_have sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif vs_have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  else openssl dgst -sha256 -r "$1" | cut -d' ' -f1
  fi
}

vs_file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
vs_file_size() { stat -L -c '%s' "$1" 2>/dev/null || stat -L -f '%z' "$1"; }

# vs_mode_looser <actual> <expected> — true when actual grants any permission bit that expected does not.
vs_mode_looser() {
  local a=$((8#$1)) e=$((8#$2))
  (((a & ~e) != 0))
}

# vs_atomic_write <dest> <mode> — reads stdin, writes DEST via a same-directory temp file, never leaves partial content.
vs_atomic_write() {
  local dest=$1 mode=$2 tmp
  tmp="$dest.new.$$"
  (umask 077; cat >"$tmp")
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dest"
}

# vs_read_secret <file> — prints the content with trailing newlines removed; fails when missing/empty.
vs_read_secret() {
  local f=$1 v
  [[ -f "$f" && -r "$f" ]] || { log_err "secret file not readable: $f"; return 1; }
  v="$(<"$f")"
  [[ -n "$v" ]] || { log_err "secret file is empty: $f"; return 1; }
  printf '%s' "$v"
}

# vs_rand_int <max> — uniform-enough integer in [0,max) from the OS CSPRNG.
vs_rand_int() { local n; n=$((16#$(openssl rand -hex 6))); printf '%d' $((n % $1)); }

# vs_gen_token <hex-bytes> — random hex token (default 32 bytes = 64 hex chars).
vs_gen_token() { openssl rand -hex "${1:-32}"; }

# vs_gen_password <length> — upper+lower+digit+symbol (symbols limited to .*+- accepted by OpenSearch and Vendetta/Wazuh API).
vs_gen_password() {
  local len=${1:-32} core pw sym='.*+-' i pos
  while :; do
    core="$(openssl rand -base64 $((len * 3)) | tr -d '\n=+/' | cut -c1-"$len")"
    [[ ${#core} -eq $len && "$core" =~ [A-Z] && "$core" =~ [a-z] && "$core" =~ [0-9] ]] && break
  done
  pw=$core
  for i in 1 2 3; do
    pos=$(vs_rand_int $((len - 2)))
    pos=$((pos + 1))
    pw="${pw:0:pos}${sym:$(vs_rand_int ${#sym}):1}${pw:pos+1}"
  done
  # a replaced char may have been the only upper/lower/digit — re-check, regenerate on the (rare) miss
  if [[ "$pw" =~ [A-Z] && "$pw" =~ [a-z] && "$pw" =~ [0-9] && "$pw" =~ [.*+-] ]]; then printf '%s' "$pw"; else vs_gen_password "$len"; fi
}

# vs_password_strong <pw> — ≥16 chars with upper/lower/digit/special.
vs_password_strong() {
  local p=$1
  ((${#p} >= 16)) && [[ "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] && "$p" =~ [^A-Za-z0-9] ]]
}

# ---------------------------------------------------------------------------------------------------
# Retry with exponential backoff (no sleeping when VS_NO_SLEEP=1, used by the test-suite)
# ---------------------------------------------------------------------------------------------------
vs_sleep() { if [[ "${VS_NO_SLEEP:-0}" == "1" ]]; then return 0; fi; sleep "$1"; }

# retry <attempts> <initial-delay-seconds> <command...>
retry() {
  local attempts=$1 delay=$2 n=1
  shift 2
  until "$@"; do
    if ((n >= attempts)); then return 1; fi
    log_warn "attempt $n/$attempts failed: $1 … retrying in ${delay}s"
    vs_sleep "$delay"
    delay=$((delay * 2))
    if ((delay > 60)); then delay=60; fi
    n=$((n + 1))
  done
}

# ---------------------------------------------------------------------------------------------------
# HTTP — secrets travel through a curl config on stdin, never argv or the environment.
# ---------------------------------------------------------------------------------------------------
VS_HTTP_CODE=""
VS_HTTP_BODY=""

# vs_curl_quote <string> — quote for a curl config file value.
vs_curl_quote() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '"%s"' "$s"
}

# vs_http <METHOD> <url> [--ca F] [--cert F --key F] [--bearer-file F] [--basic USER:PASSFILE]
#                        [--data STR | --data-file F] [--header 'K: V']... [--resolve HOST:PORT:ADDR]...
#                        [--max-time N] [--ok CSV]
# Sets VS_HTTP_CODE and VS_HTTP_BODY. Returns 0 when the status is 2xx (or in --ok), 22 for other statuses,
# curl's exit code on transport errors. TLS verification is always on; only --ca selects the trust anchor.
vs_http() {
  local method=$1 url=$2 ca="" cert="" key="" bearer="" basic="" data="" datafile="" maxt=20 ok="" cfg out rc=0 tok pw u attempt base_cfg
  local headers=() resolves=()
  shift 2
  while (($#)); do
    case "$1" in
      --ca) ca=$2; shift 2 ;;
      --cert) cert=$2; shift 2 ;;
      --key) key=$2; shift 2 ;;
      --bearer-file) bearer=$2; shift 2 ;;
      --basic) basic=$2; shift 2 ;;
      --data) data=$2; shift 2 ;;
      --data-file) datafile=$2; shift 2 ;;
      --header) headers+=("$2"); shift 2 ;;
      --resolve) resolves+=("$2"); shift 2 ;;
      --max-time) maxt=$2; shift 2 ;;
      --ok) ok=$2; shift 2 ;;
      *) log_err "vs_http: unknown option $1"; return 64 ;;
    esac
  done
  cfg="url = $(vs_curl_quote "$url")"$'\n'
  cfg+="request = $(vs_curl_quote "$method")"$'\n'
  cfg+=$'silent\nshow-error\n'
  cfg+="max-time = $maxt"$'\n'
  cfg+="connect-timeout = 10"$'\n'
  cfg+="write-out = $(vs_curl_quote $'\n%{http_code}')"$'\n'
  [[ -z "$ca" ]] || cfg+="cacert = $(vs_curl_quote "$ca")"$'\n'
  [[ -z "$cert" ]] || cfg+="cert = $(vs_curl_quote "$cert")"$'\n'
  [[ -z "$key" ]] || cfg+="key = $(vs_curl_quote "$key")"$'\n'
  if [[ -n "$bearer" ]]; then
    tok="$(vs_read_secret "$bearer")" || return 65
    cfg+="header = $(vs_curl_quote "Authorization: Bearer $tok")"$'\n'
  fi
  if [[ -n "$basic" ]]; then
    u=${basic%%:*}; pw="$(vs_read_secret "${basic#*:}")" || return 65
    cfg+="user = $(vs_curl_quote "$u:$pw")"$'\n'
  fi
  local h
  for h in "${headers[@]}"; do cfg+="header = $(vs_curl_quote "$h")"$'\n'; done
  for h in "${resolves[@]}"; do cfg+="resolve = $(vs_curl_quote "$h")"$'\n'; done
  [[ -z "$data" ]] || { cfg+="data-binary = $(vs_curl_quote "$data")"$'\n'; cfg+="header = \"Content-Type: application/json\""$'\n'; }
  [[ -z "$datafile" ]] || { cfg+="data-binary = $(vs_curl_quote "@$datafile")"$'\n'; cfg+="header = \"Content-Type: application/json\""$'\n'; }
  # curl on macOS uses SecureTransport, which cannot do TLS 1.3 client auth with an EC certificate
  # ("tlsv1 alert decode error", exit 35): retry such handshakes once capped at TLS 1.2.
  base_cfg=$cfg
  for attempt in 1 2; do
    cfg=$base_cfg
    if ((attempt == 2)); then cfg+=$'tls-max = 1.2\n'; fi
    rc=0
    out="$(printf '%s' "$cfg" | curl -K - 2>&1)" || rc=$?
    if ((rc != 35)) || [[ -z "$cert" ]] || ((attempt == 2)); then break; fi
  done
  if ((rc != 0)); then
    VS_HTTP_CODE=000
    VS_HTTP_BODY=$out
    return "$rc"
  fi
  VS_HTTP_CODE=${out##*$'\n'}
  VS_HTTP_BODY=${out%$'\n'*}
  if [[ -n "$ok" ]]; then
    [[ ",$ok," == *",$VS_HTTP_CODE,"* ]] && return 0
    return 22
  fi
  [[ "$VS_HTTP_CODE" =~ ^2[0-9][0-9]$ ]] && return 0
  return 22
}

# ---------------------------------------------------------------------------------------------------
# .env access (parsed, never sourced — .env may be operator-edited)
# ---------------------------------------------------------------------------------------------------
# vs_env_file_get <file> <KEY> — last KEY=value line, quotes stripped; empty when absent.
vs_env_file_get() {
  local file=$1 key=$2 line val=""
  [[ -f "$file" ]] || { printf ''; return 0; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?"$key"[[:space:]]*=(.*)$ ]] || continue
    val=${BASH_REMATCH[2]}
  done <"$file"
  val="${val#"${val%%[![:space:]]*}"}"
  if [[ "$val" == \"*\" && ${#val} -ge 2 ]]; then val=${val:1:${#val}-2}
  elif [[ "$val" == \'*\' && ${#val} -ge 2 ]]; then val=${val:1:${#val}-2}
  else val=${val%%[[:space:]]#*}; val="${val%"${val##*[![:space:]]}"}"
  fi
  printf '%s' "$val"
}

# vs_cfg <KEY> [default] — environment first, then $ENV_FILE, then the default.
vs_cfg() {
  local key=$1 def=${2:-} v
  v="${!key:-}"
  if [[ -z "$v" ]]; then v="$(vs_env_file_get "$ENV_FILE" "$key")"; fi
  printf '%s' "${v:-$def}"
}

# ---------------------------------------------------------------------------------------------------
# FailClosed (CONTRACT §2): CS3_PROFILE onprem/airgap + any cloud-LLM credential ⇒ refuse.
# ---------------------------------------------------------------------------------------------------
readonly VS_CLOUD_LLM_KEYS=(GEMINI_API_KEY DEEPSEEK_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY LLM_API_KEY)

# vs_failclosed_check — prints "FailClosedError: …" (variable NAMES only, never values) and returns EX_POLICY on violation.
vs_failclosed_check() {
  local profile k v offenders=() gw_host base_host
  profile="$(vs_cfg CS3_PROFILE "")"
  case "$profile" in onprem|airgap) ;; *) return 0 ;; esac
  gw_host="$(vs_url_host "$(vs_cfg LLM_GATEWAY_URL https://llm-gateway:9101)")"
  for k in "${VS_CLOUD_LLM_KEYS[@]}"; do
    v="$(vs_cfg "$k" "")$(vs_cfg "${k}_FILE" "")"
    [[ -n "$v" ]] || continue
    if [[ "$k" == LLM_API_KEY ]]; then
      base_host="$(vs_url_host "$(vs_cfg LLM_API_BASE "")")"
      # an LLM_API_KEY that authenticates against the local gateway is the sanctioned Errow→gateway credential
      if [[ -n "$base_host" && ( "$base_host" == "$gw_host" || "$base_host" == localhost || "$base_host" == 127.0.0.1 ) ]]; then continue; fi
    fi
    offenders+=("$k")
  done
  if ((${#offenders[@]})); then
    printf 'FailClosedError: CS3_PROFILE=%s forbids cloud LLM credentials; unset: %s\n' "$profile" "$(vs_join " " "${offenders[@]}")" >&2
    return "$EX_POLICY"
  fi
  return 0
}

# vs_url_host <url> — host part (no scheme/port/path).
vs_url_host() {
  local u=${1#*://}
  u=${u%%/*}; u=${u##*@}
  if [[ "$u" == \[* ]]; then u=${u%%]*}; u=${u#[}; else u=${u%%:*}; fi
  printf '%s' "$u"
}

# ---------------------------------------------------------------------------------------------------
# docker / compose
# ---------------------------------------------------------------------------------------------------
COMPOSE=()

# vs_compose_init [--no-files] — fills COMPOSE with a Compose v2 command line. Returns 1 when v2 is unavailable.
vs_compose_init() {
  local base=() ver f
  if vs_have docker && ver="$(docker compose version --short 2>/dev/null)" && [[ "$ver" =~ ^v?[2-9] ]]; then
    base=(docker compose)
  elif vs_have docker-compose && ver="$(docker-compose version --short 2>/dev/null)" && [[ "$ver" =~ ^v?[2-9] ]]; then
    base=(docker-compose)
  else
    COMPOSE=()
    return 1
  fi
  COMPOSE=("${base[@]}" -p "$COMPOSE_PROJECT" --project-directory "$STACK_DIR")
  for f in "${COMPOSE_FILE_LIST[@]:-$STACK_DIR/docker-compose.yml}"; do
    if [[ -f "$f" ]]; then COMPOSE+=(-f "$f"); fi
  done
  if [[ -f "$ENV_FILE" ]]; then COMPOSE+=(--env-file "$ENV_FILE"); fi
  return 0
}

# vs_compose_running_services — one running service name per line (needs COMPOSE set).
vs_compose_running_services() { "${COMPOSE[@]}" ps --services --status running 2>/dev/null; }

# vs_image_pinned <image-ref> — true for name:tag@sha256:<64 hex>
vs_image_pinned() { [[ "${1:-}" =~ ^[A-Za-z0-9._/:-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$ ]]; }
