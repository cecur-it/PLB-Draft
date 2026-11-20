# shellcheck shell=bash
# shellcheck disable=SC2034
# lib.sh - helpers shared by errow-to-vendetta.sh and vendetta-to-errow.sh (SC2034: result variables are read by the sourcing scripts).
# Traces: CONTRACT §0 (shell rules), §2 (secret files, ports), §6 (feedback loop, G9 offensive safety).
# Sourced, never executed. The caller sets FL_TAG (log prefix) before sourcing.

FL_TAG=${FL_TAG:-feedback-loop}
FEEDBACK_DIR=${FEEDBACK_DIR:-/var/log/feedback-loop}
FEEDBACK_LOG=${FEEDBACK_LOG:-${FEEDBACK_DIR}/feedback.log}
FEEDBACK_QUEUE_FILE=${FEEDBACK_QUEUE_FILE:-${FEEDBACK_DIR}/retest-queue.ndjson}
FEEDBACK_STATE_DIR=${FEEDBACK_STATE_DIR:-${FEEDBACK_DIR}/state}
FEEDBACK_SOAR_DIR=${FEEDBACK_SOAR_DIR:-${FEEDBACK_DIR}/soar}
FL_HTTP_TIMEOUT=${FL_HTTP_TIMEOUT:-30}
FL_CA_FILE=${FL_CA_FILE:-/pki/ca.crt}

if [[ -t 2 ]]; then
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_CYN=$'\033[36m'; C_OFF=$'\033[0m'
else
  C_RED=''; C_YEL=''; C_GRN=''; C_CYN=''; C_OFF=''
fi

log_info() { printf '%s[%s]%s %s\n' "$C_CYN" "$FL_TAG" "$C_OFF" "$*" >&2; }
log_ok()   { printf '%s[%s]%s %s\n' "$C_GRN" "$FL_TAG" "$C_OFF" "$*" >&2; }
log_warn() { printf '%s[%s] WARN:%s %s\n' "$C_YEL" "$FL_TAG" "$C_OFF" "$*" >&2; }
log_err()  { printf '%s[%s] ERROR:%s %s\n' "$C_RED" "$FL_TAG" "$C_OFF" "$*" >&2; }

fl_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# emit prints a plain (uncoloured, greppable) action line and appends it to feedback.log.
emit() {
  local line="[${FL_TAG}] $*"
  printf '%s\n' "$line"
  if [[ -n ${FL_LOG_READY-} ]]; then
    printf '%s %s\n' "$(fl_now)" "$line" >>"$FEEDBACK_LOG" 2>/dev/null || true
  fi
}

# fl_prepare_log creates the log directory once; a read-only filesystem only disables file logging.
fl_prepare_log() {
  local d
  d=$(dirname -- "$FEEDBACK_LOG")
  if mkdir -p -- "$d" 2>/dev/null && : >>"$FEEDBACK_LOG" 2>/dev/null; then
    FL_LOG_READY=1
  else
    log_warn "cannot write ${FEEDBACK_LOG}; actions are only printed to stdout"
  fi
}

require_cmds() {
  local c missing=()
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if ((${#missing[@]})); then
    log_err "missing required command(s): ${missing[*]}"
    return 1
  fi
}

# read_secret <file> prints the first line of a secret file without trailing whitespace.
read_secret() {
  local p=$1 v
  if [[ ! -r $p ]]; then
    log_err "secret file not readable: ${p}"
    return 1
  fi
  v=$(tr -d '\r' <"$p")
  v=${v%%$'\n'*}
  if [[ -z $v ]]; then
    log_err "secret file is empty: ${p}"
    return 1
  fi
  printf '%s' "$v"
}

# Backslash/quote escaping for values placed inside a curl --config file (keeps secrets out of argv).
cfg_escape() {
  local s=${1//\\/\\\\}
  printf '%s' "${s//\"/\\\"}"
}

FL_CURL_EXTRA=()

# --- LLM gateway client (/triage, /forensic, /mcp/tool_call) ---------------------------------------------------------------
LLM_GATEWAY_URL=${LLM_GATEWAY_URL:-https://llm-gateway:9101}
LLM_GATEWAY_TOKEN_FILE=${LLM_GATEWAY_TOKEN_FILE:-/run/secrets/llm_gateway_token}
CLIENT_CERT=${ERROW_FEEDBACK_CLIENT_CERT:-/pki/errow-feedback.crt}
CLIENT_KEY=${ERROW_FEEDBACK_CLIENT_KEY:-/pki/errow-feedback.key}
gw_token=''

gw_auth() {
  if [[ -z $gw_token ]]; then
    gw_token=$(read_secret "$LLM_GATEWAY_TOKEN_FILE") || return 1
  fi
}

gw_call() { # gw_call <path> <json>
  gw_auth || return 1
  FL_CURL_EXTRA=()
  if [[ -r $CLIENT_CERT && -r $CLIENT_KEY ]]; then
    FL_CURL_EXTRA=(--cert "$CLIENT_CERT" --key "$CLIENT_KEY")
  fi
  fl_http bearer "$gw_token" POST "${LLM_GATEWAY_URL%/}${1}" "$2"
  FL_CURL_EXTRA=()
}

# fl_http <none|bearer|basic> <secret> <METHOD> <url> [json-body]
# Sets HTTP_CODE ("000" on transport failure) and HTTP_BODY; always returns 0 so callers branch on HTTP_CODE.
fl_http() {
  local kind=$1 secret=$2 method=$3 url=$4 body=${5-}
  local -a base=(--silent --show-error --connect-timeout 5 --max-time "$FL_HTTP_TIMEOUT"
    -H 'Content-Type: application/json' -H 'Accept: application/json' -X "$method")
  local -a data=()
  local out='' rc=0
  local ca=$FL_CA_FILE
  if [[ -n ${VENDETTA_API_URL:-} && $url == "${VENDETTA_API_URL%/}"* ]]; then ca=$VENDETTA_API_CA_FILE; fi
  [[ -r $ca ]] && base+=(--cacert "$ca")
  [[ -n $body ]] && data=(--data-binary @-)
  case $kind in
    bearer)
      out=$(printf '%s' "$body" | curl "${base[@]}" "${FL_CURL_EXTRA[@]}" "${data[@]}" \
        -K <(printf 'header = "Authorization: Bearer %s"\n' "$(cfg_escape "$secret")") \
        -w $'\n%{http_code}' "$url") || rc=$?
      ;;
    basic)
      out=$(printf '%s' "$body" | curl "${base[@]}" "${FL_CURL_EXTRA[@]}" "${data[@]}" \
        -K <(printf 'user = "%s"\n' "$(cfg_escape "$secret")") \
        -w $'\n%{http_code}' "$url") || rc=$?
      ;;
    none)
      out=$(printf '%s' "$body" | curl "${base[@]}" "${FL_CURL_EXTRA[@]}" "${data[@]}" \
        -w $'\n%{http_code}' "$url") || rc=$?
      ;;
    *)
      log_err "fl_http: unknown auth kind ${kind}"
      return 2
      ;;
  esac
  if ((rc != 0)); then
    HTTP_CODE=000
    HTTP_BODY="curl exit ${rc}"
    return 0
  fi
  HTTP_CODE=${out##*$'\n'}
  HTTP_BODY=${out%$'\n'*}
  return 0
}

http_ok() { [[ ${HTTP_CODE:-000} =~ ^2[0-9][0-9]$ ]]; }

# Vendetta manager API (Wazuh-compatible): JWT from POST /security/user/authenticate with the password file.
VENDETTA_API_URL=${VENDETTA_API_URL:-https://vendetta-manager:55000}
VENDETTA_API_USER=${VENDETTA_API_USER:-wazuh-wui}
VENDETTA_API_PASSWORD_FILE=${VENDETTA_API_PASSWORD_FILE:-/run/secrets/vendetta_api_password}
# The manager is verified against its own pinned bundle (scripts/pin-manager-cert.sh), never the system store; FL_CA_FILE
# stays the trust anchor for the LLM gateway.
VENDETTA_API_CA_FILE=${VENDETTA_API_CA_FILE:-$FL_CA_FILE}

vendetta_jwt() {
  local pw token
  if [[ $VENDETTA_API_URL == https://* && ! -r $VENDETTA_API_CA_FILE ]]; then
    log_err "manager CA unreadable: ${VENDETTA_API_CA_FILE} — pin it with scripts/pin-manager-cert.sh"
    return 1
  fi
  pw=$(read_secret "$VENDETTA_API_PASSWORD_FILE") || return 1
  fl_http basic "${VENDETTA_API_USER}:${pw}" POST "${VENDETTA_API_URL%/}/security/user/authenticate?raw=true"
  if ! http_ok; then
    log_err "Vendetta API authentication failed (HTTP ${HTTP_CODE})"
    return 1
  fi
  token=$HTTP_BODY
  if [[ $token == \{* ]]; then
    token=$(jq -r '.data.token // empty' <<<"$token")
  fi
  if [[ -z $token || $token == *[[:space:]]* ]]; then
    log_err "Vendetta API returned no usable JWT"
    return 1
  fi
  printf '%s' "$token"
}

# lock_queue takes an exclusive advisory lock on the retest queue (<queue>.lock); the lock lives until
# unlock_queue or process exit. Without flock(1) it degrades with a warning.
lock_queue() {
  if ! command -v flock >/dev/null 2>&1; then
    log_warn "flock not available; continuing without queue locking"
    return 0
  fi
  mkdir -p -- "$(dirname -- "$FEEDBACK_QUEUE_FILE")"
  exec {FL_LOCK_FD}>>"${FEEDBACK_QUEUE_FILE}.lock"
  flock -w 30 "$FL_LOCK_FD"
}

unlock_queue() {
  if [[ -n ${FL_LOCK_FD-} ]]; then
    exec {FL_LOCK_FD}>&-
    FL_LOCK_FD=''
  fi
}

sev_rank() {
  case ${1,,} in
    critical) echo 4 ;;
    high) echo 3 ;;
    medium) echo 2 ;;
    low) echo 1 ;;
    *) echo 0 ;;
  esac
}

# host_allowed <host> <comma-separated allow-list>; entries may be exact names or "*.suffix".
host_allowed() {
  local host=${1,,} list=$2 entry
  local -a entries
  IFS=',' read -r -a entries <<<"$list"
  for entry in "${entries[@]}"; do
    entry=${entry//[[:space:]]/}
    entry=${entry,,}
    [[ -z $entry ]] && continue
    if [[ $entry == \*.* ]]; then
      [[ $host == *"${entry#\*}" ]] && return 0
    elif [[ $host == "$entry" ]]; then
      return 0
    fi
  done
  return 1
}

valid_hostname() {
  [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]
}

# --- advisory forensic proposals (PROMPT §2.5, CONTRACT §4.4 /forensic) ---------------------------------------------------
# The LLM only PROPOSES: results are appended to proposals.ndjson (status pending_analyst_review, applied false). Nothing here
# writes to Vendetta rule directories or calls an apply API, and a gateway failure never changes the primary actions.
FL_LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# fl_jq runs jq with the forensic.jq module path set (include "forensic";).
fl_jq() { jq -L "$FL_LIB_DIR" "$@"; }
FORENSIC=${ERROW_FEEDBACK_FORENSIC:-true}
FORENSIC_MIN_SEVERITY=${ERROW_FEEDBACK_FORENSIC_MIN_SEVERITY:-high}
FORENSIC_TIMEOUT=${ERROW_FEEDBACK_FORENSIC_TIMEOUT:-60}
FORENSIC_BUDGET=${ERROW_FEEDBACK_FORENSIC_BUDGET:-80}
PROPOSALS_FILE=${FEEDBACK_PROPOSALS_FILE:-${FEEDBACK_DIR}/proposals.ndjson}
FORENSIC_SPENT=0
FORENSIC_REASON=''
FORENSIC_RESULT=''
PROPOSALS_WRITTEN=0

# fl_forensic_config normalises ERROW_FEEDBACK_FORENSIC to true|false and validates the numeric knobs (exit status 2 = bad value).
fl_forensic_config() {
  case ${FORENSIC,,} in
    true | 1 | yes | on) FORENSIC=true ;;
    false | 0 | no | off) FORENSIC=false ;;
    *)
      log_err "ERROW_FEEDBACK_FORENSIC must be true or false (got '${FORENSIC}')"
      return 2
      ;;
  esac
  if [[ ! $FORENSIC_TIMEOUT =~ ^[1-9][0-9]{0,3}$ || ! $FORENSIC_BUDGET =~ ^[0-9]{1,5}$ ]]; then
    log_err "ERROW_FEEDBACK_FORENSIC_TIMEOUT (1..9999 s) and ERROW_FEEDBACK_FORENSIC_BUDGET (0..99999 s) must be integers"
    return 2
  fi
  if (($(sev_rank "$FORENSIC_MIN_SEVERITY") == 0)); then
    log_err "invalid ERROW_FEEDBACK_FORENSIC_MIN_SEVERITY: ${FORENSIC_MIN_SEVERITY}"
    return 2
  fi
}

# fl_forensic <request-json>: POST ${LLM_GATEWAY_URL}/forensic. On success FORENSIC_RESULT holds results[0]; otherwise the status
# is 1 and FORENSIC_REASON says why (token, network, timeout, HTTP 4xx/5xx, malformed answer, exhausted time budget).
fl_forensic() {
  local body=$1 remain timeout start reason='' err=''
  FORENSIC_RESULT=''
  FORENSIC_REASON=''
  remain=$((FORENSIC_BUDGET - FORENSIC_SPENT))
  if ((remain < 3)); then
    FORENSIC_REASON="time budget of ${FORENSIC_BUDGET}s exhausted"
    return 1
  fi
  timeout=$FORENSIC_TIMEOUT
  if ((timeout > remain)); then
    timeout=$remain
  fi
  if ! gw_auth 2>/dev/null; then
    FORENSIC_REASON="gateway token unreadable (${LLM_GATEWAY_TOKEN_FILE})"
    return 1
  fi
  start=$SECONDS
  FL_HTTP_TIMEOUT=$timeout gw_call /forensic "$body"
  FORENSIC_SPENT=$((FORENSIC_SPENT + SECONDS - start))
  if ! http_ok; then
    err=$(jq -r '.error // empty | tostring' <<<"${HTTP_BODY-}" 2>/dev/null | head -n1 | tr -c 'A-Za-z0-9_' ' ' | cut -c1-40 || true)
    err=${err%% }
    case ${HTTP_CODE:-000} in
      000)
        if [[ ${HTTP_BODY-} == 'curl exit 28' ]]; then
          reason="timeout after ${timeout}s"
        else
          reason="gateway unreachable (${HTTP_BODY-})"
        fi
        ;;
      401 | 403) reason="gateway rejected the bearer token (HTTP ${HTTP_CODE})" ;;
      4??) reason="gateway rejected the request (HTTP ${HTTP_CODE}${err:+ ${err}})" ;;
      5??) reason="gateway error (HTTP ${HTTP_CODE}${err:+ ${err}})" ;;
      *) reason="unexpected gateway response (HTTP ${HTTP_CODE})" ;;
    esac
    FORENSIC_REASON=$reason
    return 1
  fi
  FORENSIC_RESULT=$(jq -c 'select(((.results // [])[0].analysis // null) | type == "object") | .results[0]' <<<"${HTTP_BODY-}" 2>/dev/null || true)
  if [[ -z $FORENSIC_RESULT ]]; then
    FORENSIC_REASON="gateway returned no analysis (malformed response)"
    return 1
  fi
}

# fl_append_unique <file> <key> <line>: append under an advisory lock unless <key> is already present. 0 appended, 10 duplicate, 1 error.
fl_append_unique() {
  local file=$1 key=$2 line=$3
  mkdir -p -- "$(dirname -- "$file")" 2>/dev/null || return 1
  (
    if command -v flock >/dev/null 2>&1; then
      flock -w 30 9 || exit 1
    fi
    if [[ -f $file ]] && grep -Fq -- "$key" "$file"; then
      exit 10
    fi
    printf '%s\n' "$line" >>"$file"
  ) 9>>"${file}.lock" 2>/dev/null
}

# fl_proposal_add <kind> <subject> <fingerprint|-> <content> [extra-json-object]   (uses FORENSIC_RESULT from the last fl_forensic)
# The record always carries status=pending_analyst_review and applied=false; <extra> can add fields but never override those.
fl_proposal_add() {
  local kind=$1 subject=$2 fp=$3 content=$4 extra=${5:-'{}'} pid rec rc=0
  [[ $fp == - ]] && fp=''
  pid=$(printf '%s|%s|%s' "$kind" "$subject" "$content" | sha256sum | cut -c1-16)
  rec=$(jq -cn --arg pid "$pid" --arg now "$(fl_now)" --arg kind "$kind" --arg subject "$subject" --arg fp "$fp" \
    --arg origin "$FL_TAG" --arg content "$content" --argjson res "$FORENSIC_RESULT" --argjson extra "$extra" '
    $extra + {
      proposal_id: $pid, created_at: $now, kind: $kind, status: "pending_analyst_review", applied: false,
      subject: $subject, fingerprint: (if $fp == "" then null else $fp end), origin: $origin,
      request_id: ($res.request_id // ""), model: ($res.meta.model // ""), engine: ($res.analysis.engineUsed // ""),
      fallback: ($res.meta.fallback // false), content: $content}
    + (if $kind == "detection_rule"
       then {format: ($content | if test("^\\s*<") then "wazuh_xml" elif test("(?m)^\\s*detection\\s*:") then "sigma" else "text" end)}
       else {} end)') || {
    emit "PROPOSAL: FAILED to build ${kind} for ${subject}"
    return 0
  }
  fl_append_unique "$PROPOSALS_FILE" "\"proposal_id\":\"${pid}\"" "$rec" || rc=$?
  case $rc in
    0)
      PROPOSALS_WRITTEN=$((PROPOSALS_WRITTEN + 1))
      emit "PROPOSAL: ${kind} for ${subject} (pending analyst review, not applied)"
      ;;
    10) emit "PROPOSAL: ${kind} for ${subject} already recorded (pending analyst review, not applied)" ;;
    *) emit "PROPOSAL: FAILED to persist ${kind} for ${subject} (cannot write ${PROPOSALS_FILE})" ;;
  esac
  return 0
}
