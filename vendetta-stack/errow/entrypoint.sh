#!/usr/bin/env bash
# errow-entrypoint - container entrypoint of the Errow orchestrator image (service `errow`, `errow-viewer`).
# Traces: CONTRACT §0 (shell rules), §2 (ports/paths/secrets/env knobs), §4.4 (gateway as the only LLM egress),
#         §8 (Errow addenda: one-shot CLI, viewer pinned to 8765, DinD via DOCKER_HOST), §11 (RUNTIME.md), §12 (idempotent).
# Responsibilities:
#   * read secrets from FILES only (LLM_GATEWAY_TOKEN_FILE) and export them to the Errow process, never to argv or disk;
#   * point Errow at the sovereign gateway: LLM_API_BASE=<gateway>/v1, errow_LLM=openai/<model>, LLM_DISABLE_STREAMING=true;
#   * fail closed (exit 78, FailClosedError) when a cloud LLM credential or non-gateway endpoint is present outside profile `cloud`;
#   * telemetry / update-check / cloud sync are OFF unless explicitly opted in (ERROW_TELEMETRY, ERROW_CLOUD_ENABLED);
#   * apply /etc/errow/errow-config.yaml defaults (environment wins) and enforce the llm-providers.yaml model allow-list;
#   * wait for the DinD sidecar (DOCKER_HOST) and make sure the sandbox image is there (docker load for air-gap);
#   * run Errow in one of three modes (scan | view | idle) and tee its output to /var/log/errow/cli.log (shipped as `runtime_events`).
# Exit codes: 0 ok | 64 usage | 66 missing/unreadable input file | 69 service unavailable (DinD, sandbox image)
#             | 73 cannot create state dir | 77 target not allowed | 78 configuration / FailClosedError | else: Errow's own code.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

PROG=errow-entrypoint
VERSION=1.0.0
SELF_DIR=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)

usage() {
  cat <<'EOF'
Usage:
  errow-entrypoint [--mode scan|view|idle] [--dry-run] [--] [errow arguments...]
  errow-entrypoint --healthcheck [--mode MODE]
  errow-entrypoint --print-viewer-link
  errow-entrypoint --help | --version

Modes (precedence: --mode flag > any errow arguments imply `scan` > $ERROW_MODE > idle):
  scan   run one Errow CLI invocation: `errow [--non-interactive] --target T --scan-mode M [--instruction-file F] ...`.
         Missing flags are filled from ERROW_TARGET, ERROW_SCAN_MODE (default quick), ERROW_INSTRUCTION_FILE, ERROW_FAIL_ON.
         Errow subcommands (view, auth, cloud, completion) are passed through unchanged.
  view   serve the latest run's viewer on ERROW_VIEWER_HOST:ERROW_VIEWER_PORT (0.0.0.0:8765). Waits for the first run,
         redacts the per-process ?token= from logs (full link: --print-viewer-link) and re-serves the newest run
         when ERROW_VIEWER_FOLLOW=true.
  idle   prepare the environment and wait; start scans with `docker exec <errow> errow-entrypoint --mode scan -- ...`.

Options:
  --dry-run            resolve and print the configuration and the command (no secrets) and exit; no daemon is contacted.
  --healthcheck        exit 0 when healthy (view: viewer state/port; others: DinD ping + gateway TCP + fail-closed recheck).
  --print-viewer-link  print the authorised viewer link saved by `view` mode (treat it like a password).
  Use `--` to pass errow's own `--help`: errow-entrypoint -- --help

Environment (defaults in brackets):
  CS3_PROFILE [onprem] cloud|onprem|airgap|edge     CS3_MODEL_TRIAGE [nemotron-3-nano:30b]
  CS3_MODEL_ERROW_SECURITY [nemotron-3-nano:30b]  default errow_LLM (openai/<id>); unapproved ⇒ primary + degraded warning
  CS3_MODEL_REASONING [gemma4:26b]           second tier behind the security model (gateway side, not Errow)
  (OLLAMA_PRIMARY_MODEL / OLLAMA_FALLBACK_MODEL / OLLAMA_SECURITY_MODEL remain as deprecated aliases)
  CS3_ROUTER_URL [https://llm-gateway:9101]          LLM_GATEWAY_URL is the deprecated alias
  LLM_GATEWAY_TOKEN_FILE [/run/secrets/llm_gateway_token]   CS3_ROUTER_KEY = inline token when the file is absent
  ERROW_LLM_ROUTE [gateway] (direct: profile cloud only; key from LLM_API_KEY_FILE, model from errow_LLM)
  ERROW_TENANT_ID / ERROW_INCIDENT_ID  sent to the gateway as X-Tenant-Id / X-Incident-Id (via LLM_EXTRA_HEADERS)
  CS3_APPROVAL_TOKEN[_FILE]  human-approval token sent as X-CS3-Approval (the gateway refuses mutating tool calls without one)
  ERROW_TELEMETRY [false]   ERROW_CLOUD_ENABLED [false]   ERROW_CLOUD_URL [https://app.errow.ai]
  DOCKER_HOST [tcp://errow-dind:2376, TLS from /certs/client]   ERROW_DIND_TIMEOUT [120]
  ERROW_SANDBOX_IMAGE [vendetta-stack/errow-sandbox:$STACK_VERSION]   ERROW_SANDBOX_IMAGE_TAR (docker load when image missing)
  ERROW_WORKDIR [/workspace]   ERROW_LOG_DIR [/var/log/errow]   ERROW_PKI_CA [/pki/ca.crt]
  ERROW_ALLOWED_TARGETS  optional comma-separated host globs a scan target must match (exit 77 otherwise)
  ERROW_CONFIG_FILE [/etc/errow/errow-config.yaml]  defaults for the settings above (the environment always wins)
  ERROW_LLM_PROVIDERS_FILE [/etc/errow/llm-providers.yaml]  model allow-list / provider policy (non-cloud profiles fail closed)
EOF
}

C_RED='' C_YEL='' C_GRN='' C_OFF=''
if [[ -t 2 ]]; then C_RED=$'\033[31m' C_YEL=$'\033[33m' C_GRN=$'\033[32m' C_OFF=$'\033[0m'; fi
log_info() { printf '%s[%s]%s %s\n' "$C_GRN" "$PROG" "$C_OFF" "$*" >&2; }
log_warn() { printf '%s[%s] WARN:%s %s\n' "$C_YEL" "$PROG" "$C_OFF" "$*" >&2; }
log_err() { printf '%s[%s] ERROR:%s %s\n' "$C_RED" "$PROG" "$C_OFF" "$*" >&2; }
die() {
  local code=$1
  shift
  log_err "$*"
  exit "$code"
}

is_true() {
  case ${1,,} in 1 | true | yes | on) return 0 ;; *) return 1 ;; esac
}

# read_secret <file> prints the first line of a secret file; callers decide whether absence is fatal.
read_secret() {
  local p=$1 v
  [[ -r $p && -f $p ]] || return 1
  v=$(tr -d '\r' <"$p")
  v=${v%%$'\n'*}
  [[ -n $v ]] || return 1
  printf '%s' "$v"
}

has_arg() {
  local names=$1 a n
  shift
  local IFS='|'
  for a in "$@"; do
    for n in $names; do
      if [[ $a == "$n" || $a == "$n="* ]]; then return 0; fi
    done
  done
  return 1
}

is_subcommand() {
  case $1 in view | auth | cloud | completion) return 0 ;; *) return 1 ;; esac
}

# join_words prints its arguments space-separated (the global IFS would join them with newlines).
join_words() {
  local IFS=' '
  printf '%s' "$*"
}

# ---------------------------------------------------------------- settings --------------------------------------------
MODE_FLAG='' DRY_RUN=false DO_HEALTHCHECK=false DO_PRINT_LINK=false
ERRO_ARGS=()
GATEWAY_TOKEN='' TOKEN_STATE=missing CONFIG_FILE_STATE=''
CMD=()
CHILD_PID='' FILTER_PID='' FIFO='' RUN_RC=0 STOP=0 CLI_LOG_OK=0
CLEANUP_FILES=()

# load_stack_config applies errow-config.yaml as defaults: a non-empty variable already in the environment always wins.
load_stack_config() {
  local file=${ERROW_CONFIG_FILE:-/etc/errow/errow-config.yaml} helper=${ERROW_CONFIG_HELPER:-${SELF_DIR}/stack-config.py}
  local py=${ERROW_PYTHON:-/opt/errow/bin/python} out line name
  CONFIG_FILE_STATE="absent (${file})"
  [[ -r $file ]] || return 0
  [[ -x $py && -r $helper ]] || die 78 "cannot read ${file}: ${py} or ${helper} missing"
  out=$("$py" "$helper" env --file "$file" --profile "$CS3_PROFILE") || die 78 "invalid configuration file ${file}"
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    name=${line%%=*}
    if [[ -z $(printenv "$name" || true) ]]; then export "$name=${line#*=}"; fi
  done <<<"$out"
  CONFIG_FILE_STATE="loaded (${file})"
}

resolve_settings() {
  export HOME=${HOME:-/home/errow}
  CS3_PROFILE=${CS3_PROFILE:-onprem}
  case $CS3_PROFILE in cloud | onprem | airgap | edge) ;; *) die 78 "CS3_PROFILE must be cloud|onprem|airgap|edge (got '${CS3_PROFILE}')" ;; esac
  load_stack_config
  STACK_VERSION=${STACK_VERSION:-1.0.0}
  # CS3_MODEL_* is the stable role contract; the OLLAMA_* names are deprecated aliases kept for older .env files.
  OLLAMA_PRIMARY_MODEL=${CS3_MODEL_TRIAGE:-${OLLAMA_PRIMARY_MODEL:-nemotron-3-nano:30b}}
  OLLAMA_FALLBACK_MODEL=${CS3_MODEL_REASONING:-${OLLAMA_FALLBACK_MODEL:-gemma4:26b}}
  OLLAMA_SECURITY_MODEL=${CS3_MODEL_ERROW_SECURITY:-${CS3_MODEL_SECURITY:-${OLLAMA_SECURITY_MODEL:-nemotron-3-nano:30b}}}
  LLM_GATEWAY_URL=${CS3_ROUTER_URL:-${LLM_GATEWAY_URL:-https://llm-gateway:9101}}
  LLM_GATEWAY_TOKEN_FILE=${LLM_GATEWAY_TOKEN_FILE:-/run/secrets/llm_gateway_token}
  ERROW_LLM_ROUTE=${ERROW_LLM_ROUTE:-gateway}
  ERROW_WORKDIR=${ERROW_WORKDIR:-/workspace}
  ERROW_LOG_DIR=${ERROW_LOG_DIR:-/var/log/errow}
  ERROW_CLI_LOG=${ERROW_CLI_LOG:-${ERROW_LOG_DIR}/cli.log}
  ERROW_STATE_DIR=${ERROW_STATE_DIR:-${HOME}/.errow/entrypoint}
  ERROW_PKI_CA=${ERROW_PKI_CA:-/pki/ca.crt}
  ERROW_CLI=${ERROW_CLI:-errow}
  ERROW_PYTHON=${ERROW_PYTHON:-/opt/errow/bin/python}
  ERROW_DIND_HELPER=${ERROW_DIND_HELPER:-${SELF_DIR}/dind-ready.py}
  ERROW_DIND_TIMEOUT=${ERROW_DIND_TIMEOUT:-120}
  ERROW_VIEWER_HOST=${ERROW_VIEWER_HOST:-0.0.0.0}
  ERROW_VIEWER_PORT=${ERROW_VIEWER_PORT:-8765}
  ERROW_VIEWER_FOLLOW=${ERROW_VIEWER_FOLLOW:-true}
  ERROW_VIEWER_POLL=${ERROW_VIEWER_POLL:-10}
  ERROW_VIEWER_MIN_RESTART=${ERROW_VIEWER_MIN_RESTART:-60}
  ERROW_CLOUD_ENABLED=${ERROW_CLOUD_ENABLED:-false}
  ERROW_CLOUD_URL=${ERROW_CLOUD_URL:-https://app.errow.ai}
  ERROW_TELEMETRY=${ERROW_TELEMETRY:-false}
  VIEWER_LINK_FILE=${ERROW_STATE_DIR}/viewer-link
  [[ $ERROW_VIEWER_PORT =~ ^[0-9]{1,5}$ ]] || die 78 "ERROW_VIEWER_PORT must be a port number"
  [[ $ERROW_VIEWER_POLL =~ ^[0-9]+$ && $ERROW_VIEWER_MIN_RESTART =~ ^[0-9]+$ ]] || die 78 "ERROW_VIEWER_POLL/ERROW_VIEWER_MIN_RESTART must be integers"
  case $ERROW_LLM_ROUTE in gateway | direct) ;; *) die 78 "ERROW_LLM_ROUTE must be gateway|direct" ;; esac
  GATEWAY_API_BASE="${LLM_GATEWAY_URL%/}/v1"
  # The token file wins; CS3_ROUTER_KEY is the inline alternative for hosts without a secret mount.
  if GATEWAY_TOKEN=$(read_secret "$LLM_GATEWAY_TOKEN_FILE"); then TOKEN_STATE=readable
  elif [[ -n ${CS3_ROUTER_KEY-} ]]; then GATEWAY_TOKEN=$CS3_ROUTER_KEY TOKEN_STATE=env
  else GATEWAY_TOKEN='' TOKEN_STATE=missing; fi
  if is_true "$ERROW_CLOUD_ENABLED"; then
    APP_URL=$ERROW_CLOUD_URL
  else
    APP_URL=http://127.0.0.1:9
  fi
  if [[ $CS3_PROFILE == airgap ]] || ! is_true "$ERROW_TELEMETRY"; then
    TELEMETRY=false
    if [[ $CS3_PROFILE == airgap ]] && is_true "$ERROW_TELEMETRY"; then log_warn "ERROW_TELEMETRY ignored: profile airgap never sends telemetry"; fi
  else
    TELEMETRY=true
  fi
  SANDBOX_IMAGE=${errow_IMAGE:-${ERROW_SANDBOX_IMAGE:-vendetta-stack/errow-sandbox:${STACK_VERSION}}}
  DOCKER_HOST_RESOLVED=${DOCKER_HOST:-}
  if [[ -z $DOCKER_HOST_RESOLVED ]]; then
    if [[ -r /certs/client/ca.pem ]]; then DOCKER_HOST_RESOLVED=tcp://errow-dind:2376; else DOCKER_HOST_RESOLVED=tcp://errow-dind:2375; fi
  fi
}

# ------------------------------------------------------------- fail closed --------------------------------------------
CLOUD_KEY_VARS=(
  GEMINI_API_KEY GOOGLE_API_KEY DEEPSEEK_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY AZURE_API_KEY AZURE_OPENAI_API_KEY
  GROQ_API_KEY MISTRAL_API_KEY OPENROUTER_API_KEY COHERE_API_KEY TOGETHERAI_API_KEY XAI_API_KEY PERPLEXITYAI_API_KEY
  PERPLEXITY_API_KEY EXA_API_KEY
  AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_BEARER_TOKEN_BEDROCK GOOGLE_APPLICATION_CREDENTIALS
)

# check_llm_policy enforces the llm-providers.yaml allow-list for the gateway route (the gateway answers 403 for other models anyway;
# failing here gives the operator the reason up front). A missing policy file is not an error: the gateway remains the authority.
# select_llm_model picks errow_LLM for the gateway route: an explicit errow_LLM wins, else the security model, else (unapproved security
# model = stack pulled without the security model) the primary model with ERROW_MODEL_DEGRADED=true so the run is flagged.
select_llm_model() {
  local file=${ERROW_LLM_PROVIDERS_FILE:-/etc/errow/llm-providers.yaml} helper=${ERROW_CONFIG_HELPER:-${SELF_DIR}/stack-config.py}
  local py=${ERROW_PYTHON:-/opt/errow/bin/python} err
  [[ $ERROW_LLM_ROUTE == gateway ]] || return 0
  [[ -n ${errow_LLM-} ]] && return 0
  errow_LLM="openai/${OLLAMA_SECURITY_MODEL}"
  [[ -r $file && -x $py && -r $helper ]] || return 0
  if is_true "${ERROW_MODEL_DEGRADED:-false}"; then
    # Operator already declared the run degraded (e.g. a node without the security model): start on the primary tier.
    errow_LLM="openai/${OLLAMA_PRIMARY_MODEL}"
    log_warn "ERROW_MODEL_DEGRADED=true — running DEGRADED on ${OLLAMA_PRIMARY_MODEL} instead of ${OLLAMA_SECURITY_MODEL}"
    return 0
  fi
  if ! err=$("$py" "$helper" check-llm --file "$file" --profile "$CS3_PROFILE" --model "${errow_LLM#openai/}" 2>&1); then
    errow_LLM="openai/${OLLAMA_PRIMARY_MODEL}"
    ERROW_MODEL_DEGRADED=true
    log_warn "security model ${OLLAMA_SECURITY_MODEL} is not approved by ${file} (${err}) — Errow runs DEGRADED on ${OLLAMA_PRIMARY_MODEL}"
  fi
}

check_llm_policy() {
  local file=${ERROW_LLM_PROVIDERS_FILE:-/etc/errow/llm-providers.yaml} helper=${ERROW_CONFIG_HELPER:-${SELF_DIR}/stack-config.py}
  local py=${ERROW_PYTHON:-/opt/errow/bin/python} model=${errow_LLM:-openai/${OLLAMA_PRIMARY_MODEL}} err
  select_llm_model
  model=${errow_LLM:-$model}
  [[ $ERROW_LLM_ROUTE == gateway && -r $file ]] || return 0
  [[ -x $py && -r $helper ]] || die 78 "cannot enforce ${file}: ${py} or ${helper} missing"
  if ! err=$("$py" "$helper" check-llm --file "$file" --profile "$CS3_PROFILE" --model "${model#openai/}" 2>&1); then
    die 78 "FailClosedError: ${err}"
  fi
  export errow_LLM=$model
}

# fail_closed_check prints only variable NAMES, never values, and exits 78 when a sovereign profile is contaminated.
fail_closed_check() {
  check_llm_policy
  [[ $CS3_PROFILE != cloud ]] || return 0
  local offenders=() name suffix value cfg="${HOME}/.errow/cli-config.json" key
  for name in "${CLOUD_KEY_VARS[@]}"; do
    for suffix in '' _FILE; do
      value=$(printenv "${name}${suffix}" || true)
      if [[ -n $value ]]; then offenders+=("${name}${suffix}"); fi
    done
  done
  if [[ $ERROW_LLM_ROUTE != gateway ]]; then offenders+=("ERROW_LLM_ROUTE=${ERROW_LLM_ROUTE}"); fi
  if [[ -n ${LLM_API_KEY_FILE-} ]]; then offenders+=(LLM_API_KEY_FILE); fi
  if [[ -n ${LLM_API_KEY-} && ${LLM_API_KEY-} != "$GATEWAY_TOKEN" ]]; then offenders+=(LLM_API_KEY); fi
  if [[ -n ${LLM_API_BASE-} && ${LLM_API_BASE%/} != "$GATEWAY_API_BASE" ]]; then offenders+=(LLM_API_BASE); fi
  if [[ -n ${errow_LLM-} && ${errow_LLM-} != openai/* ]]; then offenders+=(errow_LLM); fi
  if [[ $CS3_PROFILE == airgap ]] && is_true "$ERROW_CLOUD_ENABLED"; then offenders+=(ERROW_CLOUD_ENABLED); fi
  if [[ -r $cfg ]] && command -v jq >/dev/null 2>&1; then
    # Errow's TUI persists env values to ~/.errow/cli-config.json (0600, utils/secret_files.py); a stale cloud key must not survive a profile switch.
    while IFS= read -r key; do
      if [[ -n $key ]]; then offenders+=("${key} (in ${cfg})"); fi
    done < <(jq -r --argjson names "$(printf '%s\n' "${CLOUD_KEY_VARS[@]}" | jq -R . | jq -sc .)" \
      '(.env // {}) | keys[] | ascii_upcase | select(. as $k | $names | index($k))' "$cfg" 2>/dev/null || true)
  fi
  if ((${#offenders[@]})); then
    log_err "FailClosedError: profile '${CS3_PROFILE}' forbids cloud LLM credentials or non-gateway endpoints; offending: $(join_words "${offenders[@]}")"
    log_err "Unset them (the only place a cloud key may exist is profile 'cloud' with ERROW_LLM_ROUTE=direct and LLM_API_KEY_FILE)."
    exit 78
  fi
}

# --------------------------------------------------------------- environment -------------------------------------------
export_runtime_env() {
  if [[ $ERROW_LLM_ROUTE == gateway ]]; then
    if [[ -n $GATEWAY_TOKEN ]]; then
      export LLM_API_KEY=$GATEWAY_TOKEN
    elif ! $DRY_RUN; then
      die 66 "gateway bearer token not readable: ${LLM_GATEWAY_TOKEN_FILE} (secret llm_gateway_token)"
    fi
    export LLM_API_BASE=$GATEWAY_API_BASE
    export errow_LLM=${errow_LLM:-openai/${OLLAMA_SECURITY_MODEL}}
    export LLM_DISABLE_STREAMING=true
    export errow_API_TYPE=${errow_API_TYPE:-chat_completions}
    export LLM_TIMEOUT=${LLM_TIMEOUT:-600}
    if [[ ! $errow_LLM =~ ^openai/[A-Za-z0-9._:-]+$ ]]; then die 78 "errow_LLM must look like openai/<ollama-model> in gateway mode (got '${errow_LLM}')"; fi
    # The gateway refuses mutating tool calls (sandbox exec, isolate_host, firewall) without a human-approval token;
    # launching the scan with CS3_APPROVAL_TOKEN(_FILE) is the operator's approval, carried as one more header.
    approval_token=${CS3_APPROVAL_TOKEN-}
    if [[ -z $approval_token && -n ${CS3_APPROVAL_TOKEN_FILE-} ]]; then
      approval_token=$(read_secret "$CS3_APPROVAL_TOKEN_FILE") || die 66 "CS3_APPROVAL_TOKEN_FILE not readable: ${CS3_APPROVAL_TOKEN_FILE}"
    fi
    if [[ -n ${ERROW_TENANT_ID-} || -n ${ERROW_INCIDENT_ID-} || -n $approval_token ]]; then
      [[ -z ${LLM_EXTRA_HEADERS-} ]] || jq -e 'type == "object"' <<<"$LLM_EXTRA_HEADERS" >/dev/null || die 78 "LLM_EXTRA_HEADERS must be a JSON object"
      LLM_EXTRA_HEADERS=$(jq -cn --argjson base "${LLM_EXTRA_HEADERS:-{\}}" --arg t "${ERROW_TENANT_ID-}" --arg i "${ERROW_INCIDENT_ID-}" --arg a "$approval_token" \
        '$base + (if $t != "" then {"X-Tenant-Id": $t} else {} end) + (if $i != "" then {"X-Incident-Id": $i} else {} end) + (if $a != "" then {"X-CS3-Approval": $a} else {} end)')
      export LLM_EXTRA_HEADERS
    fi
  else
    [[ $CS3_PROFILE == cloud ]] || die 78 "ERROW_LLM_ROUTE=direct is only allowed in profile cloud"
    [[ -n ${LLM_API_KEY_FILE-} ]] || die 78 "direct route needs LLM_API_KEY_FILE (a file holding the provider key)"
    [[ -n ${errow_LLM-} ]] || die 78 "direct route needs errow_LLM (e.g. gemini/gemini-2.5-pro)"
    LLM_API_KEY=$(read_secret "$LLM_API_KEY_FILE") || die 66 "LLM_API_KEY_FILE not readable: ${LLM_API_KEY_FILE}"
    export LLM_API_KEY
  fi
  export errow_TELEMETRY=$TELEMETRY errow_NO_UPDATE_CHECK=1 errow_APP_URL=$APP_URL
  export ERROW_MODEL_DEGRADED=${ERROW_MODEL_DEGRADED:-false}
  export errow_RUNTIME_BACKEND=${errow_RUNTIME_BACKEND:-docker} errow_IMAGE=$SANDBOX_IMAGE
  export DOCKER_HOST=$DOCKER_HOST_RESOLVED
  if [[ $DOCKER_HOST == tcp://*:2376 && -r /certs/client/ca.pem ]]; then
    export DOCKER_TLS_VERIFY=${DOCKER_TLS_VERIFY:-1} DOCKER_CERT_PATH=${DOCKER_CERT_PATH:-/certs/client}
  fi
  export STACK_VERSION CS3_PROFILE PYTHONUNBUFFERED=1
}

build_ca_bundle() {
  local system=/etc/ssl/certs/ca-certificates.crt out=${HOME}/.errow/ca-bundle.pem
  if [[ -r $ERROW_PKI_CA && -r $system ]]; then
    cat -- "$system" "$ERROW_PKI_CA" >"${out}.new" && mv -f -- "${out}.new" "$out"
    export SSL_CERT_FILE=$out REQUESTS_CA_BUNDLE=$out CURL_CA_BUNDLE=$out
  elif [[ $CS3_PROFILE != cloud && $LLM_GATEWAY_URL == https://* ]]; then
    log_warn "internal CA ${ERROW_PKI_CA} not readable; TLS to the gateway will fail unless it chains to the system store"
  fi
}

prepare_dirs() {
  if ! { mkdir -p "${HOME}/.errow" "$ERROW_STATE_DIR" 2>/dev/null && chmod 700 "${HOME}/.errow" "$ERROW_STATE_DIR"; }; then
    die 73 "cannot create ${HOME}/.errow (HOME must be writable: Errow stores its 0600 config there)"
  fi
  if [[ $MODE != view ]]; then mkdir -p "${ERROW_WORKDIR}/errow_runs" 2>/dev/null || log_warn "cannot create ${ERROW_WORKDIR}/errow_runs"; fi
  if mkdir -p "$ERROW_LOG_DIR" 2>/dev/null && : >>"$ERROW_CLI_LOG" 2>/dev/null; then
    CLI_LOG_OK=1
  else
    log_warn "cannot write ${ERROW_CLI_LOG}; output is only printed to stdout"
  fi
  cd -- "$ERROW_WORKDIR" 2>/dev/null || die 66 "ERROW_WORKDIR does not exist: ${ERROW_WORKDIR}"
}

wait_for_docker() {
  [[ -x $ERROW_PYTHON ]] || die 69 "ERROW_PYTHON not executable: ${ERROW_PYTHON}"
  log_info "waiting for the Docker daemon at ${DOCKER_HOST} (timeout ${ERROW_DIND_TIMEOUT}s)"
  "$ERROW_PYTHON" "$ERROW_DIND_HELPER" ping --timeout "$ERROW_DIND_TIMEOUT" || die 69 "Docker daemon not reachable at ${DOCKER_HOST}"
  if "$ERROW_PYTHON" "$ERROW_DIND_HELPER" has-image "$SANDBOX_IMAGE"; then
    log_info "sandbox image present: ${SANDBOX_IMAGE}"
  elif [[ -n ${ERROW_SANDBOX_IMAGE_TAR-} && -r ${ERROW_SANDBOX_IMAGE_TAR} ]]; then
    log_info "loading sandbox image from ${ERROW_SANDBOX_IMAGE_TAR}"
    "$ERROW_PYTHON" "$ERROW_DIND_HELPER" load "$ERROW_SANDBOX_IMAGE_TAR" || die 69 "docker load failed"
    "$ERROW_PYTHON" "$ERROW_DIND_HELPER" has-image "$SANDBOX_IMAGE" || die 69 "tarball did not provide ${SANDBOX_IMAGE}"
  elif [[ $CS3_PROFILE == airgap ]]; then
    die 69 "sandbox image ${SANDBOX_IMAGE} missing in the air-gapped DinD; set ERROW_SANDBOX_IMAGE_TAR to a docker-save tarball"
  else
    log_warn "sandbox image ${SANDBOX_IMAGE} is not in DinD yet; Errow will try to pull it on first use"
  fi
}

# ---------------------------------------------------------------- run helpers ------------------------------------------
nap() {
  sleep "$1" &
  wait $! || true
}

# shellcheck disable=SC2317  # installed with `trap ... TERM INT HUP` in main
on_signal() {
  STOP=1
  if [[ -n $CHILD_PID ]]; then kill -TERM "$CHILD_PID" 2>/dev/null || true; fi
}

# shellcheck disable=SC2317  # installed with `trap cleanup EXIT` in main
cleanup() {
  local f
  for f in "${CLEANUP_FILES[@]}"; do rm -f -- "$f"; done
}

# capture_links keeps the authorised viewer link (private, 0600) before the stream is redacted.
capture_links() {
  local line url
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line =~ (https?://[^[:space:]]+token=[A-Za-z0-9_-]+) ]]; then
      url=${BASH_REMATCH[1]}
      (umask 077 && printf '%s\n' "$url" >"${VIEWER_LINK_FILE}.new") && mv -f -- "${VIEWER_LINK_FILE}.new" "$VIEWER_LINK_FILE"
    fi
    printf '%s\n' "$line"
  done
}

log_filter() {
  if ((CLI_LOG_OK)); then
    capture_links | sed -u -E 's/(token=)[A-Za-z0-9._~%+-]+/\1REDACTED/g' | tee -a "$ERROW_CLI_LOG" || true
  else
    capture_links | sed -u -E 's/(token=)[A-Za-z0-9._~%+-]+/\1REDACTED/g' || true
  fi
}

# start_logged runs "$@" in the background with stdout+stderr passing through log_filter (stdout and cli.log).
start_logged() {
  FIFO=${ERROW_STATE_DIR}/cli.$$.fifo
  rm -f -- "$FIFO"
  mkfifo -m 600 "$FIFO"
  CLEANUP_FILES+=("$FIFO")
  log_filter <"$FIFO" &
  FILTER_PID=$!
  "$@" >"$FIFO" 2>&1 &
  CHILD_PID=$!
}

wait_logged() {
  RUN_RC=0
  wait "$CHILD_PID" || RUN_RC=$?
  while kill -0 "$CHILD_PID" 2>/dev/null; do wait "$CHILD_PID" || RUN_RC=$?; done
  wait "$FILTER_PID" || true
  rm -f -- "$FIFO"
  CHILD_PID='' FILTER_PID=''
}

# ---------------------------------------------------------------- commands ---------------------------------------------
target_host() {
  local t=$1
  t=${t#*://}
  t=${t%%/*}
  t=${t##*@}
  t=${t%%:*}
  printf '%s' "${t,,}"
}

enforce_allowed_targets() {
  local target=$1 host pattern
  [[ -n ${ERROW_ALLOWED_TARGETS-} ]] || return 0
  host=$(target_host "$target")
  local IFS=','
  for pattern in $ERROW_ALLOWED_TARGETS; do
    # shellcheck disable=SC2053  # the right-hand side is intentionally a glob
    if [[ $host == ${pattern,,} ]]; then return 0; fi
  done
  die 77 "target '${target}' is not in ERROW_ALLOWED_TARGETS"
}

build_scan_cmd() {
  local -a a=("$@")
  local target='' i
  CMD=("$ERROW_CLI")
  if ((${#a[@]})) && [[ ${a[0]} == errow ]]; then a=("${a[@]:1}"); fi
  if ((${#a[@]})) && is_subcommand "${a[0]}"; then
    CMD+=("${a[@]}")
    return 0
  fi
  if ! has_arg '-n|--non-interactive' "${a[@]}" && { [[ ! -t 0 ]] || [[ ! -t 1 ]]; }; then a=(--non-interactive "${a[@]}"); fi
  if ! has_arg '-t|--target|--target-list' "${a[@]}"; then
    [[ -n ${ERROW_TARGET-} ]] || die 64 "scan mode needs --target/--target-list or ERROW_TARGET"
    a+=(--target "$ERROW_TARGET")
  fi
  if ! has_arg '-m|--scan-mode' "${a[@]}"; then
    case ${ERROW_SCAN_MODE:-quick} in quick | standard | deep) ;; *) die 64 "ERROW_SCAN_MODE must be quick|standard|deep" ;; esac
    a+=(--scan-mode "${ERROW_SCAN_MODE:-quick}")
  fi
  if ! has_arg '--instruction|--instruction-file' "${a[@]}" && [[ -n ${ERROW_INSTRUCTION_FILE-} ]]; then
    [[ -r $ERROW_INSTRUCTION_FILE ]] || die 66 "ERROW_INSTRUCTION_FILE not readable: ${ERROW_INSTRUCTION_FILE}"
    a+=(--instruction-file "$ERROW_INSTRUCTION_FILE")
  fi
  if ! has_arg '--fail-on' "${a[@]}" && [[ -n ${ERROW_FAIL_ON-} ]]; then a+=(--fail-on "$ERROW_FAIL_ON"); fi
  for ((i = 0; i < ${#a[@]}; i++)); do
    case ${a[i]} in
      -t | --target) if ((i + 1 < ${#a[@]})); then target=${a[i + 1]}; fi ;;
      --target=*) target=${a[i]#--target=} ;;
    esac
  done
  if [[ -n $target ]]; then enforce_allowed_targets "$target"; fi
  CMD+=("${a[@]}")
}

mtime_of() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null; }

newest_run() {
  # Glob + stat instead of `find -printf` so the viewer also works where find is BSD (macOS developer hosts).
  local runs=$1 dir newest='' newest_ts=-1 ts
  [[ -d $runs ]] || return 0
  for dir in "$runs"/*/; do
    [[ -f ${dir}run.json ]] || continue
    ts=$(mtime_of "${dir}run.json")
    [[ -n $ts ]] || continue
    if ((ts > newest_ts)); then newest_ts=$ts; newest=${dir%/}; fi
  done
  if [[ -n $newest ]]; then basename "$newest"; fi
}

state_set() { printf '%s\n' "$1" >"${ERROW_STATE_DIR}/viewer.state"; }

tcp_open() {
  # shellcheck disable=SC2016  # $0/$1 are the positional parameters of the inner bash
  timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>/dev/null
}

gateway_hostport() {
  local hp=${LLM_GATEWAY_URL#*://}
  hp=${hp%%/*}
  GW_HOST=${hp%%:*}
  GW_PORT=${hp##*:}
  if [[ $GW_PORT == "$hp" ]]; then
    if [[ $LLM_GATEWAY_URL == https://* ]]; then GW_PORT=443; else GW_PORT=80; fi
  fi
}

do_healthcheck() {
  local mode=${MODE_FLAG:-${ERROW_MODE:-idle}} state
  resolve_settings
  case $mode in
    view)
      state=$(cat "${ERROW_STATE_DIR}/viewer.state" 2>/dev/null || echo starting)
      case $state in
        waiting) return 0 ;;
        serving) tcp_open 127.0.0.1 "$ERROW_VIEWER_PORT" ;;
        *) return 1 ;;
      esac
      ;;
    *)
      (fail_closed_check) || return 1
      export DOCKER_HOST=$DOCKER_HOST_RESOLVED
      if [[ $DOCKER_HOST == tcp://*:2376 && -r /certs/client/ca.pem ]]; then export DOCKER_TLS_VERIFY=${DOCKER_TLS_VERIFY:-1} DOCKER_CERT_PATH=${DOCKER_CERT_PATH:-/certs/client}; fi
      "$ERROW_PYTHON" "$ERROW_DIND_HELPER" ping --timeout 5 || return 1
      gateway_hostport
      tcp_open "$GW_HOST" "$GW_PORT"
      ;;
  esac
}

describe_config() {
  local token_note degraded_note="" approval_token_note="<unset>"
  if [[ -n ${CS3_APPROVAL_TOKEN-} ]]; then approval_token_note="inline CS3_APPROVAL_TOKEN (env)"
  elif [[ -n ${CS3_APPROVAL_TOKEN_FILE-} ]]; then approval_token_note="file ${CS3_APPROVAL_TOKEN_FILE}"
  fi
  if [[ $ERROW_LLM_ROUTE == gateway ]]; then
    if [[ $TOKEN_STATE == env ]]; then token_note="inline CS3_ROUTER_KEY (env)"; else token_note="file ${LLM_GATEWAY_TOKEN_FILE} (${TOKEN_STATE})"; fi; else token_note="file ${LLM_API_KEY_FILE-} (direct, cloud profile)"; fi
  if is_true "${ERROW_MODEL_DEGRADED:-false}"; then degraded_note="  degraded run         security model ${OLLAMA_SECURITY_MODEL} unapproved; DEGRADED on ${OLLAMA_PRIMARY_MODEL}"$'\n'; fi
  cat <<EOF
${PROG} ${VERSION} dry-run (no secrets printed)
  mode                 ${MODE}
  profile              ${CS3_PROFILE}
  llm route            ${ERROW_LLM_ROUTE}
  LLM_API_BASE         ${LLM_API_BASE-<unchanged>}
  errow_LLM            ${errow_LLM-<unchanged>}
${degraded_note}
  LLM_DISABLE_STREAMING ${LLM_DISABLE_STREAMING-<unchanged>}
  errow_API_TYPE       ${errow_API_TYPE-<unchanged>}
  LLM_API_KEY          from ${token_note}
  LLM_EXTRA_HEADERS    ${LLM_EXTRA_HEADERS-<unset>}
  approval token       from ${approval_token_note}
  errow_TELEMETRY      ${TELEMETRY}
  errow_APP_URL        ${APP_URL}
  errow_IMAGE          ${SANDBOX_IMAGE}
  DOCKER_HOST          ${DOCKER_HOST_RESOLVED}
  workdir              ${ERROW_WORKDIR}
  config file          ${CONFIG_FILE_STATE}
  cli log              ${ERROW_CLI_LOG}
EOF
}

mode_scan() {
  build_scan_cmd "$@"
  if $DRY_RUN; then
    describe_config
    printf '  command              %s\n' "$(join_words "${CMD[@]}")"
    return 0
  fi
  if [[ -t 0 && -t 1 ]]; then exec "${CMD[@]}"; fi
  start_logged "${CMD[@]}"
  wait_logged
  return "$RUN_RC"
}

mode_idle() {
  if $DRY_RUN; then
    describe_config
    printf '  command              (idle; start scans with: docker exec <errow> errow-entrypoint --mode scan -- ...)\n'
    return 0
  fi
  log_info "ready (profile ${CS3_PROFILE}, model ${errow_LLM-n/a}$(is_true "${ERROW_MODEL_DEGRADED:-false}" && printf ', DEGRADED'); waiting for exec'd scans"
  # `sleep infinity` is a GNU extension (BSD userland rejects it), so park on a day-long sleep there and re-arm on wake.
  while ((STOP == 0)); do
    sleep infinity 2>/dev/null &
    CHILD_PID=$!
    if ! kill -0 "$CHILD_PID" 2>/dev/null; then
      sleep 86400 &
      CHILD_PID=$!
    fi
    wait "$CHILD_PID" || true
  done
  return 0
}

mode_view() {
  local runs=${ERROW_WORKDIR}/errow_runs newest latest started
  local -a view=("$ERROW_CLI" view)
  if $DRY_RUN; then
    describe_config
    printf '  command              %s view [<newest run>] --host %s --port %s --no-open\n' "$ERROW_CLI" "$ERROW_VIEWER_HOST" "$ERROW_VIEWER_PORT"
    printf '  viewer follow        %s (poll %ss, min restart %ss)\n' "$ERROW_VIEWER_FOLLOW" "$ERROW_VIEWER_POLL" "$ERROW_VIEWER_MIN_RESTART"
    return 0
  fi
  state_set waiting
  log_info "viewer: waiting for the first run under ${runs}"
  newest=$(newest_run "$runs")
  while [[ -z $newest ]] && ((STOP == 0)); do
    nap "$ERROW_VIEWER_POLL"
    newest=$(newest_run "$runs")
  done
  while ((STOP == 0)); do
    log_info "viewer: serving run ${newest} on ${ERROW_VIEWER_HOST}:${ERROW_VIEWER_PORT} (link: ${PROG} --print-viewer-link)"
    start_logged "${view[@]}" "$newest" --host "$ERROW_VIEWER_HOST" --port "$ERROW_VIEWER_PORT" --no-open
    state_set serving
    started=$(date +%s)
    latest=$newest
    while ((STOP == 0)) && kill -0 "$CHILD_PID" 2>/dev/null; do
      nap "$ERROW_VIEWER_POLL"
      if ((STOP == 0)) && is_true "$ERROW_VIEWER_FOLLOW"; then
        latest=$(newest_run "$runs")
        if [[ -n $latest && $latest != "$newest" ]] && (($(date +%s) - started >= ERROW_VIEWER_MIN_RESTART)); then
          log_info "viewer: newer run ${latest}; restarting the viewer (the session token changes)"
          kill -TERM "$CHILD_PID" 2>/dev/null || true
          break
        fi
        latest=$newest
      fi
    done
    wait_logged
    if ((STOP)); then break; fi
    if [[ $latest == "$newest" ]]; then
      log_err "viewer exited with status ${RUN_RC}"
      state_set stopped
      return "$((RUN_RC == 0 ? 1 : RUN_RC))"
    fi
    newest=$latest
  done
  return 0
}

# ---------------------------------------------------------------------- main -------------------------------------------
parse_args() {
  while (($#)); do
    case $1 in
      -h | --help) usage; exit 0 ;;
      --version) echo "${PROG} ${VERSION}"; exit 0 ;;
      --dry-run) DRY_RUN=true; shift ;;
      --healthcheck) DO_HEALTHCHECK=true; shift ;;
      --print-viewer-link) DO_PRINT_LINK=true; shift ;;
      --mode)
        [[ $# -ge 2 ]] || die 64 "--mode needs a value"
        MODE_FLAG=$2
        shift 2
        ;;
      --mode=*) MODE_FLAG=${1#--mode=}; shift ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  ERRO_ARGS=("$@")
  case $MODE_FLAG in '' | scan | view | idle) ;; *) die 64 "--mode must be scan|view|idle" ;; esac
}

main() {
  parse_args "$@"
  if $DO_PRINT_LINK; then
    resolve_settings
    [[ -r $VIEWER_LINK_FILE ]] || die 66 "no viewer link yet (${VIEWER_LINK_FILE}); is the viewer serving a run?"
    cat -- "$VIEWER_LINK_FILE"
    return 0
  fi
  if $DO_HEALTHCHECK; then do_healthcheck || return 1; return 0; fi

  local rc=0
  MODE=$MODE_FLAG
  if [[ -z $MODE ]]; then
    if ((${#ERRO_ARGS[@]})); then MODE=scan; else MODE=${ERROW_MODE:-idle}; fi
  fi
  case $MODE in scan | view | idle) ;; *) die 64 "ERROW_MODE must be scan|view|idle (got '${MODE}')" ;; esac

  resolve_settings
  fail_closed_check
  export_runtime_env
  trap on_signal TERM INT HUP
  trap cleanup EXIT
  if ! $DRY_RUN; then
    prepare_dirs
    build_ca_bundle
    if [[ $MODE != view ]]; then wait_for_docker; fi
  fi
  case $MODE in
    scan) mode_scan "${ERRO_ARGS[@]}" || rc=$? ;;
    view) mode_view || rc=$? ;;
    idle) mode_idle || rc=$? ;;
  esac
  return "$rc"
}

rc=0
main "$@" || rc=$?
exit "$rc"
