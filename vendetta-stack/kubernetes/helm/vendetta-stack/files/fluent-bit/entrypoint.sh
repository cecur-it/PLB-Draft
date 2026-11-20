#!/usr/bin/env bash
# Traces: PROMPT §1 Tier 1 (edge collector); CONTRACT §8.3 (leg renderer), §11 (RUNTIME), §0 (shell rules)
# Container entrypoint of the Fluent Bit edge collector (fluent/fluent-bit:3.2.10-debug: needs bash, gzip, stat).
#   1. reads secrets from *_FILE paths into the environment (never to disk, never into a config file),
#   2. exports a default for every ${VAR} the config tree references (Fluent Bit has no ${VAR:-default}),
#   3. renders legs/*.conf (Console / ESOC / SIEM per CS3_*_ENABLED) and inputs/*.conf (systemd, host logs, syslog) into
#      enabled.d/ (always including 00-noop.conf so `@INCLUDE enabled.d/*.conf` can never match nothing),
#   4. validates the tree with `fluent-bit -D`, starts the safety-file size rotation, then exec's fluent-bit.
# Modes: (default) run | --validate/--dry-run | --render-only <dir> (K8s initContainer for the distroless image) |
#        --healthcheck | --help.   Extra arguments after `--` go to fluent-bit.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

readonly EX_USAGE=2 EX_ENV=3 EX_CONFIG=4
CONF_DIR="${FLB_CONF_DIR:-/etc/fluent-bit}"
ENABLED_DIR="${FLB_ENABLED_DIR:-$CONF_DIR/enabled.d}"
FLB_BIN="${FLB_BIN:-/fluent-bit/bin/fluent-bit}"
STATE_DIR="${FLB_STATE_DIR:-/var/log/fluent-bit}"

if [[ -t 2 ]]; then
  C_RED=$'\033[31m' C_YEL=$'\033[33m' C_GRN=$'\033[32m' C_OFF=$'\033[0m'
else
  C_RED='' C_YEL='' C_GRN='' C_OFF=''
fi
log_info() { printf '%s[entrypoint]%s %s\n' "$C_GRN" "$C_OFF" "$*" >&2; }
log_warn() { printf '%s[entrypoint] WARN%s %s\n' "$C_YEL" "$C_OFF" "$*" >&2; }
log_err() { printf '%s[entrypoint] ERROR%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; }
die() {
  local code="$1"
  shift
  log_err "$*"
  exit "$code"
}

usage() {
  cat <<'EOF'
Usage: entrypoint.sh [--validate | --dry-run | --render-only DIR | --healthcheck | --help] [-- fluent-bit args...]

  (default)            render enabled.d, validate with `fluent-bit -D`, exec fluent-bit
  --validate/--dry-run render + validate, do not start
  --render-only DIR    render the legs/inputs into DIR and exit (no secrets read; for the K8s initContainer)
  --healthcheck        GET http://127.0.0.1:2020/api/v1/health using bash only (container HEALTHCHECK)

Legs:   CS3_CONSOLE_ENABLED, CS3_ESOC_ENABLED, CS3_SIEM_ENABLED, CS3_MANAGER_ENABLED  (true|false, default false)
Secrets: CS3_INGEST_KEY_FILE -> CS3_INGEST_KEY, CS3_SIEM_TOKEN_FILE -> CS3_SIEM_TOKEN
Inputs:  /var/log/journal or /run/log/journal present -> systemd input (CS3_JOURNAL_ALL=true: whole journal);
         ${ERROW_REPORTS_DIR} / dirname(${CAIDO_LOG_GLOB}) exist -> optional report / Caido log tails;
         CFGAUDIT_ENABLED=true + ${CFGAUDIT_REPORTS_DIR} exists -> Cfgaudit finding/run tails;
         FLB_SYSLOG_ENABLED=true -> syslog inputs; /var/log/auth.log|secure and /var/log/audit/audit.log -> host inputs
         (disable with CS3_HOST_LOGS=false).
Exit codes: 0 ok, 2 usage, 3 missing/invalid environment, 4 configuration rejected by fluent-bit.
EOF
}

truthy() {
  case "${1,,}" in
    true | 1 | yes | on) return 0 ;;
    *) return 1 ;;
  esac
}

# retry <attempts> <initial-delay-seconds> <command...>: exponential backoff, returns the last exit status.
retry() {
  local attempts="$1" delay="$2" n=1 rc=0
  shift 2
  until "$@"; do
    rc=$?
    if ((n >= attempts)); then
      return "$rc"
    fi
    log_warn "attempt $n/$attempts failed (rc=$rc): $*; retrying in ${delay}s"
    sleep "$delay"
    delay=$((delay * 2 > 30 ? 30 : delay * 2))
    n=$((n + 1))
  done
}

file_ready() { [[ -r "$1" && -s "$1" ]]; }

# Prints the secret with surrounding whitespace removed. Mounted secrets can lag container start (CSI drivers).
read_secret_file() {
  local path="$1" value
  retry "${FLB_SECRET_WAIT_ATTEMPTS:-6}" 1 file_ready "$path" || die "$EX_ENV" "secret file not readable or empty: $path"
  value="$(tr -d '\r' <"$path")"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  [[ -n "$value" ]] || die "$EX_ENV" "secret file is blank: $path"
  printf '%s' "$value"
}

load_secrets() {
  if [[ -n "${CS3_INGEST_KEY_FILE:-}" ]]; then
    CS3_INGEST_KEY="$(read_secret_file "$CS3_INGEST_KEY_FILE")"
  fi
  if [[ -n "${CS3_SIEM_TOKEN_FILE:-}" ]]; then
    CS3_SIEM_TOKEN="$(read_secret_file "$CS3_SIEM_TOKEN_FILE")"
  fi
  : "${CS3_INGEST_KEY:=unset}" "${CS3_SIEM_TOKEN:=unset}"
  export CS3_INGEST_KEY CS3_SIEM_TOKEN
}

export_defaults() {
  : "${FLB_LOG_LEVEL:=info}" "${CS3_HOSTNAME:=${HOSTNAME:-fluent-bit}}" "${CS3_EPS_LIMIT:=500}" "${CS3_MESSAGE_MAX_CHARS:=8000}"
  : "${CS3_AGENT_ID:=fluent-bit-$CS3_HOSTNAME}" "${CS3_HEALTH_SCRAPE_SEC:=30}"
  : "${ERROW_TUI_PORT:=24225}" "${ERROW_REPORTS_DIR:=/var/log/errow/reports}"
  : "${CFGAUDIT_REPORTS_DIR:=/var/log/cfgaudit}" "${CFGAUDIT_ENABLED:=false}"
  : "${ERROW_SHIPPER_STATUS_FILE:=/var/lib/errow-shipper/status.json}" "${CAIDO_LOG_GLOB:=/var/log/errow/caido/*.log}"
  : "${FLB_FORWARD_TLS:=off}" "${FLB_FORWARD_TLS_VERIFY:=on}" "${FLB_FORWARD_TLS_CA_FILE:=/pki/ca.crt}"
  : "${FLB_FORWARD_TLS_CRT_FILE:=/pki/fluent-bit.crt}" "${FLB_FORWARD_TLS_KEY_FILE:=/pki/fluent-bit.key}"
  : "${FLB_FORWARD_STORAGE_LIMIT:=2G}" "${FLB_SYSLOG_PORT:=5140}"
  : "${CS3_HOST:=}" "${CS3_PORT:=443}" "${CS3_TLS:=On}" "${CS3_CA_FILE:=/pki/ca.crt}"
  : "${CS3_ESOC_HOST:=}" "${CS3_ESOC_PORT:=4317}" "${CS3_ESOC_GRPC:=On}" "${CS3_ESOC_TLS:=On}" "${CS3_ESOC_CA_FILE:=/pki/ca.crt}"
  : "${CS3_ESOC_CERT_FILE:=/pki/fluent-bit.crt}" "${CS3_ESOC_KEY_FILE:=/pki/fluent-bit.key}"
  : "${CS3_SIEM_HOST:=}" "${CS3_SIEM_PORT:=443}" "${CS3_SIEM_URI:=/v1/events}" "${CS3_SIEM_TLS:=On}"
  : "${CS3_SIEM_CA_FILE:=/pki/ca.crt}" "${CS3_SIEM_FORMAT:=json_lines}" "${CS3_SIEM_AUTH_SCHEME:=Bearer}"
  : "${CS3_MANAGER_HOST:=}" "${CS3_MANAGER_PORT:=5140}" "${FLB_MANAGER_ALERTS_PATH:=/var/vendetta/logs/alerts/alerts.json}"
  : "${FLB_SAFETY_MAX_BYTES:=67108864}" "${FLB_SAFETY_KEEP:=7}" "${FLB_ROTATE_INTERVAL:=60}"
  if [[ -z "${FLB_JOURNAL_PATH:-}" ]]; then
    if [[ -d /var/log/journal ]]; then
      FLB_JOURNAL_PATH=/var/log/journal
    elif [[ -d /run/log/journal ]]; then
      FLB_JOURNAL_PATH=/run/log/journal
    else
      FLB_JOURNAL_PATH=/var/log/journal
    fi
  fi
  export FLB_LOG_LEVEL CS3_HOSTNAME CS3_EPS_LIMIT CS3_MESSAGE_MAX_CHARS CS3_AGENT_ID CS3_HEALTH_SCRAPE_SEC \
    ERROW_TUI_PORT ERROW_REPORTS_DIR ERROW_SHIPPER_STATUS_FILE CAIDO_LOG_GLOB CFGAUDIT_ENABLED CFGAUDIT_REPORTS_DIR \
    FLB_FORWARD_TLS FLB_FORWARD_TLS_VERIFY FLB_FORWARD_TLS_CA_FILE FLB_FORWARD_TLS_CRT_FILE FLB_FORWARD_TLS_KEY_FILE \
    FLB_FORWARD_STORAGE_LIMIT FLB_SYSLOG_PORT CS3_HOST CS3_PORT CS3_TLS CS3_CA_FILE \
    CS3_ESOC_HOST CS3_ESOC_PORT CS3_ESOC_GRPC CS3_ESOC_TLS CS3_ESOC_CA_FILE CS3_ESOC_CERT_FILE CS3_ESOC_KEY_FILE \
    CS3_SIEM_HOST CS3_SIEM_PORT CS3_SIEM_URI CS3_SIEM_TLS CS3_SIEM_CA_FILE CS3_SIEM_FORMAT CS3_SIEM_AUTH_SCHEME \
    CS3_MANAGER_HOST CS3_MANAGER_PORT FLB_MANAGER_ALERTS_PATH \
    FLB_SAFETY_MAX_BYTES FLB_SAFETY_KEEP FLB_ROTATE_INTERVAL FLB_JOURNAL_PATH
}

validate_environment() {
  local problems=0 var
  fail() {
    log_err "$*"
    problems=$((problems + 1))
  }
  [[ "$CS3_EPS_LIMIT" =~ ^[0-9]+$ && "$CS3_EPS_LIMIT" -ge 1 ]] || fail "CS3_EPS_LIMIT must be a positive integer (got '$CS3_EPS_LIMIT')"
  [[ "$ERROW_TUI_PORT" =~ ^[0-9]+$ && "$ERROW_TUI_PORT" -ge 1 && "$ERROW_TUI_PORT" -le 65535 && "$ERROW_TUI_PORT" != 24224 ]] ||
    fail "ERROW_TUI_PORT must be 1-65535 and differ from 24224 (got '$ERROW_TUI_PORT')"
  [[ "$FLB_SAFETY_KEEP" =~ ^[1-9][0-9]*$ ]] || fail "FLB_SAFETY_KEEP must be a positive integer"
  if truthy "${CS3_CONSOLE_ENABLED:-false}"; then
    [[ -n "$CS3_HOST" ]] || fail "CS3_CONSOLE_ENABLED=true requires CS3_HOST"
    if [[ "${MODE}" != render-only ]]; then
      [[ "$CS3_INGEST_KEY" != unset ]] || fail "CS3_CONSOLE_ENABLED=true requires CS3_INGEST_KEY_FILE (or CS3_INGEST_KEY)"
    fi
  fi
  if truthy "${CS3_ESOC_ENABLED:-false}"; then
    [[ -n "$CS3_ESOC_HOST" ]] || fail "CS3_ESOC_ENABLED=true requires CS3_ESOC_HOST"
    if [[ "${CS3_ESOC_TLS,,}" == on && "${MODE}" != render-only ]]; then
      for var in "$CS3_ESOC_CA_FILE" "$CS3_ESOC_CERT_FILE" "$CS3_ESOC_KEY_FILE"; do
        [[ -r "$var" ]] || fail "ESOC mTLS file not readable: $var"
      done
    fi
  fi
  if truthy "${CS3_MANAGER_ENABLED:-false}"; then
    # The manager leg has two directions: alerts out to CS3 and host logs in to the rule engine.
    [[ -n "$CS3_HOST" ]] || fail "CS3_MANAGER_ENABLED=true requires CS3_HOST"
    [[ -n "$CS3_MANAGER_HOST" ]] || fail "CS3_MANAGER_ENABLED=true requires CS3_MANAGER_HOST"
    [[ "$CS3_MANAGER_PORT" =~ ^[0-9]+$ && "$CS3_MANAGER_PORT" -ge 1 && "$CS3_MANAGER_PORT" -le 65535 ]] ||
      fail "CS3_MANAGER_PORT must be 1-65535 (got '$CS3_MANAGER_PORT')"
    if [[ "${MODE}" != render-only ]]; then
      [[ "$CS3_INGEST_KEY" != unset ]] || fail "CS3_MANAGER_ENABLED=true requires CS3_INGEST_KEY_FILE (or CS3_INGEST_KEY)"
      [[ -r "$FLB_MANAGER_ALERTS_PATH" ]] || log_warn "manager alerts file not readable yet: $FLB_MANAGER_ALERTS_PATH (leg will idle until it appears)"
    fi
  fi
  if truthy "${CS3_SIEM_ENABLED:-false}"; then
    [[ -n "$CS3_SIEM_HOST" ]] || fail "CS3_SIEM_ENABLED=true requires CS3_SIEM_HOST"
    if [[ "${MODE}" != render-only ]]; then
      [[ "$CS3_SIEM_TOKEN" != unset ]] || fail "CS3_SIEM_ENABLED=true requires CS3_SIEM_TOKEN_FILE (or CS3_SIEM_TOKEN)"
    fi
  fi
  if [[ "${FLB_FORWARD_TLS,,}" == on && "${MODE}" != render-only ]]; then
    for var in "$FLB_FORWARD_TLS_CA_FILE" "$FLB_FORWARD_TLS_CRT_FILE" "$FLB_FORWARD_TLS_KEY_FILE"; do
      [[ -r "$var" ]] || fail "FLB_FORWARD_TLS=on but file not readable: $var"
    done
  fi
  if [[ "${MODE}" != render-only ]]; then
    for var in /pki/ca.crt /pki/fluent-bit.crt /pki/fluent-bit.key; do
      [[ -r "$var" ]] || log_warn "upstream mTLS file not readable yet: $var (forward output to Fluentd will retry until it appears)"
    done
  fi
  ((problems == 0)) || die "$EX_ENV" "$problems environment problem(s); see above"
}

install_fragment() {
  local src="$1" dst="$2"
  [[ -f "$src" ]] || die "$EX_ENV" "missing fragment $src"
  install -m 0644 "$src" "$dst"
  log_info "enabled $(basename "$src")"
}

render() {
  local out="$1"
  mkdir -p "$out" 2>/dev/null || true
  [[ -d "$out" && -w "$out" ]] ||
    die "$EX_ENV" "$out is not writable: mount a tmpfs/emptyDir there when the root filesystem is read-only"
  find "$out" -maxdepth 1 -type f -name '*.conf' -delete
  printf '%s\n' '# Always present: keeps the @INCLUDE enabled.d glob non-empty when every leg and optional input is off.' >"$out/00-noop.conf"

  if truthy "${CS3_CONSOLE_ENABLED:-false}"; then install_fragment "$CONF_DIR/legs/10-console.conf" "$out/10-console.conf"; fi
  if truthy "${CS3_ESOC_ENABLED:-false}"; then install_fragment "$CONF_DIR/legs/20-esoc.conf" "$out/20-esoc.conf"; fi
  if truthy "${CS3_SIEM_ENABLED:-false}"; then install_fragment "$CONF_DIR/legs/30-siem.conf" "$out/30-siem.conf"; fi
  if truthy "${CS3_MANAGER_ENABLED:-false}"; then install_fragment "$CONF_DIR/legs/50-manager.conf" "$out/50-manager.conf"; fi

  if [[ -d "$FLB_JOURNAL_PATH" ]]; then
    if truthy "${CS3_JOURNAL_ALL:-false}"; then
      install_fragment "$CONF_DIR/inputs/systemd-all.conf" "$out/40-systemd.conf"
    else
      install_fragment "$CONF_DIR/inputs/systemd.conf" "$out/40-systemd.conf"
    fi
  else
    log_info "no journal at $FLB_JOURNAL_PATH: systemd input not rendered"
  fi
  if [[ "${CS3_HOST_LOGS:-true}" != false ]]; then
    if [[ -r /var/log/auth.log || -r /var/log/secure ]]; then install_fragment "$CONF_DIR/inputs/host-auth.conf" "$out/41-host-auth.conf"; fi
    if [[ -r /var/log/audit/audit.log ]]; then install_fragment "$CONF_DIR/inputs/host-audit.conf" "$out/42-host-audit.conf"; fi
  fi
  if truthy "${FLB_SYSLOG_ENABLED:-false}"; then install_fragment "$CONF_DIR/inputs/syslog.conf" "$out/43-syslog.conf"; fi
  if [[ -d "$ERROW_REPORTS_DIR" ]]; then install_fragment "$CONF_DIR/inputs/errow-reports.conf" "$out/44-errow-reports.conf"; fi
  if truthy "${CFGAUDIT_ENABLED:-false}"; then
    [[ -d "$CFGAUDIT_REPORTS_DIR" && -r "$CFGAUDIT_REPORTS_DIR" && -x "$CFGAUDIT_REPORTS_DIR" ]] ||
      die "$EX_ENV" "CFGAUDIT_ENABLED=true requires readable directory $CFGAUDIT_REPORTS_DIR"
    install_fragment "$CONF_DIR/inputs/cfgaudit.conf" "$out/46-cfgaudit.conf"
  fi
  if [[ -d "$(dirname "$CAIDO_LOG_GLOB")" ]]; then install_fragment "$CONF_DIR/inputs/caido.conf" "$out/45-caido.conf"; fi
}

prepare_state() {
  retry 3 1 mkdir -p "$STATE_DIR/storage" "$STATE_DIR/db" || die "$EX_ENV" "cannot create $STATE_DIR (mount the fluentbit-storage volume writable)"
  [[ -w "$STATE_DIR" ]] || die "$EX_ENV" "$STATE_DIR is not writable"
}

validate_config() {
  local output rc=0
  output="$("$FLB_BIN" -c "$CONF_DIR/fluent-bit.conf" -D 2>&1)" || rc=$?
  if ((rc != 0)) || grep -q '\[error\]' <<<"$output"; then
    printf '%s\n' "$output" >&2
    die "$EX_CONFIG" "fluent-bit rejected the configuration (rc=$rc)"
  fi
  log_info "configuration valid ($("$FLB_BIN" --version | head -n 1))"
}

# Size rotation of the always-on cs3-ai-ollama.ndjson safety sink (the `file` output has no rotation of its own and reopens
# the file on every flush, so a rename is safe). Keeps FLB_SAFETY_KEEP gzip generations: .1.gz newest.
rotate_safety_file() {
  local file="$STATE_DIR/cs3-ai-ollama.ndjson" size i
  [[ -f "$file" ]] || return 0
  size="$(stat -c %s "$file")"
  ((size >= FLB_SAFETY_MAX_BYTES)) || return 0
  for ((i = FLB_SAFETY_KEEP - 1; i >= 1; i--)); do
    if [[ -f "$file.$i.gz" ]]; then mv -f "$file.$i.gz" "$file.$((i + 1)).gz"; fi
  done
  mv -f "$file" "$file.1"
  gzip -f "$file.1"
  log_info "rotated $file ($size bytes)"
}

rotation_loop() {
  local owner="$1"
  while kill -0 "$owner" 2>/dev/null; do
    sleep "$FLB_ROTATE_INTERVAL"
    rotate_safety_file || log_warn "safety-file rotation failed; will retry"
  done
}

healthcheck() {
  local status
  exec 3<>/dev/tcp/127.0.0.1/2020
  printf 'GET /api/v1/health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3
  IFS= read -r status <&3
  exec 3>&-
  [[ "$status" == *" 200 "* ]]
}

MODE=run
RENDER_DIR=''
FLB_ARGS=()
while (($# > 0)); do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --validate | --dry-run) MODE=validate ;;
    --render-only)
      [[ $# -ge 2 ]] || die "$EX_USAGE" "--render-only needs a directory"
      MODE=render-only
      RENDER_DIR="$2"
      shift
      ;;
    --healthcheck) MODE=healthcheck ;;
    --)
      shift
      FLB_ARGS=("$@")
      break
      ;;
    *) die "$EX_USAGE" "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

if [[ "$MODE" == healthcheck ]]; then
  healthcheck
  exit $?
fi

export_defaults
if [[ "$MODE" != render-only ]]; then load_secrets; else CS3_INGEST_KEY=unset CS3_SIEM_TOKEN=unset; fi
validate_environment

if [[ "$MODE" == render-only ]]; then
  render "$RENDER_DIR"
  log_info "rendered into $RENDER_DIR"
  exit 0
fi

prepare_state
render "$ENABLED_DIR"
validate_config
if [[ "$MODE" == validate ]]; then
  log_info "validate-only: not starting fluent-bit"
  exit 0
fi

rotation_loop "$$" &
log_info "starting fluent-bit (legs: console=${CS3_CONSOLE_ENABLED:-false} esoc=${CS3_ESOC_ENABLED:-false} siem=${CS3_SIEM_ENABLED:-false} manager=${CS3_MANAGER_ENABLED:-false})"
exec "$FLB_BIN" -c "$CONF_DIR/fluent-bit.conf" "${FLB_ARGS[@]}"
