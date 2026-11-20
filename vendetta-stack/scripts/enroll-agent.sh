#!/usr/bin/env bash
#
# enroll-agent.sh — enroll a host as a Vendetta agent and wire its Fluent Bit edge forwarder to the aggregation tier.
#
# Traces: PROMPT §1 Tier 1 (agents) / §3 Phase 3 scripts/enroll-agent.sh; CONTRACT §2 (authd 1515, API 55000, forward 24224 TLS + client
#         cert, vendetta_api_password), §5 (Fluent Bit → Fluentd upstream), CS3 deployment/agents/{install-forwarder.sh,cs3-enroll.mjs}.
#
# 1. Enrollment (idempotent by agent name — an existing entry in <vendetta-home>/etc/client.keys is reused, never rotated):
#      agent-auth   the Vendetta/Wazuh-compatible `agent-auth` binary (preferred when present; the authd password is placed in
#                   <home>/etc/authd.pass, never on argv)
#      authd        the native authd protocol over TLS to <manager>:1515 using openssl s_client (verifies the manager
#                   certificate against pki/ca.crt and the host name); request `OSSEC PASS: … OSSEC A:'<name>' [G:'…' IP:'…']`
#      api          fallback through the manager API :55000: authenticate (basic auth, password FILE) then POST /agents/insert
#    `--method auto` (default) picks agent-auth → authd → api. The returned key is validated (id name ip 64-hex) and written to
#    client.keys atomically (mode 0640). Keys and passwords are never printed or placed on argv.
# 2. Edge forwarder: renders <forwarder-dir> (default /etc/vendetta-edge): fluent-bit.conf (host.auth / host.audit / host.journal,
#    record_modifier agent_name/agent_id, filesystem buffering), upstream.conf (round-robin over every --forward-host, TLS on,
#    tls.verify on, tls.vhost, client certificate), pki/ copies (key 0600) and, with --install-systemd, the
#    vendetta-edge-forwarder.service unit. Client identity: --client-cert/--client-key, or --issue-client-cert (signed by the local
#    pki/ca.key, CN=<agent-name>, clientAuth).
# --dry-run validates everything and prints the plan without contacting the manager or writing files.
#
# Exit codes: 0 ok | 1 failure | 2 usage | 3 policy (FailClosedError, unverified TLS under onprem/airgap) | 4 missing prerequisite |
#             5 manager unreachable / refused the enrollment

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/pki.sh
source "$SCRIPT_DIR/lib/pki.sh"

trap 'vs_cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
enroll-agent.sh — enroll this host as a Vendetta agent and configure its Fluent Bit edge forwarder.

Usage: scripts/enroll-agent.sh --manager HOST [options]

Enrollment:
  --manager HOST             manager DNS name or IP (authd 1515, API 55000)             --authd-port N  --api-port N
  --agent-name NAME          default: this host's name         --group G (default: default)    --agent-ip IP|any (default any)
  --method auto|agent-auth|authd|api   (default auto: agent-auth if installed, else native authd, else API)
  --password-file F          authd password file (default $VENDETTA_AUTHD_PASSWORD_FILE); --no-password when authd needs none
  --api-user NAME            default $VENDETTA_API_USER or vendetta     --api-password-file F (default secrets/vendetta_api_password)
  --ca F                     CA that signed the manager certificate (default pki/ca.crt)
  --auth-cert F --auth-key F client certificate for authd when the manager verifies agents
  --allow-unverified-manager native authd without certificate verification (refused under CS3_PROFILE onprem/airgap)
  --vendetta-home DIR        default $VENDETTA_HOME or /var/ossec      --restart-service NAME  (systemctl restart after enrolling)
  --force-reenroll           replace an existing local key (and delete the manager-side agent with --method api)
  --skip-enroll
Edge forwarder:
  --forward-host H[:PORT]    repeatable; default $EDGE_FORWARD_HOSTS or fluentd-1:24224,fluentd-2:24224
  --forwarder-dir DIR        default /etc/vendetta-edge                --buffer-dir DIR (default /var/lib/vendetta-edge/buffer)
  --client-cert F --client-key F | --issue-client-cert    client identity for the forward TLS connection
  --no-journal               do not read the systemd journal         --fluent-bit-bin PATH  --install-systemd
  --skip-forwarder
General: --dry-run  --stack-dir DIR  -q  -v  -h

Exit codes: 0 ok | 1 failure | 2 usage | 3 policy | 4 prerequisite | 5 manager unreachable/refused
EOF
}

MANAGER=""
AUTHD_PORT=1515
API_PORT=55000
AGENT_NAME=""
GROUP="default"
AGENT_IP="any"
METHOD="auto"
PASSWORD_FILE=""
NO_PASSWORD=0
API_USER=""
API_PASSWORD_FILE=""
CA_FILE=""
AUTH_CERT=""
AUTH_KEY=""
ALLOW_UNVERIFIED=0
VENDETTA_HOME_DIR=""
RESTART_SERVICE=""
FORCE=0
SKIP_ENROLL=0
SKIP_FORWARDER=0
FORWARD_HOSTS=()
FORWARDER_DIR="/etc/vendetta-edge"
BUFFER_DIR="/var/lib/vendetta-edge/buffer"
CLIENT_CERT=""
CLIENT_KEY=""
ISSUE_CERT=0
NO_JOURNAL=0
FB_BIN=""
INSTALL_SYSTEMD=0
AGENT_ID=""
ENROLL_STATE="skipped"

while (($#)); do
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]}"
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --manager) vs_need "$@"; MANAGER=$2; shift 2 ;;
    --authd-port) vs_need "$@"; AUTHD_PORT=$2; shift 2 ;;
    --api-port) vs_need "$@"; API_PORT=$2; shift 2 ;;
    --agent-name) vs_need "$@"; AGENT_NAME=$2; shift 2 ;;
    --group) vs_need "$@"; GROUP=$2; shift 2 ;;
    --agent-ip) vs_need "$@"; AGENT_IP=$2; shift 2 ;;
    --method) vs_need "$@"; METHOD=$2; shift 2 ;;
    --password-file) vs_need "$@"; PASSWORD_FILE=$2; shift 2 ;;
    --no-password) NO_PASSWORD=1; shift ;;
    --api-user) vs_need "$@"; API_USER=$2; shift 2 ;;
    --api-password-file) vs_need "$@"; API_PASSWORD_FILE=$2; shift 2 ;;
    --ca) vs_need "$@"; CA_FILE=$2; shift 2 ;;
    --auth-cert) vs_need "$@"; AUTH_CERT=$2; shift 2 ;;
    --auth-key) vs_need "$@"; AUTH_KEY=$2; shift 2 ;;
    --allow-unverified-manager) ALLOW_UNVERIFIED=1; shift ;;
    --vendetta-home) vs_need "$@"; VENDETTA_HOME_DIR=$2; shift 2 ;;
    --restart-service) vs_need "$@"; RESTART_SERVICE=$2; shift 2 ;;
    --force-reenroll) FORCE=1; shift ;;
    --skip-enroll) SKIP_ENROLL=1; shift ;;
    --skip-forwarder) SKIP_FORWARDER=1; shift ;;
    --forward-host) vs_need "$@"; FORWARD_HOSTS+=("$2"); shift 2 ;;
    --forwarder-dir) vs_need "$@"; FORWARDER_DIR=$2; shift 2 ;;
    --buffer-dir) vs_need "$@"; BUFFER_DIR=$2; shift 2 ;;
    --client-cert) vs_need "$@"; CLIENT_CERT=$2; shift 2 ;;
    --client-key) vs_need "$@"; CLIENT_KEY=$2; shift 2 ;;
    --issue-client-cert) ISSUE_CERT=1; shift ;;
    --no-journal) NO_JOURNAL=1; shift ;;
    --fluent-bit-bin) vs_need "$@"; FB_BIN=$2; shift 2 ;;
    --install-systemd) INSTALL_SYSTEMD=1; shift ;;
    --dry-run) VS_DRY_RUN=1; shift ;;
    -q|--quiet) VS_QUIET=1; shift ;;
    -v|--verbose) VS_VERBOSE=1; shift ;;
    --stack-dir)
      vs_need "$@"
      [[ -d "$2" ]] || die "$EX_USAGE" "stack dir not found: $2"
      STACK_DIR="$(cd "$2" && pwd)"
      SECRETS_DIR="$STACK_DIR/secrets"; PKI_DIR="$STACK_DIR/pki"; ENV_FILE="$STACK_DIR/.env"
      shift 2 ;;
    *) die "$EX_USAGE" "unknown option: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------------------------------
vs_require openssl
[[ -n "$MANAGER" ]] || die "$EX_USAGE" "--manager HOST is required"
[[ "$MANAGER" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || "$MANAGER" =~ ^[0-9a-fA-F:]+$ ]] || die "$EX_USAGE" "invalid --manager: $MANAGER"
vs_valid_port "$AUTHD_PORT" || die "$EX_USAGE" "invalid --authd-port"
vs_valid_port "$API_PORT" || die "$EX_USAGE" "invalid --api-port"
AGENT_NAME="${AGENT_NAME:-$(hostname 2>/dev/null || echo agent)}"
[[ "$AGENT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "$EX_USAGE" "invalid --agent-name (letters, digits, . _ -): $AGENT_NAME"
[[ "$GROUP" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "$EX_USAGE" "invalid --group: $GROUP"
[[ "$AGENT_IP" == any || "$AGENT_IP" =~ ^[0-9a-fA-F.:/]+$ ]] || die "$EX_USAGE" "invalid --agent-ip: $AGENT_IP"
case "$METHOD" in auto|agent-auth|authd|api) ;; *) die "$EX_USAGE" "--method must be auto, agent-auth, authd or api" ;; esac
VENDETTA_HOME_DIR="${VENDETTA_HOME_DIR:-${VENDETTA_HOME:-/var/ossec}}"
KEYS_FILE="$VENDETTA_HOME_DIR/etc/client.keys"
PASSWORD_FILE="${PASSWORD_FILE:-$(vs_cfg VENDETTA_AUTHD_PASSWORD_FILE "")}"
API_USER="${API_USER:-$(vs_cfg VENDETTA_API_USER vendetta)}"
API_PASSWORD_FILE="${API_PASSWORD_FILE:-$SECRETS_DIR/vendetta_api_password}"
CA_FILE="${CA_FILE:-$PKI_DIR/ca.crt}"
if ((${#FORWARD_HOSTS[@]} == 0)); then IFS=, read -r -a FORWARD_HOSTS <<<"$(vs_cfg EDGE_FORWARD_HOSTS fluentd-1:24224,fluentd-2:24224)"; fi
for h in "${FORWARD_HOSTS[@]}"; do
  [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$ ]] || die "$EX_USAGE" "invalid --forward-host: $h"
done
if [[ -n "$CLIENT_CERT" && -z "$CLIENT_KEY" ]] || [[ -z "$CLIENT_CERT" && -n "$CLIENT_KEY" ]]; then die "$EX_USAGE" "--client-cert and --client-key go together"; fi
if [[ -n "$CLIENT_CERT" && $ISSUE_CERT -eq 1 ]]; then die "$EX_USAGE" "--client-cert and --issue-client-cert are mutually exclusive"; fi
if [[ -n "$AUTH_CERT" && -z "$AUTH_KEY" ]] || [[ -z "$AUTH_CERT" && -n "$AUTH_KEY" ]]; then die "$EX_USAGE" "--auth-cert and --auth-key go together"; fi
if ((!SKIP_FORWARDER)) && [[ -z "$CLIENT_CERT" && $ISSUE_CERT -eq 0 ]]; then
  die "$EX_USAGE" "the forwarder needs a TLS client identity: --client-cert F --client-key F, or --issue-client-cert (or --skip-forwarder)"
fi

fc_rc=0
vs_failclosed_check || fc_rc=$?
if ((fc_rc != 0)); then exit "$fc_rc"; fi
if ((ALLOW_UNVERIFIED)); then
  case "$(vs_cfg CS3_PROFILE "")" in
    onprem|airgap) log_err "--allow-unverified-manager is refused under CS3_PROFILE=$(vs_cfg CS3_PROFILE "") (TLS verification is mandatory)"; exit "$EX_POLICY" ;;
  esac
  log_warn "manager certificate verification DISABLED (--allow-unverified-manager)"
fi

AGENT_AUTH=""
for cand in "$VENDETTA_HOME_DIR/bin/agent-auth" "$(command -v agent-auth 2>/dev/null || true)"; do
  if [[ -n "$cand" && -x "$cand" ]]; then AGENT_AUTH=$cand; break; fi
done
if [[ "$METHOD" == auto ]]; then
  if [[ -n "$AGENT_AUTH" ]]; then METHOD=agent-auth
  elif [[ -n "$PASSWORD_FILE" || $NO_PASSWORD -eq 1 ]]; then METHOD=authd
  else METHOD=api
  fi
fi
if [[ "$METHOD" == agent-auth && -z "$AGENT_AUTH" ]]; then die "$EX_PREREQ" "--method agent-auth: agent-auth not found in $VENDETTA_HOME_DIR/bin or PATH"; fi

# ---------------------------------------------------------------------------------------------------
# client.keys handling
# ---------------------------------------------------------------------------------------------------
KEY_RE='^[0-9]{3,8} [A-Za-z0-9._-]+ [^ ]+ [0-9a-fA-F]{64}$'

keys_entry_for() { # <name> → "<id>" when present
  [[ -f "$KEYS_FILE" ]] || return 1
  awk -v n="$1" '$2 == n {print $1; found=1; exit} END {exit found ? 0 : 1}' "$KEYS_FILE"
}

keys_write() { # <line> — replaces any entry with the same name or id, atomically (mode 0640)
  local line=$1 id name rest content=""
  id=${line%% *}; rest=${line#* }; name=${rest%% *}
  [[ "$line" =~ $KEY_RE ]] || { log_err "refusing to store a malformed agent key"; return 1; }
  mkdir -p "$(dirname "$KEYS_FILE")"
  if [[ -f "$KEYS_FILE" ]]; then
    content="$(awk -v n="$name" -v i="$id" '$2 != n && $1 != i' "$KEYS_FILE")"
    if [[ -n "$content" ]]; then content+=$'\n'; fi
    cp -p -- "$KEYS_FILE" "$KEYS_FILE.bak.$(vs_ts)" 2>/dev/null || true
  fi
  printf '%s%s\n' "$content" "$line" | vs_atomic_write "$KEYS_FILE" 0640
  if getent group ossec >/dev/null 2>&1; then chgrp ossec "$KEYS_FILE" 2>/dev/null || true; fi
  AGENT_ID=$id
}

decode_api_key() { # <data.key> <id> <name> → full "id name ip key" line on stdout
  local k=$1 id=$2 name=$3 dec
  if [[ "$k" =~ ^[0-9a-fA-F]{64}$ ]]; then printf '%s %s any %s' "$id" "$name" "$k"; return 0; fi
  dec="$(printf '%s' "$k" | base64 -d 2>/dev/null | tr -d '\n')" || return 1
  [[ "$dec" =~ $KEY_RE ]] || return 1
  printf '%s' "$dec"
}

set_manager_address() {
  local conf="$VENDETTA_HOME_DIR/etc/ossec.conf"
  [[ -f "$conf" ]] || { log_warn "$conf not found — set <server><address>$MANAGER</address> after installing the agent"; return 0; }
  if grep -q "<address>$MANAGER</address>" "$conf"; then log_ok "ossec.conf already points at $MANAGER"; return 0; fi
  cp -p -- "$conf" "$conf.bak.$(vs_ts)"
  # BSD sed has neither -i without a suffix nor the 0,/re/ address: rewrite the first matching line by number
  local n
  n="$(grep -n -m1 -o -E '<address>[^<]*</address>' "$conf" | cut -d: -f1)"
  if [[ -n "$n" ]]; then
    sed "${n}s|<address>[^<]*</address>|<address>$MANAGER</address>|" "$conf" >"$conf.new" && cat "$conf.new" >"$conf" && rm -f -- "$conf.new"
  fi
  log_ok "ossec.conf <server><address> set to $MANAGER"
}

# ---------------------------------------------------------------------------------------------------
# Enrollment methods
# ---------------------------------------------------------------------------------------------------
enroll_agent_auth() {
  local args rc=0 passdst="$VENDETTA_HOME_DIR/etc/authd.pass"
  args=(-m "$MANAGER" -p "$AUTHD_PORT" -A "$AGENT_NAME" -G "$GROUP")
  [[ "$AGENT_IP" == any ]] || args+=(-I "$AGENT_IP")
  if ((!ALLOW_UNVERIFIED)); then args+=(-v "$CA_FILE"); fi
  [[ -z "$AUTH_CERT" ]] || args+=(-x "$AUTH_CERT" -k "$AUTH_KEY")
  if ((!NO_PASSWORD)); then
    [[ -n "$PASSWORD_FILE" ]] || die "$EX_USAGE" "authd needs --password-file (or VENDETTA_AUTHD_PASSWORD_FILE), or --no-password when the manager does not require one"
    vs_read_secret "$PASSWORD_FILE" | vs_atomic_write "$passdst" 0640
  fi
  "$AGENT_AUTH" "${args[@]}" </dev/null >"$VS_WORK/agent-auth.out" 2>&1 || rc=$?
  if ((rc != 0)); then
    log_err "agent-auth failed (exit $rc): $(tail -n 3 "$VS_WORK/agent-auth.out" | tr '\n' ' ' | cut -c1-300)"
    return "$EX_NOTREADY"
  fi
  AGENT_ID="$(keys_entry_for "$AGENT_NAME")" || { log_err "agent-auth reported success but $KEYS_FILE has no entry for $AGENT_NAME"; return 1; }
}

enroll_authd() {
  local msg pw="" sargs resp rc=0 line
  if ((!NO_PASSWORD)); then
    [[ -n "$PASSWORD_FILE" ]] || die "$EX_USAGE" "authd needs --password-file (or VENDETTA_AUTHD_PASSWORD_FILE), or --no-password when the manager does not require one"
    pw="$(vs_read_secret "$PASSWORD_FILE")" || return 1
  fi
  msg="OSSEC A:'$AGENT_NAME'"
  if [[ "$GROUP" != default ]]; then msg+=" G:'$GROUP'"; fi
  if [[ "$AGENT_IP" != any ]]; then msg+=" IP:'$AGENT_IP'"; fi
  if [[ -n "$pw" ]]; then msg="OSSEC PASS: $pw $msg"; fi
  sargs=(-connect "$MANAGER:$AUTHD_PORT" -quiet)
  if [[ "$MANAGER" =~ ^[0-9.]+$ || "$MANAGER" == *:* ]]; then
    if ((!ALLOW_UNVERIFIED)); then sargs+=(-verify_ip "$MANAGER"); fi
  else
    sargs+=(-servername "$MANAGER")
    if ((!ALLOW_UNVERIFIED)); then sargs+=(-verify_hostname "$MANAGER"); fi
  fi
  if ((!ALLOW_UNVERIFIED)); then sargs+=(-verify_return_error -CAfile "$CA_FILE"); fi
  [[ -z "$AUTH_CERT" ]] || sargs+=(-cert "$AUTH_CERT" -key "$AUTH_KEY")
  resp="$(printf '%s\n' "$msg" | timeout 20 openssl s_client "${sargs[@]}" 2>"$VS_WORK/s_client.err")" || rc=$?
  unset pw msg
  if [[ "$resp" == *"OSSEC K:'"* ]]; then
    line="${resp#*OSSEC K:\'}"
    line="${line%%\'*}"
    keys_write "$line" || return 1
    return 0
  fi
  if [[ "$resp" == *ERROR* ]]; then
    log_err "authd refused the enrollment: $(printf '%s' "$resp" | tr '\n' ' ' | cut -c1-200)"
    if [[ "$resp" == *Duplicated* ]]; then log_err "the manager already holds an agent named $AGENT_NAME — remove it there or use --method api --force-reenroll"; fi
    return "$EX_NOTREADY"
  fi
  if ((!ALLOW_UNVERIFIED)) && grep -qi 'verify error\|certificate verify failed' "$VS_WORK/s_client.err" 2>/dev/null; then
    log_err "TLS verification of $MANAGER:$AUTHD_PORT failed against $CA_FILE — is the manager certificate issued by this CA with $MANAGER in its SAN?"
  else
    log_err "no usable answer from $MANAGER:$AUTHD_PORT (exit $rc): $(tr '\n' ' ' <"$VS_WORK/s_client.err" | cut -c1-200)"
  fi
  return "$EX_NOTREADY"
}

enroll_api() {
  local url="https://$MANAGER:$API_PORT" jwt rid key line existing rc
  [[ -r "$API_PASSWORD_FILE" ]] || die "$EX_USAGE" "API password file not readable: $API_PASSWORD_FILE"
  rc=0
  retry 3 2 vs_http POST "$url/security/user/authenticate?raw=true" --ca "$CA_FILE" --basic "$API_USER:$API_PASSWORD_FILE" --max-time 20 || rc=$?
  if ((rc != 0)); then
    log_err "manager API authentication failed (HTTP $VS_HTTP_CODE) at $url"
    return "$EX_NOTREADY"
  fi
  jwt=${VS_HTTP_BODY//[$'\r\n']/}
  printf '%s' "$jwt" | vs_atomic_write "$VS_WORK/jwt" 0600
  unset jwt
  vs_http GET "$url/agents?name=$AGENT_NAME&select=id" --ca "$CA_FILE" --bearer-file "$VS_WORK/jwt" --max-time 20 || true
  existing="$(jq -r '.data.affected_items[0].id // empty' <<<"$VS_HTTP_BODY" 2>/dev/null || true)"
  if [[ -n "$existing" ]]; then
    if ((!FORCE)); then
      log_err "agent $AGENT_NAME already exists on the manager (id $existing) but this host has no key — use --force-reenroll to replace it"
      return "$EX_NOTREADY"
    fi
    vs_http DELETE "$url/agents?agents_list=$existing&status=all&older_than=0s" --ca "$CA_FILE" --bearer-file "$VS_WORK/jwt" --max-time 30 \
      || { log_err "could not delete the stale manager-side agent $existing (HTTP $VS_HTTP_CODE)"; return 1; }
    log_info "deleted stale manager-side agent $existing"
  fi
  vs_http POST "$url/agents/insert" --ca "$CA_FILE" --bearer-file "$VS_WORK/jwt" --max-time 30 \
    --data "$(jq -cn --arg n "$AGENT_NAME" --arg ip "$AGENT_IP" '{name: $n, ip: $ip}')" \
    || { log_err "POST /agents/insert failed (HTTP $VS_HTTP_CODE: $(jq -r '.detail // .title // empty' <<<"$VS_HTTP_BODY" 2>/dev/null | cut -c1-200))"; return "$EX_NOTREADY"; }
  rid="$(jq -r '.data.id // empty' <<<"$VS_HTTP_BODY")"
  key="$(jq -r '.data.key // empty' <<<"$VS_HTTP_BODY")"
  [[ -n "$rid" && -n "$key" ]] || { log_err "manager API returned no agent id/key"; return 1; }
  line="$(decode_api_key "$key" "$rid" "$AGENT_NAME")" || { log_err "manager API returned an unrecognised key format"; return 1; }
  unset key
  keys_write "$line" || return 1
  if [[ "$GROUP" != default ]]; then
    vs_http PUT "$url/agents/$rid/group/$GROUP" --ca "$CA_FILE" --bearer-file "$VS_WORK/jwt" --max-time 20 \
      || log_warn "could not assign group $GROUP (HTTP $VS_HTTP_CODE) — create the group on the manager first"
  fi
}

do_enroll() {
  local existing rc=0
  log_step "enrollment: agent '$AGENT_NAME' → $MANAGER (method $METHOD, group $GROUP)"
  if existing="$(keys_entry_for "$AGENT_NAME")" && ((!FORCE)); then
    AGENT_ID=$existing
    ENROLL_STATE="already-enrolled"
    log_ok "already enrolled as id $existing in $KEYS_FILE — nothing to do (use --force-reenroll to replace)"
    return 0
  fi
  if ((VS_DRY_RUN)); then
    log_dry "would enroll via $METHOD against $MANAGER (authd $AUTHD_PORT / API $API_PORT), CA $CA_FILE, keys → $KEYS_FILE"
    ENROLL_STATE="dry-run"
    return 0
  fi
  if [[ "$METHOD" == api || ( "$METHOD" != agent-auth && $ALLOW_UNVERIFIED -eq 0 ) ]]; then
    [[ -r "$CA_FILE" ]] || die "$EX_USAGE" "CA certificate not readable: $CA_FILE (run scripts/bootstrap.sh or pass --ca)"
  fi
  mkdir -p "$VENDETTA_HOME_DIR/etc"
  case "$METHOD" in
    agent-auth) enroll_agent_auth || rc=$? ;;
    authd) enroll_authd || rc=$? ;;
    api) enroll_api || rc=$? ;;
  esac
  if ((rc != 0)); then exit "$rc"; fi
  ENROLL_STATE="enrolled"
  log_ok "enrolled as id $AGENT_ID (key stored in $KEYS_FILE, mode $(vs_file_mode "$KEYS_FILE"))"
  set_manager_address
  if [[ -n "$RESTART_SERVICE" ]]; then
    if vs_have systemctl; then run systemctl restart "$RESTART_SERVICE"; else log_warn "systemctl not available — restart $RESTART_SERVICE manually"; fi
  fi
}

# ---------------------------------------------------------------------------------------------------
# Edge forwarder
# ---------------------------------------------------------------------------------------------------
write_if_changed() { # <dest> <mode> — stdin → dest; reports unchanged/updated
  local dest=$1 mode=$2 new
  new="$(cat)"
  if [[ -f "$dest" ]] && [[ "$(<"$dest")" == "$new" ]] && [[ "$(vs_file_mode "$dest")" == "${mode#0}" ]]; then
    log_ok "$dest unchanged"
    return 0
  fi
  printf '%s\n' "$new" | vs_atomic_write "$dest" "$mode"
  log_ok "wrote $dest"
}

render_upstream() {
  local h host port
  printf '%s\n' "# Rendered by scripts/enroll-agent.sh — round-robin over the aggregation tier; a node that is down is skipped." \
    "[UPSTREAM]" "    Name       vendetta_aggregators"
  for h in "${FORWARD_HOSTS[@]}"; do
    host=${h%%:*}; port=24224
    if [[ "$h" == *:* ]]; then port=${h##*:}; fi
    printf '\n[NODE]\n    Name       %s\n    Host       %s\n    Port       %s\n    tls        on\n    tls.verify on\n    tls.vhost  %s\n' "$host" "$host" "$port" "$host"
    printf '    tls.ca_file  %s/pki/ca.crt\n    tls.crt_file %s/pki/client.crt\n    tls.key_file %s/pki/client.key\n' "$FORWARDER_DIR" "$FORWARDER_DIR" "$FORWARDER_DIR"
  done
}

render_fluent_bit() {
  cat <<EOF
# Rendered by scripts/enroll-agent.sh — Vendetta edge forwarder for agent '$AGENT_NAME'. Contains no secrets
# (the TLS client key lives in $FORWARDER_DIR/pki, mode 0600). Delivery is filesystem-buffered, at-least-once.
[SERVICE]
    Flush                     5
    Grace                     30
    Log_Level                 info
    storage.path              $BUFFER_DIR
    storage.sync              normal
    storage.checksum          on
    storage.backlog.mem_limit 64M
    HTTP_Server               On
    HTTP_Listen               127.0.0.1
    HTTP_Port                 2020
    Health_Check              On

[INPUT]
    Name                      tail
    Alias                     host_auth_tail
    Tag                       host.auth
    Path                      /var/log/auth.log,/var/log/secure
    Path_Key                  file
    DB                        $BUFFER_DIR/host-auth.db
    Skip_Long_Lines           On
    Mem_Buf_Limit             16MB
    storage.type              filesystem

[INPUT]
    Name                      tail
    Alias                     host_audit_tail
    Tag                       host.audit
    Path                      /var/log/audit/audit.log
    Path_Key                  file
    DB                        $BUFFER_DIR/host-audit.db
    Skip_Long_Lines           On
    Mem_Buf_Limit             16MB
    storage.type              filesystem
EOF
  if ((!NO_JOURNAL)); then
    cat <<EOF

[INPUT]
    Name                      systemd
    Alias                     host_journal
    Tag                       host.journal
    Read_From_Tail            On
    Strip_Underscores         On
    DB                        $BUFFER_DIR/host-journal.db
    storage.type              filesystem
EOF
  fi
  cat <<EOF

[FILTER]
    Name                      record_modifier
    Match                     host.*
    Record                    agent_name $AGENT_NAME
    Record                    agent_id ${AGENT_ID:-unenrolled}
    Record                    vendetta_group $GROUP

[OUTPUT]
    Name                      forward
    Alias                     vendetta_aggregators
    Match                     *
    Upstream                  $FORWARDER_DIR/upstream.conf
    Require_ack_response      On
    Compress                  gzip
    Retry_Limit               False
    net.connect_timeout       10
    net.keepalive             on
    storage.total_limit_size  2G
EOF
}

render_unit() {
  cat <<EOF
[Unit]
Description=Vendetta edge forwarder (Fluent Bit) for $AGENT_NAME
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$FB_BIN -c $FORWARDER_DIR/fluent-bit.conf
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$BUFFER_DIR
ReadOnlyPaths=/var/log $FORWARDER_DIR

[Install]
WantedBy=multi-user.target
EOF
}

do_forwarder() {
  local src_crt src_key work=$VS_WORK
  log_step "edge forwarder → $(vs_join , "${FORWARD_HOSTS[@]}") (TLS on, verify on) in $FORWARDER_DIR"
  [[ -r "$CA_FILE" ]] || die "$EX_USAGE" "CA certificate not readable: $CA_FILE"
  if [[ -z "$FB_BIN" ]]; then
    for cand in /opt/fluent-bit/bin/fluent-bit "$(command -v fluent-bit 2>/dev/null || true)"; do
      if [[ -n "$cand" && -x "$cand" ]]; then FB_BIN=$cand; break; fi
    done
  fi
  if ((INSTALL_SYSTEMD)) && [[ -z "$FB_BIN" ]]; then die "$EX_PREREQ" "--install-systemd: Fluent Bit binary not found (install it or pass --fluent-bit-bin)"; fi
  if [[ -z "$FB_BIN" ]]; then log_warn "Fluent Bit binary not found — configuration is rendered but cannot be syntax-checked"; fi

  if ((VS_DRY_RUN)); then
    log_dry "would write $FORWARDER_DIR/{fluent-bit.conf,upstream.conf,pki/ca.crt,pki/client.crt,pki/client.key}$([[ $INSTALL_SYSTEMD -eq 1 ]] && echo ' and the vendetta-edge-forwarder.service unit')"
    if ((ISSUE_CERT)); then log_dry "would issue a client certificate CN=$AGENT_NAME (clientAuth) from $PKI_DIR/ca.key"; fi
    if ((VS_VERBOSE)); then render_fluent_bit >&2; render_upstream >&2; fi
    return 0
  fi

  (umask 022; mkdir -p "$FORWARDER_DIR")
  (umask 077; mkdir -p "$FORWARDER_DIR/pki" "$BUFFER_DIR")
  chmod 0700 "$FORWARDER_DIR/pki"
  if ((ISSUE_CERT)); then
    if [[ -s "$FORWARDER_DIR/pki/client.crt" && -s "$FORWARDER_DIR/pki/client.key" ]] \
      && [[ "$(pki_cert_days_left "$FORWARDER_DIR/pki/client.crt")" -ge "$PKI_RENEW_DAYS" ]] \
      && openssl verify -CAfile "$CA_FILE" "$FORWARDER_DIR/pki/client.crt" >/dev/null 2>&1 \
      && pki_key_matches "$FORWARDER_DIR/pki/client.crt" "$FORWARDER_DIR/pki/client.key"; then
      log_ok "client certificate for $AGENT_NAME still valid — kept"
    else
      pki_validate_config
      pki_issue_leaf "$AGENT_NAME" "$work/client.crt" "$work/client.key" clientAuth
      install -m 0644 "$work/client.crt" "$FORWARDER_DIR/pki/client.crt"
      install -m 0600 "$work/client.key" "$FORWARDER_DIR/pki/client.key"
      log_ok "issued client certificate CN=$AGENT_NAME ($(pki_cert_days_left "$FORWARDER_DIR/pki/client.crt") days)"
    fi
  else
    [[ -r "$CLIENT_CERT" && -r "$CLIENT_KEY" ]] || die "$EX_USAGE" "client certificate/key not readable"
    pki_key_matches "$CLIENT_CERT" "$CLIENT_KEY" || die "$EX_USAGE" "--client-key does not match --client-cert"
    src_crt=$CLIENT_CERT; src_key=$CLIENT_KEY
    if ! cmp -s "$src_crt" "$FORWARDER_DIR/pki/client.crt" 2>/dev/null; then install -m 0644 "$src_crt" "$FORWARDER_DIR/pki/client.crt"; fi
    if ! cmp -s "$src_key" "$FORWARDER_DIR/pki/client.key" 2>/dev/null; then install -m 0600 "$src_key" "$FORWARDER_DIR/pki/client.key"; fi
  fi
  if ! cmp -s "$CA_FILE" "$FORWARDER_DIR/pki/ca.crt" 2>/dev/null; then install -m 0644 "$CA_FILE" "$FORWARDER_DIR/pki/ca.crt"; fi
  chmod 0600 "$FORWARDER_DIR/pki/client.key"

  render_upstream | write_if_changed "$FORWARDER_DIR/upstream.conf" 0644
  render_fluent_bit | write_if_changed "$FORWARDER_DIR/fluent-bit.conf" 0644
  if [[ -n "$FB_BIN" ]]; then
    if "$FB_BIN" --dry-run -c "$FORWARDER_DIR/fluent-bit.conf" >"$work/fb-check.out" 2>&1; then
      log_ok "Fluent Bit accepted the rendered configuration (--dry-run)"
    else
      log_err "Fluent Bit rejected the rendered configuration: $(tail -n 3 "$work/fb-check.out" | tr '\n' ' ' | cut -c1-300)"
      exit "$EX_FAIL"
    fi
  fi
  if ((INSTALL_SYSTEMD)); then
    vs_have systemctl || die "$EX_PREREQ" "--install-systemd needs systemd"
    render_unit | write_if_changed /etc/systemd/system/vendetta-edge-forwarder.service 0644
    systemctl daemon-reload
    systemctl enable --now vendetta-edge-forwarder.service
    systemctl is-active --quiet vendetta-edge-forwarder.service || die "$EX_FAIL" "vendetta-edge-forwarder.service did not start (journalctl -u vendetta-edge-forwarder)"
    log_ok "vendetta-edge-forwarder.service active"
  fi
}

# ---------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------
vs_mkwork enroll-agent
if ((!SKIP_ENROLL)); then do_enroll; fi
if ((!SKIP_FORWARDER)); then do_forwarder; fi

log_info "next steps: restart the agent (systemctl restart <vendetta-agent service>), then confirm on the manager: agent_control -l | GET /agents?name=$AGENT_NAME"
log_info "           and verify alerts/logs arrive: scripts/healthcheck.sh; edge buffer health: curl -s http://127.0.0.1:2020/api/v1/health"
printf 'agent: name=%s id=%s enrollment=%s method=%s forwarder=%s\n' "$AGENT_NAME" "${AGENT_ID:-n/a}" "$ENROLL_STATE" "$METHOD" "$([[ $SKIP_FORWARDER -eq 1 ]] && echo skipped || echo "$FORWARDER_DIR")"
exit "$EX_OK"
