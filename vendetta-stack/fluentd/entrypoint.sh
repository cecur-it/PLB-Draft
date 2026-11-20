#!/usr/bin/env bash
# Traces: PROMPT §1 Tier 2 (Fluentd aggregation), §6 Closed-loop, CONTRACT §5, §8.3, §8.11, §13
# Container entrypoint of vendetta-stack/fluentd: validates the environment, renders the optional legs into enabled.d/, prepares the
# buffer / dead-letter / dry-run directories, validates the whole tree with `fluentd --dry-run` and then execs fluentd.
# Idempotent: enabled.d/ is rebuilt from scratch on every start, directories are created only when absent.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR
trap 'log "terminated by signal"; exit 143' TERM INT

usage() {
  cat <<'EOF'
Usage: cs3-fluentd-entrypoint [--check | --help] [fluentd [fluentd-args...]]
  (no args)      render + validate + exec fluentd with the default config (FLUENTD_CONF, default fluent.conf)
  --check        render + `fluentd --dry-run`, then exit 0 (used by tests/validate.sh and CI)
Environment (full list in RUNTIME.md):
  FLUENTD_NODE_ID 1|2 (or derived from a hostname ending in fluentd-1 / fluentd-2)
  CS3_AGGREGATOR_LEGS  comma list of esoc,siem (default empty)        ERROW_CLOUD_ENABLED  true|false (default false)
  ERROW_FEEDBACK_LIVE  true|false (default false)                     FLUENTD_WAIT_SEC  seconds to wait for /pki + secrets (60)
  VENDETTA_JWT_ATTEMPTS / VENDETTA_JWT_RETRY_SEC  manager pre-flight retries when ERROW_FEEDBACK_LIVE=true (6 / 5)
  FLUENTD_CONF         fluent.conf (aggregator) or edge/forwarder.conf (edge Fluentd)
EOF
}

log() { printf '%s [cs3-fluentd-entrypoint] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

retry() { # retry <attempts> <delay-seconds> <command...>
  local n=$1 d=$2 i
  shift 2
  for ((i = 1; i <= n; i++)); do
    if "$@"; then return 0; fi
    ((i < n)) && { log "attempt $i/$n failed: $*; retrying in ${d}s"; sleep "$d"; }
  done
  return 1
}

readable_file() { [[ -f $1 && -r $1 && -s $1 ]]; }

wait_for_files() { # wait_for_files <file...>: poll until all exist and are non-empty
  local f deadline=$((SECONDS + ${FLUENTD_WAIT_SEC:-60}))
  for f in "$@"; do
    until readable_file "$f"; do
      ((SECONDS < deadline)) || die "required file missing or empty after ${FLUENTD_WAIT_SEC:-60}s: $f"
      sleep 2
    done
  done
}

is_true() { [[ ${1:-} == true || ${1:-} == 1 || ${1:-} == yes ]]; }

node_id() {
  local id=${FLUENTD_NODE_ID:-}
  if [[ -z $id || ! $id =~ ^[12]$ ]]; then
    if [[ "$(hostname)" =~ fluentd-([12])(-[0-9]+)?$ ]]; then id=${BASH_REMATCH[1]}; fi
  fi
  [[ $id =~ ^[12]$ ]] || die "FLUENTD_NODE_ID must be 1 or 2 (got '${FLUENTD_NODE_ID:-}')"
  printf '%s' "$id"
}

mint_jwt() { # POST /security/user/authenticate?raw=true -> atomic write of $jwt_file
  ruby -rnet/http -ruri -ropenssl - "${VENDETTA_API_URL%/}" "${VENDETTA_API_USER:-wazuh-wui}" "${VENDETTA_API_PASSWORD_FILE:-/run/secrets/vendetta_api_password}" \
    "${VENDETTA_API_CA_FILE:-/pki/ca.crt}" "$jwt_file" <<'RUBY'
url, user, pwfile, ca, out = ARGV
uri = URI.join(url + '/', 'security/user/authenticate?raw=true')
req = Net::HTTP::Post.new(uri)
req.basic_auth(user, File.read(pwfile).strip)
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = uri.scheme == 'https'
if http.use_ssl?
  http.ca_file = ca
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
end
http.open_timeout = 5
http.read_timeout = 15
res = http.request(req)
abort "authenticate failed: HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess) && !res.body.to_s.strip.empty?
File.write("#{out}.tmp", res.body.strip, perm: 0o600)
File.rename("#{out}.tmp", out)
RUBY
}

render_enabled() {
  local etc=$1 legs=",${CS3_AGGREGATOR_LEGS:-},"
  local opt=$etc/optional dst=$etc/enabled.d
  legs=${legs// /}
  mkdir -p "$dst"
  rm -f "$dst"/*.conf
  printf '# Traces: CONTRACT §8.3 - keeps the enabled.d glob non-empty\n' >"$dst/00-noop.conf"

  local leg
  for leg in $(tr ',' '\n' <<<"${CS3_AGGREGATOR_LEGS:-}" | tr -d ' '); do
    [[ -z $leg || $leg == esoc || $leg == siem ]] || die "CS3_AGGREGATOR_LEGS: unknown leg '$leg' (allowed: esoc, siem)"
  done

  if [[ $legs == *,esoc,* ]]; then
    : "${CS3_ESOC_URL:?CS3_ESOC_URL is required when CS3_AGGREGATOR_LEGS contains esoc}"
    export CS3_ESOC_URL
    cp "$opt/esoc.conf" "$dst/10-esoc.conf"
  else cp "$opt/esoc-null.conf" "$dst/10-esoc.conf"; fi

  if [[ $legs == *,siem,* ]]; then
    : "${CS3_SIEM_URL:?CS3_SIEM_URL is required when CS3_AGGREGATOR_LEGS contains siem}"
    export CS3_SIEM_URL
    cp "$opt/siem.conf" "$dst/20-siem.conf"
  else cp "$opt/siem-null.conf" "$dst/20-siem.conf"; fi

  if is_true "${ERROW_CLOUD_ENABLED:-false}"; then
    export ERROW_CLOUD_URL=${ERROW_CLOUD_URL:-https://app.errow.ai}
    wait_for_files "${ERROW_CLOUD_TOKEN_FILE:-/run/secrets/errow_api_token}"
    cp "$opt/errow-cloud.conf" "$dst/30-errow-cloud.conf"
  else cp "$opt/errow-cloud-null.conf" "$dst/30-errow-cloud.conf"; fi

  if is_true "${ERROW_FEEDBACK_LIVE:-false}"; then
    export VENDETTA_API_URL=${VENDETTA_API_URL:-https://vendetta-manager:55000}
    # Pre-flight only: the live execd leg posts to the errow-feedback gate (POST /approved-action), which owns the manager
    # credential and the APPROVALS.md check. Minting here proves the manager is reachable and the credential works before the
    # first finding, so a misconfigured live stack fails at boot instead of dead-lettering every action.
    jwt_file=/run/fluentd/vendetta.jwt
    wait_for_files "${VENDETTA_API_PASSWORD_FILE:-/run/secrets/vendetta_api_password}" "${VENDETTA_API_CA_FILE:-/pki/ca.crt}"
    retry "${VENDETTA_JWT_ATTEMPTS:-6}" "${VENDETTA_JWT_RETRY_SEC:-5}" mint_jwt || die "could not obtain a Vendetta API JWT from ${VENDETTA_API_URL} (ERROW_FEEDBACK_LIVE=true refuses to start without it)"
    [[ -n ${VENDETTA_EXECD_AGENT_REGEX:-} ]] || log "WARN ERROW_FEEDBACK_LIVE=true but VENDETTA_EXECD_AGENT_REGEX is empty: no finding will be delivered (allow-list is empty)"
    : "${ERROW_FEEDBACK_URL:=http://errow-feedback:9102/errow-finding}"
    export ERROW_FEEDBACK_URL
    cp "$opt/vendetta-execd-live.conf" "$dst/40-vendetta-execd.conf"
  else cp "$opt/vendetta-execd-dry-run.conf" "$dst/40-vendetta-execd.conf"; fi
  log "enabled.d: $(find "$dst" -name '*.conf' -printf '%f ' | tr -s ' ')"
}

prepare_dirs() {
  mkdir -p /var/log/fluentd/buffer /var/log/fluentd/dead-letter /var/log/fluentd/dry-run /run/fluentd
  chmod 0700 /var/log/fluentd/buffer /var/log/fluentd/dead-letter /var/log/fluentd/dry-run
  # Log rotation: Fluentd's own log goes to stdout (rotate with the container log driver); dead-letter files are sliced per minute
  # (only minutes that had events), dry-run files per day (timekey), and both are pruned here.
  find /var/log/fluentd/dead-letter -type f -mtime "+${FLUENTD_DEADLETTER_RETENTION_DAYS:-14}" -delete 2>/dev/null || true
  find /var/log/fluentd/dry-run -type f -mtime "+${FLUENTD_DRYRUN_RETENTION_DAYS:-14}" -delete 2>/dev/null || true
}

main() {
  local check=false
  case "${1:-}" in
    -h | --help) usage; exit 0 ;;
    --check) check=true; shift ;;
    *) ;;
  esac
  if [[ $# -gt 0 && ${1#-} != "$1" ]]; then set -- fluentd "$@"; fi
  [[ $# -gt 0 ]] || set -- fluentd
  [[ $1 == fluentd ]] || exec "$@"

  local etc=${FLUENTD_ETC:-/fluentd/etc} conf=${FLUENTD_CONF:-fluent.conf} mode=aggregator
  [[ $conf == edge/* ]] && mode=edge
  prepare_dirs
  if [[ " ${args[*]:-} " != *" -c "* && " ${args[*]:-} " != *" --config "* ]]; then args+=(-c "$etc/$conf"); fi
  args+=(-p /fluentd/plugins)

  if [[ $mode == aggregator ]]; then
    local id
    id=$(node_id)
    export FLUENTD_NODE_ID=$id
    wait_for_files /pki/ca.crt "/pki/fluentd-$id.crt" "/pki/fluentd-$id.key" \
      /run/secrets/opensearch_admin_password /run/secrets/llm_gateway_token /run/secrets/feedback_webhook_token
    render_enabled "$etc"
    log "node=$id mode=aggregator legs='${CS3_AGGREGATOR_LEGS:-}' errow_cloud=${ERROW_CLOUD_ENABLED:-false} feedback_live=${ERROW_FEEDBACK_LIVE:-false}"
  else
    wait_for_files /pki/ca.crt "${EDGE_CLIENT_CERT:-/pki/fluent-bit.crt}" "${EDGE_CLIENT_KEY:-/pki/fluent-bit.key}"
    log "mode=edge conf=$conf"
  fi

  retry 2 3 fluentd --dry-run "${args[@]}" >/dev/null || { fluentd --dry-run "${args[@]}" >&2 || true; die "fluentd --dry-run rejected the configuration"; }
  log "configuration valid"
  if [[ $check == true ]]; then exit 0; fi

  if [[ $mode == aggregator ]] && is_true "${ERROW_FEEDBACK_LIVE:-false}"; then
    local parent=$$
    (
      trap 'exit 0' TERM INT
      while kill -0 "$parent" 2>/dev/null; do
        sleep "${VENDETTA_JWT_REFRESH_SEC:-600}" &
        wait $! || true
        mint_jwt || echo "[cs3-fluentd-entrypoint] WARN JWT refresh failed; the previous token stays in use" >&2
      done
    ) &
  fi
  trap - TERM INT
  exec fluentd "${args[@]}"
}

main "$@"
