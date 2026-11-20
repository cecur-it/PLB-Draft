#!/usr/bin/env bash
# Cecur CS3 — Linux forwarder installer (Fluent Bit + systemd + watchdog timer).
#
# Usage (as root):
#   CS3_ENROLL_TOKEN=<one-time token> ./install-forwarder.sh \
#       --console-url https://cs3.example.internal --agent-id <agentId> \
#       [--ca-file ./internal-ca.pem] [--client-cert agent.crt --client-key agent.key] [--pin-sha256 <base64 spki hash>] \
#       [--fluent-bit-pkg ./fluent-bit_3.x_amd64.deb --fluent-bit-sha256 <hex>] [--dry-run]
#   ./install-forwarder.sh --uninstall
#
# Gateway profile (OTLP listener + ESOC/SIEM egress + AI tier; operations/fluent-telemetry-fabric.md):
#   add --profile gateway and any of
#   [--otlp-listen ADDR] [--otlp-port N] [--otlp-cert F --otlp-key F --otlp-client-ca F]   OTLP listener (mTLS; mandatory off-loopback)
#   [--esoc-host H] [--esoc-port N] --esoc-cert F --esoc-key F [--esoc-ca F]               OTLP/gRPC mTLS egress to the ESOC
#   [--siem-url https://H[:P]/path] [--siem-auth-scheme S] [--siem-format F] [--siem-ca F] [--siem-proxy URL]   SIEM over HTTPS
#   [--ai-tier]                                                                           node runs Ollama (Nemotron/Gemma)
#   The SIEM credential is read from CS3_SIEM_TOKEN or --siem-token-file, never from argv.
#
# The enrollment token is single use; it is read from CS3_ENROLL_TOKEN or --token-file, never
# from argv (which is visible in `ps`). Re-running without a token keeps the existing credentials.
set -euo pipefail
umask 077

readonly CONF_DIR=/etc/cecur
readonly DATA_DIR=/var/lib/cecur-forwarder
readonly ENV_FILE="$CONF_DIR/forwarder.env"
readonly FB_BIN=/opt/fluent-bit/bin/fluent-bit
readonly FRAG_DIR="$CONF_DIR/fluent-bit.d"
readonly DROPIN_DIR=/etc/systemd/system/cecur-forwarder.service.d
readonly GATEWAY_FRAGS=(10-otlp-input.conf 10-otlp-input-mtls.conf 20-normalize.conf 30-heartbeat.conf 40-esoc-otlp.conf 50-siem-http.conf 60-ai-tier.conf cs3-otlp-normalize.lua)
readonly GATEWAY_PKI=("$CONF_DIR"/pki/{otlp-server.crt,otlp-server.key,otlp-client-ca.pem,esoc-client.crt,esoc-client.key,esoc-ca.pem,siem-ca.pem})
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

console_url="${CS3_URL:-}"; agent_id=""; token_file=""; ca_file=""; pin=""
client_cert=""; client_key=""; fb_pkg=""; fb_sha=""; dry_run=0; uninstall=0
profile=edge; ai_tier=0
otlp_listen=""; otlp_port=""; otlp_cert=""; otlp_key=""; otlp_client_ca=""
esoc_host=""; esoc_port=""; esoc_cert=""; esoc_key=""; esoc_ca=""
siem_url=""; siem_token_file=""; siem_scheme=""; siem_format=""; siem_ca=""; siem_proxy=""

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[cecur-forwarder] $*" >&2; }
run() { if ((dry_run)); then echo "DRY-RUN: $*" >&2; else "$@"; fi; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
env_get() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -n 1 | tr -d "'"; }
# Remove only what the gateway profile installed; operator-added fragments and drop-ins are left alone.
remove_gateway_files() {
  local f
  for f in "${GATEWAY_FRAGS[@]}"; do run rm -f "$FRAG_DIR/$f"; done
  run rm -f "${GATEWAY_PKI[@]}" "$DROPIN_DIR/10-gateway.conf"
  if ((! dry_run)); then rmdir "$FRAG_DIR" "$DROPIN_DIR" 2>/dev/null || true; fi
}

while (($#)); do
  case "$1" in
    --console-url) console_url="${2:?}"; shift 2 ;;
    --agent-id) agent_id="${2:?}"; shift 2 ;;
    --token-file) token_file="${2:?}"; shift 2 ;;
    --ca-file) ca_file="${2:?}"; shift 2 ;;
    --client-cert) client_cert="${2:?}"; shift 2 ;;
    --client-key) client_key="${2:?}"; shift 2 ;;
    --pin-sha256) pin="${2:?}"; shift 2 ;;
    --fluent-bit-pkg) fb_pkg="${2:?}"; shift 2 ;;
    --fluent-bit-sha256) fb_sha="${2:?}"; shift 2 ;;
    --profile) profile="${2:?}"; shift 2 ;;
    --otlp-listen) otlp_listen="${2:?}"; shift 2 ;;
    --otlp-port) otlp_port="${2:?}"; shift 2 ;;
    --otlp-cert) otlp_cert="${2:?}"; shift 2 ;;
    --otlp-key) otlp_key="${2:?}"; shift 2 ;;
    --otlp-client-ca) otlp_client_ca="${2:?}"; shift 2 ;;
    --esoc-host) esoc_host="${2:?}"; shift 2 ;;
    --esoc-port) esoc_port="${2:?}"; shift 2 ;;
    --esoc-cert) esoc_cert="${2:?}"; shift 2 ;;
    --esoc-key) esoc_key="${2:?}"; shift 2 ;;
    --esoc-ca) esoc_ca="${2:?}"; shift 2 ;;
    --siem-url) siem_url="${2:?}"; shift 2 ;;
    --siem-token-file) siem_token_file="${2:?}"; shift 2 ;;
    --siem-auth-scheme) siem_scheme="${2:?}"; shift 2 ;;
    --siem-format) siem_format="${2:?}"; shift 2 ;;
    --siem-ca) siem_ca="${2:?}"; shift 2 ;;
    --siem-proxy) siem_proxy="${2:?}"; shift 2 ;;
    --ai-tier) ai_tier=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    -h|--help) sed -n '2,/^set -/{/^set -/!p}' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
command -v systemctl >/dev/null || die "systemd is required"

if ((uninstall)); then
  log "uninstalling"
  for u in cecur-forwarder-watchdog.timer cecur-forwarder-watchdog.service cecur-forwarder.service; do
    systemctl disable --now "$u" 2>/dev/null || true
  done
  rm -f /etc/systemd/system/cecur-forwarder*.service /etc/systemd/system/cecur-forwarder-watchdog.timer \
        /usr/local/sbin/cs3-forwarder-watchdog.sh
  rm -f "$DROPIN_DIR/10-gateway.conf"; rmdir "$DROPIN_DIR" 2>/dev/null || true
  systemctl daemon-reload
  rm -rf "$CONF_DIR" "$DATA_DIR"
  log "removed (Fluent Bit package left in place)"
  exit 0
fi

[[ -n "$console_url" ]] || die "--console-url (or CS3_URL) is required"
[[ "$console_url" =~ ^https://([A-Za-z0-9.-]+)(:([0-9]{1,5}))?/?$ ]] \
  || die "console URL must look like https://host[:port] (plaintext HTTP is refused)"
cs3_host="${BASH_REMATCH[1]}"; cs3_port="${BASH_REMATCH[3]:-443}"
base="https://${cs3_host}:${cs3_port}"
[[ -z "$pin" || "$pin" =~ ^[A-Za-z0-9+/=]{44}$ ]] || die "--pin-sha256 must be a base64 SHA-256 SPKI hash (44 chars)"

# ---- gateway profile validation (before anything is installed) ------------------------------------
[[ "$profile" == edge || "$profile" == gateway ]] || die "--profile must be 'edge' or 'gateway'"
siem_token=""; siem_host=""; siem_port=""; siem_uri=""
if [[ "$profile" == edge ]]; then
  [[ -z "$otlp_listen$otlp_port$otlp_cert$otlp_key$otlp_client_ca$esoc_host$esoc_port$esoc_cert$esoc_key$esoc_ca$siem_url$siem_token_file$siem_scheme$siem_format$siem_ca$siem_proxy" && $ai_tier -eq 0 ]] \
    || die "OTLP/ESOC/SIEM/AI-tier options require --profile gateway"
else
  otlp_listen="${otlp_listen:-127.0.0.1}"; otlp_port="${otlp_port:-4318}"
  [[ "$otlp_listen" =~ ^[A-Za-z0-9.:-]+$ ]] || die "invalid --otlp-listen"
  valid_port "$otlp_port" || die "invalid --otlp-port"
  if [[ -n "$otlp_cert$otlp_key$otlp_client_ca" ]]; then
    [[ -n "$otlp_cert" && -n "$otlp_key" && -n "$otlp_client_ca" ]] \
      || die "--otlp-cert, --otlp-key and --otlp-client-ca must be given together"
    [[ -r "$otlp_cert" && -r "$otlp_key" && -r "$otlp_client_ca" ]] || die "OTLP listener certificate material not readable"
  elif [[ ! "$otlp_listen" =~ ^(127\.[0-9.]+|::1|localhost)$ ]]; then
    die "OTLP listener on $otlp_listen is reachable off-host: mutual TLS is mandatory (--otlp-cert/--otlp-key/--otlp-client-ca)"
  fi

  if [[ -n "$esoc_host" ]]; then
    esoc_port="${esoc_port:-4317}"
    [[ "$esoc_host" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid --esoc-host"
    valid_port "$esoc_port" || die "invalid --esoc-port"
    [[ -n "$esoc_cert" && -n "$esoc_key" ]] || die "ESOC egress requires a client certificate: --esoc-cert and --esoc-key (mTLS is not optional)"
    [[ -r "$esoc_cert" && -r "$esoc_key" ]] || die "ESOC client certificate/key not readable"
    [[ -z "$esoc_ca" || -r "$esoc_ca" ]] || die "cannot read ESOC CA file $esoc_ca"
  else
    [[ -z "$esoc_port$esoc_cert$esoc_key$esoc_ca" ]] || die "--esoc-* options need --esoc-host"
  fi

  if [[ -n "$siem_url" ]]; then
    siem_url_re='^https://([A-Za-z0-9.-]+)(:([0-9]{1,5}))?(/[A-Za-z0-9._~%/@:+,;=?&-]*)?$'
    [[ "$siem_url" =~ $siem_url_re ]] \
      || die "--siem-url must look like https://host[:port][/path] (plaintext HTTP is refused)"
    siem_host="${BASH_REMATCH[1]}"; siem_port="${BASH_REMATCH[3]:-443}"; siem_uri="${BASH_REMATCH[4]:-/}"
    valid_port "$siem_port" || die "invalid port in --siem-url"
    siem_scheme="${siem_scheme:-Bearer}"; siem_format="${siem_format:-json_lines}"
    [[ "$siem_scheme" =~ ^[A-Za-z][A-Za-z0-9-]{0,31}$ ]] || die "invalid --siem-auth-scheme"
    [[ "$siem_format" == json || "$siem_format" == json_lines || "$siem_format" == json_stream ]] \
      || die "--siem-format must be json, json_lines or json_stream"
    [[ -z "$siem_ca" || -r "$siem_ca" ]] || die "cannot read SIEM CA file $siem_ca"
    [[ -z "$siem_proxy" || "$siem_proxy" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || die "--siem-proxy must look like http://host:port"
    # Credential: env or file (never argv); an existing one is kept when re-running.
    siem_token="${CS3_SIEM_TOKEN:-}"
    [[ -z "$siem_token" && -n "$siem_token_file" ]] && siem_token="$(tr -d '\r\n' < "$siem_token_file")"
    [[ -n "$siem_token" ]] || siem_token="$(env_get CS3_SIEM_TOKEN)"
    [[ "$siem_token" =~ ^[A-Za-z0-9._~+/=:-]{8,512}$ ]] \
      || die "SIEM credential missing or malformed (set CS3_SIEM_TOKEN or --siem-token-file)"
  else
    [[ -z "$siem_token_file$siem_scheme$siem_format$siem_ca$siem_proxy" ]] || die "--siem-* options need --siem-url"
  fi
fi

install -d -m 0750 "$CONF_DIR" "$DATA_DIR" "$DATA_DIR/buffer"
install -d -m 0750 "$CONF_DIR/pki"
[[ -z "$client_cert" && -z "$client_key" ]] || [[ -n "$client_cert" && -n "$client_key" ]] \
  || die "--client-cert and --client-key must be given together"
if [[ -n "$client_cert" ]]; then
  [[ -r "$client_cert" && -r "$client_key" ]] || die "client certificate/key not readable"
  run install -m 0644 "$client_cert" "$CONF_DIR/pki/agent.crt"
  run install -m 0600 "$client_key" "$CONF_DIR/pki/agent.key"
fi
if [[ -n "$ca_file" ]]; then
  [[ -r "$ca_file" ]] || die "cannot read CA file $ca_file"
  run install -m 0644 "$ca_file" "$CONF_DIR/pki/ca.pem"
fi
ca_path="$CONF_DIR/pki/ca.pem"
[[ -s "$ca_path" ]] || ca_path=/etc/ssl/certs/ca-certificates.crt   # fall back to the system trust store

# ---- 1. Fluent Bit ------------------------------------------------------------------------------
if [[ ! -x "$FB_BIN" ]]; then
  if [[ -n "$fb_pkg" ]]; then
    [[ -r "$fb_pkg" ]] || die "cannot read $fb_pkg"
    if [[ -n "$fb_sha" ]]; then
      echo "$fb_sha  $fb_pkg" | sha256sum --check --status || die "Fluent Bit package checksum mismatch"
    else
      log "WARNING: --fluent-bit-sha256 not given; package integrity is not verified"
    fi
    if command -v dpkg >/dev/null; then run dpkg -i "$fb_pkg"
    elif command -v rpm >/dev/null; then run rpm -Uvh "$fb_pkg"
    else die "no dpkg/rpm available to install $fb_pkg"; fi
  elif command -v apt-get >/dev/null && apt-cache policy fluent-bit 2>/dev/null | grep -q Candidate; then
    run apt-get install -y fluent-bit
  elif command -v dnf >/dev/null && dnf -q list available fluent-bit >/dev/null 2>&1; then
    run dnf install -y fluent-bit
  else
    die "Fluent Bit is not installed and no package source is configured. Provide --fluent-bit-pkg (air-gapped) or mirror the Fluent Bit repo internally."
  fi
  # Package units may auto-enable the stock service; we run our own instance.
  run systemctl disable --now fluent-bit.service 2>/dev/null || true
fi

# ---- 2. Enrollment (one-time token -> per-agent ingest key) -------------------------------------
token="${CS3_ENROLL_TOKEN:-}"
[[ -z "$token" && -n "$token_file" ]] && token="$(tr -d '\r\n' < "$token_file")"

if [[ -n "$token" ]]; then
  [[ -n "$agent_id" ]] || die "--agent-id is required when enrolling"
  [[ "$agent_id" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "invalid agent id"
  [[ "$token" =~ ^[A-Za-z0-9._~+/=-]{8,128}$ ]] || die "enrollment token has unexpected characters"
  log "claiming enrollment for $agent_id"
  curl_args=(-fsS --max-time 30 --proto '=https' --tlsv1.2 -X POST -H 'Content-Type: application/json' --data @-)
  [[ -s "$CONF_DIR/pki/ca.pem" ]] && curl_args+=(--cacert "$CONF_DIR/pki/ca.pem")
  [[ -n "$pin" ]] && curl_args+=(--pinnedpubkey "sha256//$pin")
  if ((dry_run)); then
    log "DRY-RUN: would POST $base/api/fleet/enroll/claim"
    ingest_key="dry-run"
  else
    # Token goes via stdin (not argv) so it never appears in the process list.
    resp="$(printf '{"agentId":"%s","token":"%s"}' "$agent_id" "$token" \
      | curl "${curl_args[@]}" "$base/api/fleet/enroll/claim")" || die "enrollment claim failed (expired/used token, TLS trust or pin mismatch?)"
    ingest_key="$(printf '%s' "$resp" | sed -n 's/.*"ingestKey" *: *"\([A-Za-z0-9._~-]*\)".*/\1/p')"
    [[ -n "$ingest_key" ]] || die "console response did not include an ingest key"
  fi
  unset token
  {
    echo "CS3_HOST=$cs3_host"
    echo "CS3_PORT=$cs3_port"
    echo "CS3_AGENT_ID=$agent_id"
    echo "CS3_HOSTNAME=$(hostname -f 2>/dev/null || hostname)"
    echo "CS3_INGEST_KEY=$ingest_key"
    echo "CS3_CA_FILE=$ca_path"
    echo "CS3_PIN_SHA256=$pin"
  } > "$ENV_FILE.new"
  run chmod 0600 "$ENV_FILE.new"
  run mv -f "$ENV_FILE.new" "$ENV_FILE"
elif [[ -s "$ENV_FILE" ]]; then
  log "no token supplied; keeping existing credentials in $ENV_FILE"
else
  die "no enrollment token (CS3_ENROLL_TOKEN / --token-file) and no existing credentials"
fi

# ---- 2b. Gateway variables (forwarder.env) -------------------------------------------------------
# Regenerated on every run from the flags; operator-tuned cadence values are preserved.
write_gateway_env() {
  if ((dry_run)); then log "DRY-RUN: would write $profile-profile variables to $ENV_FILE"; return 0; fi
  local tmp="$ENV_FILE.gw" hb scrape maxc
  hb="$(env_get CS3_HEARTBEAT_SEC)"; scrape="$(env_get CS3_HEALTH_SCRAPE_SEC)"; maxc="$(env_get CS3_MESSAGE_MAX_CHARS)"
  {
    grep -Ev '^CS3_(OTLP|ESOC|SIEM|HEARTBEAT|HEALTH|MESSAGE)_[A-Z_]+=' "$ENV_FILE" || true
    if [[ "$profile" == gateway ]]; then
      echo "CS3_OTLP_LISTEN=$otlp_listen"
      echo "CS3_OTLP_PORT=$otlp_port"
      if [[ -n "$otlp_cert" ]]; then
        echo "CS3_OTLP_CA_FILE=$CONF_DIR/pki/otlp-client-ca.pem"
        echo "CS3_OTLP_CERT_FILE=$CONF_DIR/pki/otlp-server.crt"
        echo "CS3_OTLP_KEY_FILE=$CONF_DIR/pki/otlp-server.key"
      fi
      echo "CS3_HEARTBEAT_SEC=${hb:-60}"
      echo "CS3_HEALTH_SCRAPE_SEC=${scrape:-30}"
      echo "CS3_MESSAGE_MAX_CHARS=${maxc:-8000}"
      if [[ -n "$esoc_host" ]]; then
        echo "CS3_ESOC_HOST=$esoc_host"
        echo "CS3_ESOC_PORT=$esoc_port"
        echo "CS3_ESOC_CA_FILE=$(gateway_ca "$esoc_ca" esoc-ca.pem)"
        echo "CS3_ESOC_CERT_FILE=$CONF_DIR/pki/esoc-client.crt"
        echo "CS3_ESOC_KEY_FILE=$CONF_DIR/pki/esoc-client.key"
      fi
      if [[ -n "$siem_url" ]]; then
        echo "CS3_SIEM_HOST=$siem_host"
        echo "CS3_SIEM_PORT=$siem_port"
        echo "CS3_SIEM_URI='$siem_uri'"
        echo "CS3_SIEM_TLS=On"
        echo "CS3_SIEM_CA_FILE=$(gateway_ca "$siem_ca" siem-ca.pem)"
        echo "CS3_SIEM_FORMAT=$siem_format"
        echo "CS3_SIEM_AUTH_SCHEME=$siem_scheme"
        echo "CS3_SIEM_TOKEN=$siem_token"
        [[ -z "$siem_proxy" ]] || echo "CS3_SIEM_PROXY='$siem_proxy'"
      fi
    fi
  } > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$ENV_FILE"
}

# CA files fall back to the system trust store when none was supplied.
gateway_ca() { if [[ -n "$1" ]]; then echo "$CONF_DIR/pki/$2"; else echo /etc/ssl/certs/ca-certificates.crt; fi; }

install_gateway() {
  local tpl="$SRC_DIR/templates/gateway.d" otlp_frag=10-otlp-input.conf f
  [[ -z "$otlp_cert" ]] || otlp_frag=10-otlp-input-mtls.conf
  remove_gateway_files
  run install -d -m 0750 "$FRAG_DIR"
  for f in "$otlp_frag" 20-normalize.conf 30-heartbeat.conf cs3-otlp-normalize.lua; do
    run install -m 0640 "$tpl/$f" "$FRAG_DIR/$f"
  done
  if [[ -n "$otlp_cert" ]]; then
    run install -m 0644 "$otlp_cert" "$CONF_DIR/pki/otlp-server.crt"
    run install -m 0600 "$otlp_key" "$CONF_DIR/pki/otlp-server.key"
    run install -m 0644 "$otlp_client_ca" "$CONF_DIR/pki/otlp-client-ca.pem"
  fi
  if [[ -n "$esoc_host" ]]; then
    run install -m 0640 "$tpl/40-esoc-otlp.conf" "$FRAG_DIR/40-esoc-otlp.conf"
    run install -m 0644 "$esoc_cert" "$CONF_DIR/pki/esoc-client.crt"
    run install -m 0600 "$esoc_key" "$CONF_DIR/pki/esoc-client.key"
    if [[ -n "$esoc_ca" ]]; then run install -m 0644 "$esoc_ca" "$CONF_DIR/pki/esoc-ca.pem"; fi
  fi
  if [[ -n "$siem_url" ]]; then
    run install -m 0640 "$tpl/50-siem-http.conf" "$FRAG_DIR/50-siem-http.conf"
    if [[ -n "$siem_ca" ]]; then run install -m 0644 "$siem_ca" "$CONF_DIR/pki/siem-ca.pem"; fi
    if ((! dry_run)) && [[ -n "$siem_proxy" ]]; then
      sed -i -E 's/^    # (Proxy )/    \1/' "$FRAG_DIR/50-siem-http.conf"
    fi
  fi
  if ((ai_tier)); then run install -m 0640 "$tpl/60-ai-tier.conf" "$FRAG_DIR/60-ai-tier.conf"; fi
  # The OTLP listener, Lua and dual egress need more headroom than the <25 MB edge budget.
  run install -d -m 0755 "$DROPIN_DIR"
  run install -m 0644 "$SRC_DIR/systemd/cecur-forwarder-gateway.conf" "$DROPIN_DIR/10-gateway.conf"
  # Enable the @INCLUDE of the fragment directory in the main config.
  if ((! dry_run)); then
    sed -i -E 's|^# (@INCLUDE /etc/cecur/fluent-bit\.d/)|\1|' "$CONF_DIR/fluent-bit.conf"
  fi
  local summary="OTLP ${otlp_listen}:${otlp_port}"
  [[ -z "$esoc_host" ]] || summary+=", ESOC ${esoc_host}:${esoc_port}"
  [[ -z "$siem_url" ]] || summary+=", SIEM ${siem_host}"
  if ((ai_tier)); then summary+=", AI tier"; fi
  log "gateway profile installed ($summary)"
}

write_gateway_env

# ---- 3. Config, units, watchdog -----------------------------------------------------------------
run install -m 0640 "$SRC_DIR/templates/fluent-bit-linux.conf" "$CONF_DIR/fluent-bit.conf"
# Referenced by absolute path from [SERVICE] Parsers_File; Fluent Bit aborts at startup if it is missing.
run install -m 0640 "$SRC_DIR/templates/parsers.conf" "$CONF_DIR/parsers.conf"
# mTLS is enabled whenever a client certificate/key pair is present in the pki directory.
if ((! dry_run)) && [[ -s "$CONF_DIR/pki/agent.crt" && -s "$CONF_DIR/pki/agent.key" ]]; then
  sed -i -E 's/^    # (tls\.(crt|key)_file)/    \1/' "$CONF_DIR/fluent-bit.conf"
  log "mTLS enabled (client certificate configured)"
fi
if [[ "$profile" == gateway ]]; then
  install_gateway
else
  remove_gateway_files
fi
run install -m 0644 "$SRC_DIR/systemd/cecur-forwarder.service" /etc/systemd/system/cecur-forwarder.service
run install -m 0644 "$SRC_DIR/systemd/cecur-forwarder-watchdog.service" /etc/systemd/system/cecur-forwarder-watchdog.service
run install -m 0644 "$SRC_DIR/systemd/cecur-forwarder-watchdog.timer" /etc/systemd/system/cecur-forwarder-watchdog.timer
run install -m 0755 "$SRC_DIR/cs3-forwarder-watchdog.sh" /usr/local/sbin/cs3-forwarder-watchdog.sh

run systemctl daemon-reload
run systemctl enable --now cecur-forwarder.service cecur-forwarder-watchdog.timer
if ((dry_run)); then log "dry run complete"; exit 0; fi

sleep 3
systemctl is-active --quiet cecur-forwarder.service || { journalctl -u cecur-forwarder -n 20 --no-pager >&2; die "forwarder failed to start"; }
log "installed and running (agent $(sed -n 's/^CS3_AGENT_ID=//p' "$ENV_FILE"))"
