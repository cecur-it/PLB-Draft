#!/usr/bin/env bash
#
# install-ollama.sh — installs the pinned Ollama release as a hardened, loopback-only
# service under a dedicated non-root account (cs3-ollama). Idempotent: safe to re-run.
#
# Traces: PROMPT §1 Tier 4 (sovereign LLM tier: Ollama 0.40.5 on 127.0.0.1:11434),
#         PROMPT §3 (hardening, air-gap), CONTRACT §8.1 (Ollama never leaves loopback; the
#         mTLS worker proxy in ollama-lb/worker-proxy.cfg is the only network listener).
#         Ports and extends CS3 scripts/install-ollama.sh.
#
# Platforms: Linux (systemd) and macOS (launchd, account _cs3-ollama via dscl).
#
# What it does
#   1. account  cs3-ollama (system, nologin), /var/lib/cs3-ollama mode 750, models in
#               /var/lib/cs3-ollama/.ollama/models (OLLAMA_MODELS)
#   2. binary   pinned OLLAMA_PINNED_VERSION: connected profiles download the release archive
#               and verify it against the release sha256sum.txt (retry with backoff);
#               --offline-binary + --offline-sha256 install without touching the network
#   3. service  renders the packaged cs3-ollama.service / com.cecur-it.cs3-ollama.plist (next to
#               this script), diffs against the installed copy and reloads/restarts only on change
#   4. logs     /etc/logrotate.d/cs3-ollama (Linux) or /etc/newsyslog.d/cs3-ollama.conf (macOS)
#   5. checks   GET http://127.0.0.1:11434/api/version must report the pinned version;
#               --verify-loopback asserts 11434 is bound only to 127.0.0.1 / ::1 (ss -ltnH)
#
# Usage:
#   sudo ollama/install-ollama.sh [options]
#     --profile cloud|onprem|airgap|edge   airgap forbids any network access and requires
#                                          --offline-binary and --offline-sha256 (default: $CS3_PROFILE)
#     --offline-binary <path>              ollama binary or release archive (.tgz/.tar.gz/.tar.zst)
#     --offline-sha256 <hex|file>          expected SHA-256 of --offline-binary (sha256sum file accepted)
#     --num-parallel <n>                   OLLAMA_NUM_PARALLEL   (unit default 4; keep equal to the LB per-server maxconn)
#     --keep-alive <dur>                   OLLAMA_KEEP_ALIVE    (unit default 30m)
#     --max-loaded-models <n>              OLLAMA_MAX_LOADED_MODELS (unit default 2)
#     --verify-loopback                    fail unless 11434 listens only on loopback
#     --status                             report binary, version, unit drift, service state and health
#                                          (the health probe targets the live endpoint, also with --destdir)
#     --uninstall [--purge --yes]          remove service + binary; weights and account are kept unless
#                                          --purge is given (which also requires --yes)
#     --dry-run                            print every mutating step, change nothing
#     --destdir <dir>                      stage into <dir> (packaging / image builds / tests): no
#                                          account, service or health steps, no root required
#     -h, --help
# Environment: OLLAMA_PINNED_VERSION (default 0.40.5), OLLAMA_OFFLINE_BINARY, OLLAMA_OFFLINE_SHA256,
#   OLLAMA_BIND_ADDR (default 127.0.0.1:11434; loopback only — rendered into the unit/plist and used by the checks),
#   OLLAMA_DOWNLOAD_BASE (internal mirror of github.com/ollama/ollama/releases/download),
#   CS3_DOWNLOAD_RETRIES (5), CS3_DOWNLOAD_BACKOFF (2, seconds, doubled per retry), CS3_HEALTH_TIMEOUT (90).
# Exit codes: 0 ok, 1 failure, 2 usage, 3 integrity (checksum / air-gap violation / wrong version),
#             4 post-install verification (health, version, loopback, status) failed.
set -euo pipefail
set -o errtrace
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

OLLAMA_PINNED_VERSION="${OLLAMA_PINNED_VERSION:-0.40.5}"
readonly SERVICE_USER="cs3-ollama"
readonly SERVICE_GROUP="cs3-ollama"
readonly SERVICE_HOME="/var/lib/cs3-ollama"
readonly UNIT_NAME="cs3-ollama.service"
readonly LAUNCHD_LABEL="com.cecur-it.cs3-ollama"
OLLAMA_BIND_ADDR="${OLLAMA_BIND_ADDR:-127.0.0.1:11434}"
[[ "$OLLAMA_BIND_ADDR" =~ ^127\.0\.0\.1:[0-9]{2,5}$ ]] || { echo "OLLAMA_BIND_ADDR must be 127.0.0.1:<port> (Ollama is loopback-only), got '$OLLAMA_BIND_ADDR'" >&2; exit 2; }
readonly BIND_HOST="${OLLAMA_BIND_ADDR%%:*}"
readonly BIND_PORT="${OLLAMA_BIND_ADDR##*:}"
readonly INSTALL_PREFIX="/usr/local"
readonly DEFAULT_DOWNLOAD_BASE="https://github.com/ollama/ollama/releases/download"

readonly EX_FAIL=1 EX_USAGE=2 EX_INTEGRITY=3 EX_VERIFY=4

if [[ -t 2 ]]; then C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_RST=$'\033[0m'; else C_RED=""; C_YEL=""; C_GRN=""; C_RST=""; fi
log()  { printf '%s[install-ollama]%s %s\n' "$C_GRN" "$C_RST" "$1"; }
warn() { printf '%s[install-ollama][warn]%s %s\n' "$C_YEL" "$C_RST" "$1" >&2; }
die()  { local code="$1"; shift; printf '%s[install-ollama][FAIL]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit "$code"; }

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' -e '/^#$/s/^#//'; }

MODE="install"
PROFILE="${CS3_PROFILE:-}"
OFFLINE_BINARY="${OLLAMA_OFFLINE_BINARY:-}"
OFFLINE_SHA256="${OLLAMA_OFFLINE_SHA256:-}"
NUM_PARALLEL=""
KEEP_ALIVE=""
MAX_LOADED_MODELS=""
VERIFY_LOOPBACK="false"
DRY_RUN="false"
PURGE="false"
ASSUME_YES="false"
DESTDIR="${CS3_DESTDIR:-}"
DOWNLOAD_RETRIES="${CS3_DOWNLOAD_RETRIES:-5}"
DOWNLOAD_BACKOFF="${CS3_DOWNLOAD_BACKOFF:-2}"
HEALTH_TIMEOUT="${CS3_HEALTH_TIMEOUT:-90}"
DOWNLOAD_BASE="${OLLAMA_DOWNLOAD_BASE:-$DEFAULT_DOWNLOAD_BASE}"

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$EX_USAGE" "$1 needs a value (see --help)"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)           need_value "$@"; PROFILE="$2"; shift 2 ;;
    --offline-binary)    need_value "$@"; OFFLINE_BINARY="$2"; shift 2 ;;
    --offline-sha256)    need_value "$@"; OFFLINE_SHA256="$2"; shift 2 ;;
    --num-parallel)      need_value "$@"; NUM_PARALLEL="$2"; shift 2 ;;
    --keep-alive)        need_value "$@"; KEEP_ALIVE="$2"; shift 2 ;;
    --max-loaded-models) need_value "$@"; MAX_LOADED_MODELS="$2"; shift 2 ;;
    --destdir)           need_value "$@"; DESTDIR="${2%/}"; shift 2 ;;
    --verify-loopback)   VERIFY_LOOPBACK="true"; shift ;;
    --status)            MODE="status"; shift ;;
    --uninstall)         MODE="uninstall"; shift ;;
    --purge)             PURGE="true"; shift ;;
    --yes)               ASSUME_YES="true"; shift ;;
    --dry-run)           DRY_RUN="true"; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)                   die "$EX_USAGE" "unknown argument: $1 (see --help)" ;;
  esac
done

case "$PROFILE" in ""|cloud|onprem|airgap|edge) ;; *) die "$EX_USAGE" "--profile must be cloud, onprem, airgap or edge (got '$PROFILE')" ;; esac
[[ "$NUM_PARALLEL" =~ ^([1-9][0-9]{0,2})?$ ]] || die "$EX_USAGE" "--num-parallel must be an integer 1-999"
[[ "$MAX_LOADED_MODELS" =~ ^([1-9][0-9]{0,1})?$ ]] || die "$EX_USAGE" "--max-loaded-models must be an integer 1-99"
[[ "$KEEP_ALIVE" =~ ^(-1|[0-9]+[smh]?)?$ ]] || die "$EX_USAGE" "--keep-alive must look like 30m, 3600s, 24h or -1"
[[ "$OLLAMA_PINNED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$EX_USAGE" "OLLAMA_PINNED_VERSION must be x.y.z (got '$OLLAMA_PINNED_VERSION')"
[[ "$DOWNLOAD_RETRIES" =~ ^[1-9][0-9]?$ && "$DOWNLOAD_BACKOFF" =~ ^[0-9]+$ && "$HEALTH_TIMEOUT" =~ ^[0-9]+$ ]] \
  || die "$EX_USAGE" "CS3_DOWNLOAD_RETRIES / CS3_DOWNLOAD_BACKOFF / CS3_HEALTH_TIMEOUT must be integers"
if [[ "$PURGE" == "true" && "$MODE" != "uninstall" ]]; then die "$EX_USAGE" "--purge only applies to --uninstall"; fi
if [[ "$PURGE" == "true" && "$ASSUME_YES" != "true" && "$DRY_RUN" != "true" ]]; then
  die "$EX_USAGE" "--purge deletes the model store and the service account; re-run with --yes to confirm"
fi

case "$(uname -s)" in
  Linux)  OS_NAME="linux" ;;
  Darwin) OS_NAME="darwin" ;;
  *)      die "$EX_FAIL" "unsupported platform $(uname -s); Windows is handled by install.ps1" ;;
esac

dp() { printf '%s%s' "$DESTDIR" "$1"; }
BIN_PATH="$(dp "$INSTALL_PREFIX/bin/ollama")"
LIB_PATH="$(dp "$INSTALL_PREFIX/lib/ollama")"
UNIT_PATH="$(dp "/etc/systemd/system/$UNIT_NAME")"
PLIST_PATH="$(dp "/Library/LaunchDaemons/$LAUNCHD_LABEL.plist")"
if [[ "$OS_NAME" == "linux" ]]; then
  LOGROTATE_SRC="$SCRIPT_DIR/cs3-ollama.logrotate"
  LOGROTATE_PATH="$(dp "/etc/logrotate.d/cs3-ollama")"
else
  LOGROTATE_SRC="$SCRIPT_DIR/cs3-ollama.newsyslog.conf"
  LOGROTATE_PATH="$(dp "/etc/newsyslog.d/cs3-ollama.conf")"
fi
STAGED="false"
[[ -n "$DESTDIR" ]] && STAGED="true"

mkdir -p "${TMPDIR:-/var/tmp}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/cs3-ollama.XXXXXX")"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    local IFS=' '
    printf '[install-ollama][dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

mutating_env_ok() {
  [[ "$DRY_RUN" == "true" || "$STAGED" == "true" || "${EUID:-$(id -u)}" -eq 0 ]] \
    || die "$EX_FAIL" "must run as root (creates a system account and a service); re-run with sudo, or use --dry-run / --destdir"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print tolower($1)}'
  else openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  fi
}

verify_sha256() {
  local file="$1" expected="$2" actual
  actual="$(sha256_of "$file")"
  [[ "$actual" == "${expected,,}" ]] || die "$EX_INTEGRITY" "SHA-256 mismatch for $file: expected ${expected,,}, got $actual"
  log "SHA-256 verified for $(basename "$file")"
}

http_get() {
  if command -v curl >/dev/null 2>&1; then curl --fail --silent --show-error --max-time 5 "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -T 5 -O - "$1"
  else die "$EX_FAIL" "curl or wget is required"
  fi
}

retry() {
  local max="$1" delay="$2" attempt=1
  shift 2
  until "$@"; do
    if (( attempt >= max )); then return 1; fi
    warn "attempt ${attempt}/${max} failed: $*; retrying in ${delay}s"
    sleep "$delay"
    delay=$(( delay * 2 ))
    attempt=$(( attempt + 1 ))
  done
}

fetch() {
  local url="$1" out="$2" proto="=https"
  [[ "$PROFILE" != "airgap" ]] || die "$EX_INTEGRITY" "profile is airgap: refusing to fetch $url"
  case "$url" in
    http://127.0.0.1[:/]*|http://localhost[:/]*) proto="=http,https" ;;
    https://*) ;;
    *) die "$EX_INTEGRITY" "refusing non-HTTPS download URL: $url" ;;
  esac
  command -v curl >/dev/null 2>&1 || die "$EX_FAIL" "curl is required to download $url"
  retry "$DOWNLOAD_RETRIES" "$DOWNLOAD_BACKOFF" curl --fail --silent --show-error --location --proto "$proto" --output "$out" "$url" \
    || die "$EX_FAIL" "download failed after ${DOWNLOAD_RETRIES} attempts: $url"
}

client_version() {
  local bin="$1" out
  [[ -x "$bin" ]] || return 0
  out="$(OLLAMA_HOST="127.0.0.1:9" "$bin" --version 2>&1 || true)"
  printf '%s\n' "$out" | sed -n 's/.*client version is \([0-9][0-9.]*\).*/\1/p; s/.*ollama version is \([0-9][0-9.]*\).*/\1/p' | head -n 1
}

# --- templates ---------------------------------------------------------------
sed_file() {
  local expr="$1" file="$2"
  sed -e "$expr" "$file" >"$file.new"
  mv "$file.new" "$file"
}

render_unit() {
  local out="$1"
  [[ -f "$SCRIPT_DIR/$UNIT_NAME" ]] || die "$EX_FAIL" "packaged unit not found next to the script: $SCRIPT_DIR/$UNIT_NAME"
  cp "$SCRIPT_DIR/$UNIT_NAME" "$out"
  [[ "$OLLAMA_BIND_ADDR" == "127.0.0.1:11434" ]] || sed_file "s|^Environment=OLLAMA_HOST=.*\$|Environment=OLLAMA_HOST=${OLLAMA_BIND_ADDR}|" "$out"
  [[ -z "$NUM_PARALLEL" ]]      || sed_file "s|^Environment=OLLAMA_NUM_PARALLEL=.*\$|Environment=OLLAMA_NUM_PARALLEL=${NUM_PARALLEL}|" "$out"
  [[ -z "$KEEP_ALIVE" ]]        || sed_file "s|^Environment=OLLAMA_KEEP_ALIVE=.*\$|Environment=OLLAMA_KEEP_ALIVE=${KEEP_ALIVE}|" "$out"
  [[ -z "$MAX_LOADED_MODELS" ]] || sed_file "s|^Environment=OLLAMA_MAX_LOADED_MODELS=.*\$|Environment=OLLAMA_MAX_LOADED_MODELS=${MAX_LOADED_MODELS}|" "$out"
}

set_plist_env() {
  local file="$1" key="$2" value="$3"
  sed_file "/<key>${key}<\\/key>/{
n
s|<string>.*</string>|<string>${value}</string>|
}" "$file"
}

render_plist() {
  local out="$1"
  [[ -f "$SCRIPT_DIR/$LAUNCHD_LABEL.plist" ]] || die "$EX_FAIL" "packaged plist not found next to the script: $SCRIPT_DIR/$LAUNCHD_LABEL.plist"
  cp "$SCRIPT_DIR/$LAUNCHD_LABEL.plist" "$out"
  [[ "$OLLAMA_BIND_ADDR" == "127.0.0.1:11434" ]] || set_plist_env "$out" OLLAMA_HOST "$OLLAMA_BIND_ADDR"
  [[ -z "$NUM_PARALLEL" ]]      || set_plist_env "$out" OLLAMA_NUM_PARALLEL "$NUM_PARALLEL"
  [[ -z "$KEEP_ALIVE" ]]        || set_plist_env "$out" OLLAMA_KEEP_ALIVE "$KEEP_ALIVE"
  [[ -z "$MAX_LOADED_MODELS" ]] || set_plist_env "$out" OLLAMA_MAX_LOADED_MODELS "$MAX_LOADED_MODELS"
}

# install_if_changed <rendered-src> <dest> <mode>; returns 0 when it wrote, 10 when already current.
install_if_changed() {
  local src="$1" dest="$2" mode="$3"
  if [[ -f "$dest" ]] && diff -q "$src" "$dest" >/dev/null 2>&1; then
    log "$dest already up to date — skipping (idempotent)."
    return 10
  fi
  log "Writing $dest"
  run install -d -m 0755 "$(dirname "$dest")"
  run install -m "$mode" "$src" "$dest"
  return 0
}

# --- account -----------------------------------------------------------------
darwin_free_id() {
  local used candidate
  used="$( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } 2>/dev/null | awk '{print $2}')"
  for candidate in $(seq 300 399); do
    if ! printf '%s\n' "$used" | grep -qx "$candidate"; then printf '%s' "$candidate"; return 0; fi
  done
  die "$EX_FAIL" "no free service UID/GID in 300-399"
}

ensure_service_account() {
  if [[ "$STAGED" == "true" ]]; then
    run install -d -m 0750 "$(dp "$SERVICE_HOME")" "$(dp "$SERVICE_HOME/.ollama/models")"
    return
  fi
  if [[ "$OS_NAME" == "linux" ]]; then
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
      log "Service account $SERVICE_USER already exists — skipping creation."
    else
      log "Creating dedicated system account: $SERVICE_USER"
      run useradd --system --no-create-home --home-dir "$SERVICE_HOME" --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    local grp
    for grp in render video; do
      if getent group "$grp" >/dev/null 2>&1 && ! id -nG "$SERVICE_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$grp"; then
        log "Adding $SERVICE_USER to group $grp (GPU device access)"
        run usermod -aG "$grp" "$SERVICE_USER"
      fi
    done
    local owner="$SERVICE_USER:$SERVICE_GROUP"
  else
    local acct="_${SERVICE_USER}" id
    if dscl . -read "/Users/${acct}" >/dev/null 2>&1; then
      log "Service account ${acct} already exists — skipping creation."
    else
      log "Creating dedicated macOS service account: ${acct}"
      if [[ "$DRY_RUN" == "true" ]]; then id="300"; else id="$(darwin_free_id)"; fi
      run dscl . -create "/Groups/${acct}"
      run dscl . -create "/Groups/${acct}" PrimaryGroupID "$id"
      run dscl . -create "/Users/${acct}"
      run dscl . -create "/Users/${acct}" UniqueID "$id"
      run dscl . -create "/Users/${acct}" PrimaryGroupID "$id"
      run dscl . -create "/Users/${acct}" UserShell /usr/bin/false
      run dscl . -create "/Users/${acct}" NFSHomeDirectory "$SERVICE_HOME"
      run dscl . -create "/Users/${acct}" RealName "CS3 Ollama service"
      run dscl . -create "/Users/${acct}" IsHidden 1
    fi
    local owner="${acct}:${acct}"
  fi
  run install -d -m 0750 -o "${owner%%:*}" -g "${owner##*:}" "$SERVICE_HOME" "$SERVICE_HOME/.ollama" "$SERVICE_HOME/.ollama/models"
  run chmod 750 "$SERVICE_HOME"
  if [[ -d "$SERVICE_HOME" && "$(stat -c '%U' "$SERVICE_HOME" 2>/dev/null || stat -f '%Su' "$SERVICE_HOME")" != "${owner%%:*}" ]]; then
    run chown -R "$owner" "$SERVICE_HOME"
  fi
}

# --- binary ------------------------------------------------------------------
resolve_offline_sha() {
  local value="$1"
  if [[ -f "$value" ]]; then value="$(awk 'NF {print $1; exit}' "$value")"; fi
  [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]] || die "$EX_USAGE" "--offline-sha256 must be 64 hex characters or a sha256sum file"
  printf '%s' "${value,,}"
}

unpack_archive() {
  local archive="$1" dest="$2"
  mkdir -p "$dest"
  case "$archive" in
    *.tar.zst)
      command -v zstd >/dev/null 2>&1 || die "$EX_FAIL" "zstd is required to unpack ${archive##*/}"
      zstd -dc "$archive" | tar -x -C "$dest" ;;
    *.tgz|*.tar.gz) tar -xzf "$archive" -C "$dest" ;;
    *) die "$EX_FAIL" "unsupported archive type: $archive" ;;
  esac
}

place_payload() {
  local payload_bin="$1" payload_lib="$2"
  run install -d -m 0755 "$(dirname "$BIN_PATH")"
  run install -m 0755 "$payload_bin" "$BIN_PATH"
  if [[ -n "$payload_lib" && -d "$payload_lib" ]]; then
    run rm -rf "${LIB_PATH}.new"
    run install -d -m 0755 "$(dirname "$LIB_PATH")"
    run cp -R "$payload_lib" "${LIB_PATH}.new"
    run rm -rf "$LIB_PATH"
    run mv "${LIB_PATH}.new" "$LIB_PATH"
  fi
}

asset_for_platform() {
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "$EX_FAIL" "unsupported CPU architecture $(uname -m)" ;;
  esac
  if [[ "$OS_NAME" == "darwin" ]]; then printf 'ollama-darwin.tgz'; else printf 'ollama-linux-%s.tar.zst ollama-linux-%s.tgz' "$arch" "$arch"; fi
}

install_ollama_binary() {
  BINARY_CHANGED="false"
  local installed
  installed="$(client_version "$BIN_PATH")"

  if [[ -n "$OFFLINE_BINARY" ]]; then
    [[ -f "$OFFLINE_BINARY" ]] || die "$EX_USAGE" "--offline-binary path not found: $OFFLINE_BINARY"
    [[ -n "$OFFLINE_SHA256" ]] || die "$EX_INTEGRITY" "--offline-binary requires --offline-sha256 (refusing an unverified binary)"
    local expected_sha
    expected_sha="$(resolve_offline_sha "$OFFLINE_SHA256")"
    verify_sha256 "$OFFLINE_BINARY" "$expected_sha"
  elif [[ "$PROFILE" == "airgap" ]]; then
    die "$EX_INTEGRITY" "profile is airgap but no --offline-binary/--offline-sha256 was given; refusing to use the network"
  fi

  if [[ "$installed" == "$OLLAMA_PINNED_VERSION" ]]; then
    log "Ollama $OLLAMA_PINNED_VERSION already installed at $BIN_PATH — skipping (idempotent)."
    return
  fi
  [[ -z "$installed" ]] || log "Installed Ollama is ${installed}; replacing with pinned ${OLLAMA_PINNED_VERSION}."

  local payload_bin payload_lib=""
  if [[ -n "$OFFLINE_BINARY" ]]; then
    log "Installing Ollama from the offline artifact (no network access): $OFFLINE_BINARY"
    case "$OFFLINE_BINARY" in
      *.tgz|*.tar.gz|*.tar.zst)
        unpack_archive "$OFFLINE_BINARY" "$WORK_DIR/payload"
        payload_bin="$WORK_DIR/payload/bin/ollama"
        payload_lib="$WORK_DIR/payload/lib/ollama"
        [[ -f "$payload_bin" ]] || die "$EX_FAIL" "archive has no bin/ollama" ;;
      *) payload_bin="$OFFLINE_BINARY" ;;
    esac
  else
    local base="${DOWNLOAD_BASE%/}/v${OLLAMA_PINNED_VERSION}" asset="" candidate
    log "Resolving Ollama ${OLLAMA_PINNED_VERSION} from ${base}"
    if [[ "$DRY_RUN" == "true" ]]; then
      log "[dry-run] would download $(asset_for_platform | tr ' ' '|') + sha256sum.txt from ${base}, verify and unpack"
      return
    fi
    fetch "$base/sha256sum.txt" "$WORK_DIR/sha256sum.txt"
    for candidate in $(asset_for_platform | tr ' ' '\n'); do
      if grep -qE "[[:space:]]\*?(\./)?${candidate}\$" "$WORK_DIR/sha256sum.txt"; then asset="$candidate"; break; fi
    done
    [[ -n "$asset" ]] || die "$EX_FAIL" "release ${OLLAMA_PINNED_VERSION} has no asset for this platform in sha256sum.txt"
    fetch "$base/$asset" "$WORK_DIR/$asset"
    verify_sha256 "$WORK_DIR/$asset" "$(grep -E "[[:space:]]\*?(\./)?${asset}\$" "$WORK_DIR/sha256sum.txt" | awk '{print $1; exit}')"
    unpack_archive "$WORK_DIR/$asset" "$WORK_DIR/payload"
    payload_bin="$WORK_DIR/payload/bin/ollama"
    payload_lib="$WORK_DIR/payload/lib/ollama"
    [[ -f "$payload_bin" ]] || die "$EX_FAIL" "downloaded archive has no bin/ollama"
  fi

  place_payload "$payload_bin" "$payload_lib"
  BINARY_CHANGED="true"
  if [[ "$DRY_RUN" != "true" ]]; then
    local now
    now="$(client_version "$BIN_PATH")"
    [[ "$now" == "$OLLAMA_PINNED_VERSION" ]] || die "$EX_INTEGRITY" "installed binary reports version '${now:-unknown}', expected ${OLLAMA_PINNED_VERSION}"
    log "Ollama ${OLLAMA_PINNED_VERSION} installed at $BIN_PATH"
  fi
}

# --- service -----------------------------------------------------------------
install_logrotate() {
  [[ -f "$LOGROTATE_SRC" ]] || die "$EX_FAIL" "packaged log rotation snippet not found: $LOGROTATE_SRC"
  if [[ "$STAGED" != "true" && "$OS_NAME" == "linux" && ! -d /etc/logrotate.d ]]; then
    warn "logrotate is not installed (/etc/logrotate.d missing); skipping $LOGROTATE_PATH"
    return
  fi
  install_if_changed "$LOGROTATE_SRC" "$LOGROTATE_PATH" 0644 || true
}

install_systemd_service() {
  local rendered="$WORK_DIR/$UNIT_NAME" unit_changed="false"
  render_unit "$rendered"
  if install_if_changed "$rendered" "$UNIT_PATH" 0644; then unit_changed="true"; fi
  [[ "$STAGED" != "true" ]] || return 0
  command -v systemctl >/dev/null 2>&1 || die "$EX_FAIL" "systemd (systemctl) is required on Linux for the hardened unit"
  [[ "$unit_changed" != "true" ]] || run systemctl daemon-reload
  if systemctl is-active "$UNIT_NAME" >/dev/null 2>&1; then
    if [[ "$unit_changed" == "true" || "$BINARY_CHANGED" == "true" ]]; then
      log "Unit or binary changed — restarting $UNIT_NAME"
      run systemctl restart "$UNIT_NAME"
    else
      log "$UNIT_NAME already active — nothing to restart (idempotent)."
    fi
  else
    run systemctl enable --now "$UNIT_NAME"
    log "$UNIT_NAME enabled and started, bound to ${BIND_HOST}:${BIND_PORT}."
  fi
  if [[ "$(systemctl is-active ollama.service 2>/dev/null || true)" == "active" ]]; then
    warn "the stock ollama.service is active and competes for ${BIND_HOST}:${BIND_PORT}; disable it (systemctl disable --now ollama.service)."
  fi
}

install_launchd_service() {
  local rendered="$WORK_DIR/$LAUNCHD_LABEL.plist" plist_changed="false"
  render_plist "$rendered"
  if install_if_changed "$rendered" "$PLIST_PATH" 0644; then plist_changed="true"; fi
  [[ "$STAGED" != "true" ]] || return 0
  if launchctl list 2>/dev/null | grep -q "$LAUNCHD_LABEL"; then
    if [[ "$plist_changed" == "true" || "$BINARY_CHANGED" == "true" ]]; then
      run launchctl unload "$PLIST_PATH" || true
      run launchctl load -w "$PLIST_PATH"
      log "$LAUNCHD_LABEL reloaded."
    else
      log "$LAUNCHD_LABEL already loaded — nothing to reload (idempotent)."
    fi
  else
    run launchctl load -w "$PLIST_PATH"
    log "$LAUNCHD_LABEL loaded, bound to ${BIND_HOST}:${BIND_PORT}."
  fi
}

# --- verification --------------------------------------------------------------
health_check() {
  local deadline=$(( SECONDS + HEALTH_TIMEOUT )) body="" version=""
  log "Waiting up to ${HEALTH_TIMEOUT}s for http://${BIND_HOST}:${BIND_PORT}/api/version"
  while (( SECONDS < deadline )); do
    if body="$(http_get "http://${BIND_HOST}:${BIND_PORT}/api/version" 2>/dev/null)"; then
      version="$(printf '%s' "$body" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      [[ "$version" == "$OLLAMA_PINNED_VERSION" ]] \
        || die "$EX_VERIFY" "health check: server reports version '${version:-unparseable}', expected ${OLLAMA_PINNED_VERSION}"
      log "Health check passed: Ollama ${version} answers on ${BIND_HOST}:${BIND_PORT}."
      return 0
    fi
    sleep 2
  done
  die "$EX_VERIFY" "health check: no valid answer from http://${BIND_HOST}:${BIND_PORT}/api/version within ${HEALTH_TIMEOUT}s"
}

listeners_on_port() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH 2>/dev/null | awk -v suffix=":${BIND_PORT}" '{ if (substr($4, length($4) - length(suffix) + 1) == suffix) print $4 }'
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${BIND_PORT}" -sTCP:LISTEN -Fn 2>/dev/null | sed -n 's/^n//p'
  else
    die "$EX_FAIL" "ss (iproute2) or lsof is required for --verify-loopback"
  fi
}

verify_loopback() {
  local addrs addr bad=0
  addrs="$(listeners_on_port || true)"
  if [[ -z "$addrs" ]]; then
    die "$EX_VERIFY" "loopback check: nothing is listening on port ${BIND_PORT}"
  fi
  while IFS= read -r addr; do
    [[ -n "$addr" ]] || continue
    case "$addr" in
      "${BIND_HOST}:${BIND_PORT}"|"[::1]:${BIND_PORT}") log "loopback check: ${addr} is loopback-only" ;;
      *) warn "loopback check: ${addr} is reachable beyond loopback"; bad=1 ;;
    esac
  done <<<"$addrs"
  [[ "$bad" -eq 0 ]] || die "$EX_VERIFY" "port ${BIND_PORT} is bound to a non-loopback address; Ollama must listen on ${BIND_HOST} only"
}

# --- status / uninstall ----------------------------------------------------------
report_status() {
  local failures=0 version unit_state="n/a" rendered="$WORK_DIR/status.render" live="false"
  [[ "$STAGED" != "true" ]] || live="true"
  version="$(client_version "$BIN_PATH")"
  if [[ -z "$version" ]]; then
    warn "ollama binary: not installed at $BIN_PATH"; failures=1
  elif [[ "$version" != "$OLLAMA_PINNED_VERSION" ]]; then
    warn "ollama binary: version ${version}, pinned ${OLLAMA_PINNED_VERSION}"; failures=1
  else
    log "ollama binary: $BIN_PATH (${version}, matches pin)"
  fi
  if [[ "$OS_NAME" == "linux" ]]; then
    render_unit "$rendered"
    if [[ ! -f "$UNIT_PATH" ]]; then warn "unit: $UNIT_PATH not installed"; failures=1
    elif diff -q "$rendered" "$UNIT_PATH" >/dev/null 2>&1; then log "unit: $UNIT_PATH matches the packaged unit"
    else warn "unit: $UNIT_PATH differs from the packaged unit (re-run the installer to reconcile)"; fi
    if [[ "$STAGED" != "true" ]] && command -v systemctl >/dev/null 2>&1; then
      unit_state="$(systemctl is-active "$UNIT_NAME" 2>/dev/null || true)"
      log "$UNIT_NAME: ${unit_state:-unknown}"
      if [[ "$unit_state" == "active" ]]; then live="true"; else failures=1; fi
    fi
  else
    render_plist "$rendered"
    if [[ ! -f "$PLIST_PATH" ]]; then warn "plist: $PLIST_PATH not installed"; failures=1
    elif diff -q "$rendered" "$PLIST_PATH" >/dev/null 2>&1; then log "plist: $PLIST_PATH matches the packaged plist"
    else warn "plist: $PLIST_PATH differs from the packaged plist (re-run the installer to reconcile)"; fi
    if [[ "$STAGED" != "true" ]]; then
      if launchctl list 2>/dev/null | grep -q "$LAUNCHD_LABEL"; then log "$LAUNCHD_LABEL: loaded"; live="true"; else warn "$LAUNCHD_LABEL: not loaded"; failures=1; fi
    fi
  fi
  if [[ "$live" == "true" ]]; then
    ( health_check ) || failures=1
  fi
  if [[ "$VERIFY_LOOPBACK" == "true" ]]; then
    ( verify_loopback ) || failures=1
  fi
  [[ "$failures" -eq 0 ]] || die "$EX_VERIFY" "status: one or more checks failed"
  log "status: OK"
}

uninstall() {
  mutating_env_ok
  log "Uninstalling the CS3 Ollama service (model store and account are kept unless --purge --yes)."
  if [[ "$STAGED" != "true" ]]; then
    if [[ "$OS_NAME" == "linux" ]]; then
      if command -v systemctl >/dev/null 2>&1; then
        run systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
      fi
    elif launchctl list 2>/dev/null | grep -q "$LAUNCHD_LABEL"; then
      run launchctl unload "$PLIST_PATH" || true
    fi
  fi
  local path
  for path in "$UNIT_PATH" "$PLIST_PATH" "$LOGROTATE_PATH" "$BIN_PATH"; do
    if [[ -e "$path" ]]; then run rm -f "$path"; log "removed $path"; fi
  done
  if [[ -d "$LIB_PATH" ]]; then run rm -rf "$LIB_PATH"; log "removed $LIB_PATH"; fi
  if [[ "$STAGED" != "true" && "$OS_NAME" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
    run systemctl daemon-reload
  fi
  if [[ "$PURGE" == "true" ]]; then
    warn "--purge: deleting $(dp "$SERVICE_HOME") (model weights) and the service account"
    run rm -rf "$(dp "$SERVICE_HOME")"
    if [[ "$STAGED" != "true" ]]; then
      if [[ "$OS_NAME" == "linux" ]]; then
        id -u "$SERVICE_USER" >/dev/null 2>&1 && run userdel "$SERVICE_USER"
        getent group "$SERVICE_GROUP" >/dev/null 2>&1 && run groupdel "$SERVICE_GROUP"
      else
        run dscl . -delete "/Users/_${SERVICE_USER}" 2>/dev/null || true
        run dscl . -delete "/Groups/_${SERVICE_USER}" 2>/dev/null || true
      fi
    fi
  else
    log "Kept $(dp "$SERVICE_HOME") (model weights) and the ${SERVICE_USER} account."
  fi
  log "Uninstall complete."
}

main() {
  log "Target: $OS_NAME | pinned version: $OLLAMA_PINNED_VERSION | profile: ${PROFILE:-<none>} | dry-run: $DRY_RUN${DESTDIR:+ | destdir: $DESTDIR}"
  case "$MODE" in
    status)    report_status; return ;;
    uninstall) uninstall; return ;;
  esac
  mutating_env_ok
  ensure_service_account
  install_ollama_binary
  if [[ "$OS_NAME" == "linux" ]]; then install_systemd_service; else install_launchd_service; fi
  install_logrotate
  if [[ "$DRY_RUN" == "true" ]]; then
    [[ "$VERIFY_LOOPBACK" != "true" ]] || log "[dry-run] would verify that port ${BIND_PORT} is bound only to loopback (ss -ltnH)"
  else
    [[ "$STAGED" == "true" ]] || health_check
    [[ "$VERIFY_LOOPBACK" != "true" ]] || verify_loopback
  fi
  log "Done. Ollama ${OLLAMA_PINNED_VERSION} is configured for ${BIND_HOST}:${BIND_PORT} (loopback only) as ${SERVICE_USER}."
}

BINARY_CHANGED="false"
main
