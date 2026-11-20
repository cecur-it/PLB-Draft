#!/usr/bin/env bash
#
# install-llama.cpp.sh — non-CUDA GGUF fallback for the sovereign LLM tier: builds the pinned
# llama.cpp release from a checksum-verified source archive (or installs a pre-built
# llama-server after an explicit SHA-256 check) and runs `llama-server` as a sandboxed systemd
# service bound to 127.0.0.1:11434, so the llm-gateway and the worker proxy stay unchanged.
# Idempotent: safe to re-run.
#
# Traces: PROMPT §1 Tier 4 (llama.cpp CPU fallback when no CUDA/Metal accelerator qualifies —
#         see ollama/detect-hardware.mjs), PROMPT §3 (hardening, air-gap, integrity),
#         CONTRACT §8.1 (inference endpoint 127.0.0.1:11434), CONTRACT §10 (models.json digests).
#         Ports and extends CS3 scripts/install-llama.cpp.sh (tag b4000).
#
# What it does (Linux)
#   1. model    resolves an approved model id from models.json (default: the entry tier), locates its
#               GGUF and verifies the SHA-256 against models.json; the "<pinned-per-release>"
#               sentinel is refused under --release and in the airgap profile
#   2. binary   verified source archive (pinned SHA-256 for the pinned tag, or --source-archive +
#               --source-sha256) built CPU-only and statically, or --offline-binary + --offline-sha256
#   3. account  cs3-llama (system, nologin), /var/lib/cs3-llama-cpp mode 750
#   4. service  renders the packaged cs3-llama-cpp.service next to this script plus
#               /etc/cs3/llama-cpp.env; reload/restart only when something changed
#   5. checks   /health and /v1/models on 127.0.0.1:11434; --verify-loopback asserts loopback-only
# macOS: builds with Metal and installs the binary + verified GGUF under the prefix; no launchd
#        unit is shipped (Ollama with Metal, ollama/install-ollama.sh, is the supported macOS runtime).
# GGUF weights are never downloaded: provide them with --gguf, in $OLLAMA_AIRGAP_BUNDLE_DIR as
# <id with ':' replaced by '_'>.gguf, or in /var/lib/cs3-llama-cpp/models.
#
# Usage:
#   sudo ollama/install-llama.cpp.sh [options]
#     --profile cloud|onprem|airgap|edge   airgap forbids network access (needs --source-archive or
#                                          --offline-binary) and implies --release (default: $CS3_PROFILE)
#     --release                            refuse the <pinned-per-release> sentinel digest
#     --model <id>                         approved model id (default: first model of the entry tier)
#     --gguf <path>                        GGUF weights to install and verify
#     --gguf-sha256 <hex>                  digest to enforce when models.json still holds the sentinel
#                                          (not allowed with --release / airgap)
#     --models-json <file>                 default: models.json next to this script
#     --source-archive <file>              llama.cpp source tarball (requires --source-sha256 unless
#                                          it is the pinned tag's archive)
#     --source-sha256 <hex|file>           expected SHA-256 of the source archive
#     --offline-binary <file>              pre-built llama-server (skips the build)
#     --offline-sha256 <hex|file>          expected SHA-256 of --offline-binary
#     --prefix <dir>                       install prefix (Linux default /opt/cs3-llama-cpp)
#     --threads <n> --ctx-size <n> --parallel <n>   llama-server sizing (defaults: nproc, 16384, 2)
#     --verify-loopback                    fail unless 11434 listens only on loopback
#     --status                             report binary, model, unit drift, service and health
#     --uninstall [--purge --yes]          remove service + binary; GGUF weights and the account are
#                                          kept unless --purge is given (which also requires --yes)
#     --dry-run                            print every mutating step, change nothing
#     --destdir <dir>                      stage into <dir> (packaging / tests): no account, service
#                                          or health steps, no root required
#     -h, --help
# Environment: LLAMA_CPP_PINNED_TAG (b4000), LLAMA_CPP_SOURCE_SHA256 (required when the tag is
#   overridden), LLAMA_CPP_SOURCE_URL, OLLAMA_AIRGAP_BUNDLE_DIR, OLLAMA_BIND_ADDR (127.0.0.1:11434),
#   CS3_DOWNLOAD_RETRIES (5), CS3_DOWNLOAD_BACKOFF (2), CS3_HEALTH_TIMEOUT (300).
# Exit codes: 0 ok, 1 failure, 2 usage, 3 integrity (checksum / sentinel / air-gap violation),
#             4 post-install verification (health, loopback, status) failed.
set -euo pipefail
set -o errtrace
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

readonly DEFAULT_TAG="b4000"
readonly DEFAULT_TAG_SOURCE_SHA256="bdfc19f69f966ef98e0f1ab6c7744eda1229bafaa121f515b3f4f0ac8779fd9f"
readonly SENTINEL="<pinned-per-release>"
readonly SERVICE_USER="cs3-llama"
readonly SERVICE_HOME="/var/lib/cs3-llama-cpp"
readonly UNIT_NAME="cs3-llama-cpp.service"
readonly ENV_FILE="/etc/cs3/llama-cpp.env"
readonly EX_FAIL=1 EX_USAGE=2 EX_INTEGRITY=3 EX_VERIFY=4

LLAMA_CPP_PINNED_TAG="${LLAMA_CPP_PINNED_TAG:-$DEFAULT_TAG}"
LLAMA_CPP_SOURCE_URL="${LLAMA_CPP_SOURCE_URL:-https://github.com/ggml-org/llama.cpp/archive/refs/tags/${LLAMA_CPP_PINNED_TAG}.tar.gz}"
OLLAMA_BIND_ADDR="${OLLAMA_BIND_ADDR:-127.0.0.1:11434}"
[[ "$OLLAMA_BIND_ADDR" =~ ^127\.0\.0\.1:[0-9]{2,5}$ ]] || { echo "OLLAMA_BIND_ADDR must be 127.0.0.1:<port> (llama-server is loopback-only), got '$OLLAMA_BIND_ADDR'" >&2; exit 2; }
readonly BIND_HOST="${OLLAMA_BIND_ADDR%%:*}"
readonly BIND_PORT="${OLLAMA_BIND_ADDR##*:}"

if [[ -t 2 ]]; then C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_RST=$'\033[0m'; else C_RED=""; C_YEL=""; C_GRN=""; C_RST=""; fi
log()  { printf '%s[install-llama.cpp]%s %s\n' "$C_GRN" "$C_RST" "$1"; }
warn() { printf '%s[install-llama.cpp][warn]%s %s\n' "$C_YEL" "$C_RST" "$1" >&2; }
die()  { local code="$1"; shift; printf '%s[install-llama.cpp][FAIL]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit "$code"; }

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' -e '/^#$/s/^#//'; }

MODE="install"
PROFILE="${CS3_PROFILE:-}"
RELEASE="false"
MODEL=""
GGUF_PATH=""
GGUF_SHA256_OVERRIDE=""
MODELS_JSON="$SCRIPT_DIR/models.json"
SOURCE_ARCHIVE=""
SOURCE_SHA256="${LLAMA_CPP_SOURCE_SHA256:-}"
OFFLINE_BINARY=""
OFFLINE_SHA256=""
PREFIX=""
THREADS=""
CTX_SIZE="16384"
PARALLEL="2"
VERIFY_LOOPBACK="false"
DRY_RUN="false"
PURGE="false"
ASSUME_YES="false"
DESTDIR="${CS3_DESTDIR:-}"
DOWNLOAD_RETRIES="${CS3_DOWNLOAD_RETRIES:-5}"
DOWNLOAD_BACKOFF="${CS3_DOWNLOAD_BACKOFF:-2}"
HEALTH_TIMEOUT="${CS3_HEALTH_TIMEOUT:-300}"

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$EX_USAGE" "$1 needs a value (see --help)"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)         need_value "$@"; PROFILE="$2"; shift 2 ;;
    --release)         RELEASE="true"; shift ;;
    --model)           need_value "$@"; MODEL="$2"; shift 2 ;;
    --gguf)            need_value "$@"; GGUF_PATH="$2"; shift 2 ;;
    --gguf-sha256)     need_value "$@"; GGUF_SHA256_OVERRIDE="$2"; shift 2 ;;
    --models-json)     need_value "$@"; MODELS_JSON="$2"; shift 2 ;;
    --source-archive)  need_value "$@"; SOURCE_ARCHIVE="$2"; shift 2 ;;
    --source-sha256)   need_value "$@"; SOURCE_SHA256="$2"; shift 2 ;;
    --offline-binary)  need_value "$@"; OFFLINE_BINARY="$2"; shift 2 ;;
    --offline-sha256)  need_value "$@"; OFFLINE_SHA256="$2"; shift 2 ;;
    --prefix)          need_value "$@"; PREFIX="$2"; shift 2 ;;
    --threads)         need_value "$@"; THREADS="$2"; shift 2 ;;
    --ctx-size)        need_value "$@"; CTX_SIZE="$2"; shift 2 ;;
    --parallel)        need_value "$@"; PARALLEL="$2"; shift 2 ;;
    --destdir)         need_value "$@"; DESTDIR="${2%/}"; shift 2 ;;
    --verify-loopback) VERIFY_LOOPBACK="true"; shift ;;
    --status)          MODE="status"; shift ;;
    --uninstall)       MODE="uninstall"; shift ;;
    --purge)           PURGE="true"; shift ;;
    --yes)             ASSUME_YES="true"; shift ;;
    --dry-run)         DRY_RUN="true"; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "$EX_USAGE" "unknown argument: $1 (see --help)" ;;
  esac
done

case "$PROFILE" in ""|cloud|onprem|airgap|edge) ;; *) die "$EX_USAGE" "--profile must be cloud, onprem, airgap or edge (got '$PROFILE')" ;; esac
[[ "$PROFILE" != "airgap" ]] || RELEASE="true"
[[ "$LLAMA_CPP_PINNED_TAG" =~ ^b[0-9]{3,6}$ ]] || die "$EX_USAGE" "LLAMA_CPP_PINNED_TAG must look like b4000 (got '$LLAMA_CPP_PINNED_TAG')"
[[ -z "$THREADS" || "$THREADS" =~ ^[1-9][0-9]{0,2}$ ]] || die "$EX_USAGE" "--threads must be an integer 1-999"
[[ "$CTX_SIZE" =~ ^[1-9][0-9]{2,6}$ ]] || die "$EX_USAGE" "--ctx-size must be an integer >= 100"
[[ "$PARALLEL" =~ ^[1-9][0-9]?$ ]] || die "$EX_USAGE" "--parallel must be an integer 1-99"
[[ "$DOWNLOAD_RETRIES" =~ ^[1-9][0-9]?$ && "$DOWNLOAD_BACKOFF" =~ ^[0-9]+$ && "$HEALTH_TIMEOUT" =~ ^[0-9]+$ ]] \
  || die "$EX_USAGE" "CS3_DOWNLOAD_RETRIES / CS3_DOWNLOAD_BACKOFF / CS3_HEALTH_TIMEOUT must be integers"
if [[ "$PURGE" == "true" && "$MODE" != "uninstall" ]]; then die "$EX_USAGE" "--purge only applies to --uninstall"; fi
if [[ "$PURGE" == "true" && "$ASSUME_YES" != "true" && "$DRY_RUN" != "true" ]]; then
  die "$EX_USAGE" "--purge deletes the GGUF store and the service account; re-run with --yes to confirm"
fi
if [[ -n "$GGUF_SHA256_OVERRIDE" ]]; then
  [[ "$GGUF_SHA256_OVERRIDE" =~ ^[0-9a-fA-F]{64}$ ]] || die "$EX_USAGE" "--gguf-sha256 must be 64 hex characters"
  [[ "$RELEASE" != "true" ]] || die "$EX_INTEGRITY" "--gguf-sha256 cannot replace the models.json digest under --release / airgap"
fi

case "$(uname -s)" in
  Linux)  OS_NAME="linux" ;;
  Darwin) OS_NAME="darwin" ;;
  *)      die "$EX_FAIL" "unsupported platform $(uname -s)" ;;
esac
if [[ -z "$PREFIX" ]]; then
  if [[ "$OS_NAME" == "linux" ]]; then PREFIX="/opt/cs3-llama-cpp"; else PREFIX="${HOME:-/var/root}/.cs3/llama.cpp"; fi
fi
[[ -n "$THREADS" ]] || THREADS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

dp() { printf '%s%s' "$DESTDIR" "$1"; }
STAGED="false"
[[ -z "$DESTDIR" ]] || STAGED="true"
BIN_PATH="$(dp "$PREFIX/bin/llama-server")"
MARKER_PATH="$(dp "$PREFIX/.cs3-installed")"
UNIT_PATH="$(dp "/etc/systemd/system/$UNIT_NAME")"
ENV_PATH="$(dp "$ENV_FILE")"
if [[ "$OS_NAME" == "linux" ]]; then MODELS_DIR="$SERVICE_HOME/models"; else MODELS_DIR="$PREFIX/models"; fi

mkdir -p "${TMPDIR:-/var/tmp}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/cs3-llama-cpp.XXXXXX")"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    local IFS=' '
    printf '[install-llama.cpp][dry-run] %s\n' "$*"
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

resolve_sha() { # resolve_sha <flag-name> <hex|sha256sum file>
  local value="$2"
  if [[ -f "$value" ]]; then value="$(awk 'NF {print $1; exit}' "$value")"; fi
  [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]] || die "$EX_USAGE" "$1 must be 64 hex characters or a sha256sum file"
  printf '%s' "${value,,}"
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

install_if_changed() { # install_if_changed <src> <dest> <mode>; 0 = wrote, 10 = already current
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

# --- model --------------------------------------------------------------------
safe_id() { printf '%s' "${1//:/_}"; }

resolve_model() {
  command -v jq >/dev/null 2>&1 || die "$EX_FAIL" "jq is required to read $MODELS_JSON"
  [[ -r "$MODELS_JSON" ]] || die "$EX_USAGE" "models.json not readable: $MODELS_JSON"
  jq -e '.models | type == "array" and length > 0' "$MODELS_JSON" >/dev/null 2>&1 || die "$EX_USAGE" "$MODELS_JSON is not a valid models.json"
  if [[ -z "$MODEL" ]]; then
    MODEL="$(jq -r '.tiers.entry.models[0] // empty' "$MODELS_JSON")"
    [[ -n "$MODEL" ]] || die "$EX_USAGE" "models.json has no entry tier; pass --model"
  fi
  jq -e --arg id "$MODEL" '[.models[].id] | index($id) != null' "$MODELS_JSON" >/dev/null 2>&1 \
    || die "$EX_INTEGRITY" "model '$MODEL' is not an approved tag in $MODELS_JSON"
  MODEL_SHA256="$(jq -r --arg id "$MODEL" '.models[] | select(.id == $id) | .sha256' "$MODELS_JSON")"
  MODEL_FILE="$(safe_id "$MODEL").gguf"
  MODEL_DEST="$(dp "$MODELS_DIR/$MODEL_FILE")"
  EXPECTED_SHA=""
  if [[ "$MODEL_SHA256" == "$SENTINEL" ]]; then
    if [[ "$RELEASE" == "true" ]]; then
      die "$EX_INTEGRITY" "models.json holds the ${SENTINEL} sentinel for $MODEL; run scripts/pin-model-digests.mjs before a release/air-gap install"
    fi
    if [[ -n "$GGUF_SHA256_OVERRIDE" ]]; then
      EXPECTED_SHA="${GGUF_SHA256_OVERRIDE,,}"
      warn "$MODEL is unpinned in models.json; enforcing the operator-supplied --gguf-sha256."
    else
      warn "$MODEL is unpinned in models.json: the GGUF is NOT integrity-checked (development only; use --release for production)."
    fi
  elif [[ "$MODEL_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
    EXPECTED_SHA="${MODEL_SHA256,,}"
    [[ -z "$GGUF_SHA256_OVERRIDE" || "${GGUF_SHA256_OVERRIDE,,}" == "$EXPECTED_SHA" ]] \
      || die "$EX_INTEGRITY" "--gguf-sha256 disagrees with the pinned models.json digest for $MODEL"
  else
    die "$EX_INTEGRITY" "models.json sha256 for $MODEL is neither 64-hex nor the sentinel: '$MODEL_SHA256'"
  fi
}

GGUF_SOURCE=""
locate_gguf() { # sets GGUF_SOURCE; returns 1 when no candidate exists
  local candidate
  if [[ -n "$GGUF_PATH" ]]; then
    [[ -f "$GGUF_PATH" ]] || die "$EX_USAGE" "--gguf file not found: $GGUF_PATH"
    GGUF_SOURCE="$GGUF_PATH"; return 0
  fi
  for candidate in "${OLLAMA_AIRGAP_BUNDLE_DIR:+${OLLAMA_AIRGAP_BUNDLE_DIR%/}/$MODEL_FILE}" "$MODEL_DEST"; do
    if [[ -n "$candidate" && -f "$candidate" ]]; then GGUF_SOURCE="$candidate"; return 0; fi
  done
  return 1
}

file_size() { stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1"; }

install_gguf() {
  local sidecar="${MODEL_DEST}.sha256"
  if [[ -n "$EXPECTED_SHA" && -f "$MODEL_DEST" && -f "$sidecar" ]] \
     && [[ "$(awk 'NR==1' "$sidecar")" == "$EXPECTED_SHA" && "$(awk 'NR==2' "$sidecar")" == "$(file_size "$MODEL_DEST")" ]]; then
    log "GGUF $MODEL_FILE already verified at $MODEL_DEST — skipping (idempotent)."
    return
  fi
  if ! locate_gguf; then
    local hint="no GGUF for $MODEL: pass --gguf, set OLLAMA_AIRGAP_BUNDLE_DIR (expects $MODEL_FILE) or place it at $MODEL_DEST"
    if [[ "$DRY_RUN" == "true" ]]; then warn "[dry-run] a real run would fail: $hint"; return; fi
    die "$EX_FAIL" "$hint"
  fi
  if [[ -n "$EXPECTED_SHA" ]]; then verify_sha256 "$GGUF_SOURCE" "$EXPECTED_SHA"; fi
  run install -d -m 0750 "$(dirname "$MODEL_DEST")"
  if [[ "$(readlink -f "$GGUF_SOURCE")" != "$(readlink -f "$MODEL_DEST")" ]]; then
    log "Installing GGUF to $MODEL_DEST"
    run cp "$GGUF_SOURCE" "${MODEL_DEST}.part"
    run mv "${MODEL_DEST}.part" "$MODEL_DEST"
  fi
  run chmod 0640 "$MODEL_DEST"
  if [[ -n "$EXPECTED_SHA" && "$DRY_RUN" != "true" ]]; then
    printf '%s\n%s\n' "$EXPECTED_SHA" "$(file_size "$MODEL_DEST")" >"$sidecar"
  fi
  if [[ "$OS_NAME" == "linux" && "$STAGED" != "true" ]]; then
    run chown "$SERVICE_USER:$SERVICE_USER" "$MODEL_DEST"
    [[ ! -f "$sidecar" ]] || run chown "$SERVICE_USER:$SERVICE_USER" "$sidecar"
  fi
}

# --- binary -------------------------------------------------------------------
source_pin() {
  if [[ -n "$SOURCE_ARCHIVE" ]]; then
    [[ -f "$SOURCE_ARCHIVE" ]] || die "$EX_USAGE" "--source-archive not found: $SOURCE_ARCHIVE"
  fi
  if [[ -n "$SOURCE_SHA256" ]]; then
    SOURCE_PIN="$(resolve_sha "--source-sha256" "$SOURCE_SHA256")"
  elif [[ "$LLAMA_CPP_PINNED_TAG" == "$DEFAULT_TAG" ]]; then
    SOURCE_PIN="$DEFAULT_TAG_SOURCE_SHA256"
  else
    die "$EX_USAGE" "tag $LLAMA_CPP_PINNED_TAG has no built-in digest: pass --source-sha256 (or LLAMA_CPP_SOURCE_SHA256)"
  fi
}

require_build_tools() {
  local missing=() tool
  for tool in cmake cc c++ make tar; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "$EX_FAIL" "missing build tools: ${missing[*]} (install a C/C++ toolchain, cmake and make, or use --offline-binary)"
}

build_from_source() { # build_from_source <verified archive> -> WORK_DIR/llama-server
  local archive="$1" src="$WORK_DIR/src" backend_flags
  require_build_tools
  mkdir -p "$src"
  tar -xzf "$archive" -C "$src" --strip-components=1
  if [[ "$OS_NAME" == "darwin" ]]; then backend_flags="-DGGML_METAL=ON"; else backend_flags="-DGGML_CUDA=OFF"; fi
  log "Building llama.cpp ${LLAMA_CPP_PINNED_TAG} (${backend_flags#-DGGML_}, static, no libcurl)"
  cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF \
    -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=ON -DLLAMA_BUILD_SERVER=ON "$backend_flags"
  cmake --build "$src/build" --config Release --target llama-server -j "$THREADS"
  [[ -x "$src/build/bin/llama-server" ]] || die "$EX_FAIL" "build finished but build/bin/llama-server is missing"
  cp "$src/build/bin/llama-server" "$WORK_DIR/llama-server"
}

install_binary() {
  local want_marker payload=""
  if [[ -n "$OFFLINE_BINARY" ]]; then
    [[ -f "$OFFLINE_BINARY" ]] || die "$EX_USAGE" "--offline-binary not found: $OFFLINE_BINARY"
    [[ -n "$OFFLINE_SHA256" ]] || die "$EX_INTEGRITY" "--offline-binary requires --offline-sha256 (refusing an unverified binary)"
    local offline_pin
    offline_pin="$(resolve_sha "--offline-sha256" "$OFFLINE_SHA256")"
    verify_sha256 "$OFFLINE_BINARY" "$offline_pin"
    want_marker="binary ${offline_pin}"
    payload="$OFFLINE_BINARY"
  else
    source_pin
    want_marker="${LLAMA_CPP_PINNED_TAG} ${SOURCE_PIN}"
    if [[ -z "$SOURCE_ARCHIVE" && "$PROFILE" == "airgap" ]]; then
      die "$EX_INTEGRITY" "profile is airgap: pass --source-archive (+ --source-sha256) or --offline-binary; refusing to use the network"
    fi
  fi

  if [[ -x "$BIN_PATH" && -f "$MARKER_PATH" && "$(cat "$MARKER_PATH")" == "$want_marker" ]]; then
    log "llama-server ${want_marker%% *} already installed at $BIN_PATH — skipping (idempotent)."
    BINARY_CHANGED="false"
    return
  fi

  if [[ -z "$payload" ]]; then
    local archive="$SOURCE_ARCHIVE"
    if [[ -z "$archive" ]]; then
      if [[ "$DRY_RUN" == "true" ]]; then
        log "[dry-run] would download $LLAMA_CPP_SOURCE_URL, verify SHA-256 ${SOURCE_PIN}, build and install llama-server"
        return
      fi
      archive="$WORK_DIR/llama.cpp-${LLAMA_CPP_PINNED_TAG}.tar.gz"
      fetch "$LLAMA_CPP_SOURCE_URL" "$archive"
    fi
    verify_sha256 "$archive" "$SOURCE_PIN"
    if [[ "$DRY_RUN" == "true" ]]; then
      log "[dry-run] would build llama-server from $archive and install it to $BIN_PATH"
      return
    fi
    build_from_source "$archive"
    payload="$WORK_DIR/llama-server"
  fi

  run install -d -m 0755 "$(dirname "$BIN_PATH")"
  run install -m 0755 "$payload" "${BIN_PATH}.new"
  run mv "${BIN_PATH}.new" "$BIN_PATH"
  if [[ "$DRY_RUN" != "true" ]]; then printf '%s\n' "$want_marker" | tr -d '\n' >"$MARKER_PATH"; fi
  BINARY_CHANGED="true"
  log "llama-server installed at $BIN_PATH"
}

# --- account and service --------------------------------------------------------------------
ensure_account_and_dirs() {
  if [[ "$STAGED" != "true" ]]; then
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
      log "Service account $SERVICE_USER already exists — skipping creation."
    else
      log "Creating dedicated system account: $SERVICE_USER"
      run useradd --system --no-create-home --home-dir "$SERVICE_HOME" --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$SERVICE_HOME" "$SERVICE_HOME/models"
  else
    run install -d -m 0750 "$(dp "$SERVICE_HOME")" "$(dp "$SERVICE_HOME/models")"
  fi
}

render_unit() {
  local out="$1"
  [[ -f "$SCRIPT_DIR/$UNIT_NAME" ]] || die "$EX_FAIL" "packaged unit not found next to the script: $SCRIPT_DIR/$UNIT_NAME"
  sed -e "s|^ExecStart=/opt/cs3-llama-cpp/bin/llama-server |ExecStart=${PREFIX}/bin/llama-server |" \
      -e "s|--port 11434 |--port ${BIND_PORT} |" "$SCRIPT_DIR/$UNIT_NAME" >"$out"
}

render_env() {
  cat >"$1" <<EOF
# Managed by install-llama.cpp.sh — re-run the installer instead of editing.
LLAMA_MODEL_ID=${MODEL}
LLAMA_MODEL_PATH=${MODELS_DIR}/${MODEL_FILE}
LLAMA_THREADS=${THREADS}
LLAMA_CTX_SIZE=${CTX_SIZE}
LLAMA_PARALLEL=${PARALLEL}
EOF
}

install_service() {
  local unit_rendered="$WORK_DIR/$UNIT_NAME" env_rendered="$WORK_DIR/llama-cpp.env" changed="false"
  render_unit "$unit_rendered"
  render_env "$env_rendered"
  if install_if_changed "$env_rendered" "$ENV_PATH" 0640; then changed="true"; fi
  if install_if_changed "$unit_rendered" "$UNIT_PATH" 0644; then changed="true"; fi
  [[ "$STAGED" != "true" && "$DRY_RUN" != "true" ]] || return 0
  chown "root:$SERVICE_USER" "$ENV_PATH"
  command -v systemctl >/dev/null 2>&1 || die "$EX_FAIL" "systemd (systemctl) is required on Linux for the hardened unit"
  [[ "$changed" != "true" ]] || systemctl daemon-reload
  if systemctl is-active "$UNIT_NAME" >/dev/null 2>&1; then
    if [[ "$changed" == "true" || "$BINARY_CHANGED" == "true" ]]; then
      log "Unit, environment or binary changed — restarting $UNIT_NAME"
      systemctl restart "$UNIT_NAME"
    else
      log "$UNIT_NAME already active — nothing to restart (idempotent)."
    fi
  else
    if systemctl is-active cs3-ollama.service >/dev/null 2>&1; then
      warn "cs3-ollama.service is active; starting $UNIT_NAME stops it (Conflicts=) because both bind ${BIND_HOST}:${BIND_PORT}."
    fi
    systemctl enable --now "$UNIT_NAME"
    log "$UNIT_NAME enabled and started, bound to ${BIND_HOST}:${BIND_PORT}."
  fi
}

# --- verification ---------------------------------------------------------------------------
health_check() {
  local deadline=$(( SECONDS + HEALTH_TIMEOUT )) models=""
  log "Waiting up to ${HEALTH_TIMEOUT}s for http://${BIND_HOST}:${BIND_PORT}/health (model load can take minutes)"
  while (( SECONDS < deadline )); do
    if http_get "http://${BIND_HOST}:${BIND_PORT}/health" >/dev/null 2>&1; then
      models="$(http_get "http://${BIND_HOST}:${BIND_PORT}/v1/models" 2>/dev/null | tr -d ' \n' || true)"
      if [[ "$models" == *"\"id\":\"${MODEL}\""* ]]; then
        log "Health check passed: llama-server serves ${MODEL} on ${BIND_HOST}:${BIND_PORT} (OpenAI-compatible /v1)."
        return 0
      fi
      die "$EX_VERIFY" "health check: /v1/models does not list '${MODEL}'"
    fi
    sleep 2
  done
  die "$EX_VERIFY" "health check: no healthy answer from http://${BIND_HOST}:${BIND_PORT}/health within ${HEALTH_TIMEOUT}s"
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
  [[ -n "$addrs" ]] || die "$EX_VERIFY" "loopback check: nothing is listening on port ${BIND_PORT}"
  while IFS= read -r addr; do
    [[ -n "$addr" ]] || continue
    case "$addr" in
      "${BIND_HOST}:${BIND_PORT}"|"[::1]:${BIND_PORT}") log "loopback check: ${addr} is loopback-only" ;;
      *) warn "loopback check: ${addr} is reachable beyond loopback"; bad=1 ;;
    esac
  done <<<"$addrs"
  [[ "$bad" -eq 0 ]] || die "$EX_VERIFY" "port ${BIND_PORT} is bound to a non-loopback address; llama-server must listen on ${BIND_HOST} only"
}

report_status() {
  local failures=0 live="false" rendered_unit="$WORK_DIR/status.unit" rendered_env="$WORK_DIR/status.env" state
  resolve_model
  [[ "$STAGED" != "true" ]] || live="true"
  if [[ -x "$BIN_PATH" ]]; then log "binary: $BIN_PATH ($(cat "$MARKER_PATH" 2>/dev/null || echo 'no marker'))"; else warn "binary: not installed at $BIN_PATH"; failures=1; fi
  if [[ -f "$MODEL_DEST" ]]; then log "model: $MODEL_DEST"; else warn "model: $MODEL_DEST missing"; failures=1; fi
  if [[ "$OS_NAME" == "linux" ]]; then
    render_unit "$rendered_unit"; render_env "$rendered_env"
    if [[ ! -f "$UNIT_PATH" ]]; then warn "unit: $UNIT_PATH not installed"; failures=1
    elif diff -q "$rendered_unit" "$UNIT_PATH" >/dev/null 2>&1; then log "unit: matches the packaged unit"
    else warn "unit: $UNIT_PATH differs from the packaged unit (re-run the installer to reconcile)"; fi
    if [[ -f "$ENV_PATH" ]] && ! diff -q "$rendered_env" "$ENV_PATH" >/dev/null 2>&1; then
      warn "env: $ENV_PATH differs from the values this invocation would render"
    fi
    if [[ "$STAGED" != "true" ]] && command -v systemctl >/dev/null 2>&1; then
      state="$(systemctl is-active "$UNIT_NAME" 2>/dev/null || true)"
      log "$UNIT_NAME: ${state:-unknown}"
      if [[ "$state" == "active" ]]; then live="true"; else failures=1; fi
    fi
  fi
  if [[ "$live" == "true" ]]; then ( health_check ) || failures=1; fi
  if [[ "$VERIFY_LOOPBACK" == "true" ]]; then ( verify_loopback ) || failures=1; fi
  [[ "$failures" -eq 0 ]] || die "$EX_VERIFY" "status: one or more checks failed"
  log "status: OK"
}

uninstall() {
  mutating_env_ok
  log "Uninstalling llama.cpp (GGUF weights and the account are kept unless --purge --yes)."
  if [[ "$STAGED" != "true" && "$OS_NAME" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
    run systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
  fi
  local path
  for path in "$UNIT_PATH" "$ENV_PATH" "$BIN_PATH" "$MARKER_PATH"; do
    if [[ -e "$path" ]]; then run rm -f "$path"; log "removed $path"; fi
  done
  if [[ "$STAGED" != "true" && "$OS_NAME" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
    run systemctl daemon-reload
  fi
  if [[ "$PURGE" == "true" ]]; then
    warn "--purge: deleting $(dp "$MODELS_DIR") (GGUF weights) and the service account"
    run rm -rf "$(dp "$SERVICE_HOME")" "$(dp "$MODELS_DIR")"
    if [[ "$STAGED" != "true" && "$OS_NAME" == "linux" ]]; then
      id -u "$SERVICE_USER" >/dev/null 2>&1 && run userdel "$SERVICE_USER"
      getent group "$SERVICE_USER" >/dev/null 2>&1 && run groupdel "$SERVICE_USER"
    fi
  else
    log "Kept $(dp "$MODELS_DIR") (GGUF weights) and the ${SERVICE_USER} account."
  fi
  log "Uninstall complete."
}

main() {
  log "Target: $OS_NAME | tag: $LLAMA_CPP_PINNED_TAG | profile: ${PROFILE:-<none>} | release: $RELEASE | dry-run: $DRY_RUN${DESTDIR:+ | destdir: $DESTDIR}"
  case "$MODE" in
    status)    report_status; return ;;
    uninstall) uninstall; return ;;
  esac
  mutating_env_ok
  resolve_model
  if [[ -n "$EXPECTED_SHA" ]]; then log "Model: $MODEL -> $MODEL_FILE (sha256 ${EXPECTED_SHA:0:12}...)"; else log "Model: $MODEL -> $MODEL_FILE (digest unverified)"; fi
  if [[ "$OS_NAME" == "linux" ]]; then ensure_account_and_dirs; else run install -d -m 0750 "$(dp "$MODELS_DIR")"; fi
  install_gguf
  install_binary
  if [[ "$OS_NAME" == "linux" ]]; then
    install_service
    if [[ "$DRY_RUN" == "true" ]]; then
      [[ "$VERIFY_LOOPBACK" != "true" ]] || log "[dry-run] would verify that port ${BIND_PORT} is bound only to loopback (ss -ltnH)"
    else
      [[ "$STAGED" == "true" ]] || health_check
      [[ "$VERIFY_LOOPBACK" != "true" ]] || verify_loopback
    fi
    log "Done. llama.cpp ${LLAMA_CPP_PINNED_TAG} serves ${MODEL} on ${BIND_HOST}:${BIND_PORT} (loopback only) as ${SERVICE_USER}."
  else
    log "Done. Run: $BIN_PATH --host ${BIND_HOST} --port ${BIND_PORT} --model $(dp "$MODELS_DIR")/${MODEL_FILE} --alias ${MODEL}"
  fi
}

BINARY_CHANGED="false"
MODEL_SHA256=""
MODEL_FILE=""
MODEL_DEST=""
EXPECTED_SHA=""
SOURCE_PIN=""
main
