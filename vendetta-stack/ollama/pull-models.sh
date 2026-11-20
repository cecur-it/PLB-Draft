#!/usr/bin/env bash
#
# pull-models.sh — provisions the approved models into the local Ollama store.
#   connected profiles (cloud/onprem/edge): `ollama pull <approved tag>`, then — when models.json
#                       carries a pinned digest — verifies that the stored weights blob has exactly
#                       that SHA-256
#   airgap profile:     NEVER touches the network; loads the GGUF blob from OLLAMA_AIRGAP_BUNDLE_DIR,
#                       verifies its SHA-256 against models.json and registers it with `ollama create`
# Only tags listed in models.json can be provisioned. Idempotent: models that are already present
# (and, when pinned, digest-correct) are skipped.
#
# Traces: PROMPT §1 Tier 4 (nemotron-3-nano:30b / gemma4:26b / gemma4:31b), PROMPT §3 (air-gap,
#         supply-chain integrity), CONTRACT §10 (models.json: approved tags + per-release digests),
#         CONTRACT §8.2 (worker model preload). Ports CS3 ansible role ollama_models.
#
# Usage: pull-models.sh [options]
#   --from-models-json     take the approved set and digests from models.json (always the case;
#                          accepted so callers can state the intent explicitly)
#   --models <csv>         model ids to provision (default: $OLLAMA_PRELOAD_MODELS; "all" = every
#                          approved model; "none" = nothing; unset = primary + fallback + security + deep model;
#                          edge profile = fallback + security + deep model)
#   --models-json <file>   default: $OLLAMA_MODELS_JSON, ./models.json next to this script, /opt/cs3/models.json
#   --profile <name>       cloud|onprem|airgap|edge (default: $CS3_PROFILE, else onprem)
#   --bundle-dir <dir>     air-gap bundle with the GGUF blobs (default: $OLLAMA_AIRGAP_BUNDLE_DIR)
#   --release              refuse the "<pinned-per-release>" sentinel digest (implied by airgap)
#   --print-models         print the resolved model ids, one per line, and exit
#   --dry-run              show what would be pulled/created, change nothing
#   -h, --help
# Bundle layout (first match wins): <dir>/<id with ':'->'_'>.gguf, <dir>/models/<...>.gguf,
#   <dir>/models/blobs/sha256-<digest>, <dir>/blobs/sha256-<digest>. An optional
#   <dir>/<...>.Modelfile (parameters/template only; any FROM line is dropped) overrides the packaged
#   modelfiles/<...>.Modelfile. The registered model always uses the verified blob.
# Environment: OLLAMA_BIN (ollama), OLLAMA_PRIMARY_MODEL (nemotron-3-nano:30b),
#   OLLAMA_FALLBACK_MODEL (gemma4:26b), OLLAMA_SECURITY_MODEL (nemotron-3-nano:30b — the security classes are
#   served by the agentic tier), INFERENCE_MODEL_REASONING_DEEP (gemma4:31b — the only security/Errow fallback),
#   OLLAMA_MODELFILES_DIR,
#   OLLAMA_PULL_RETRIES (3). Model ids whose models.json entry carries an `upstream` Hub tag are pulled from
#   that tag and then registered under the approved local id, so callers only ever address the local id.
# Exit codes: 0 ok, 1 failure, 2 usage, 3 integrity/policy (unapproved tag, digest mismatch,
#             sentinel under release/airgap).
set -euo pipefail
set -o errtrace
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly SENTINEL="<pinned-per-release>"
readonly EX_FAIL=1 EX_USAGE=2 EX_INTEGRITY=3

log()  { printf '[pull-models] %s\n' "$1" >&2; }
warn() { printf '[pull-models][warn] %s\n' "$1" >&2; }
die()  { local code="$1"; shift; printf '[pull-models][FAIL] %s\n' "$*" >&2; exit "$code"; }

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' -e '/^#$/s/^#//'; }

OLLAMA_BIN="${OLLAMA_BIN:-ollama}"
PROFILE="${CS3_PROFILE:-onprem}"
MODELS_JSON="${OLLAMA_MODELS_JSON:-}"
BUNDLE_DIR="${OLLAMA_AIRGAP_BUNDLE_DIR:-}"
MODELS_CSV="${OLLAMA_PRELOAD_MODELS:-}"
PRIMARY_MODEL="${OLLAMA_PRIMARY_MODEL:-nemotron-3-nano:30b}"
FALLBACK_MODEL="${OLLAMA_FALLBACK_MODEL:-gemma4:26b}"
SECURITY_MODEL="${OLLAMA_SECURITY_MODEL:-nemotron-3-nano:30b}"
DEEP_MODEL="${INFERENCE_MODEL_REASONING_DEEP:-gemma4:31b}"
RELEASE="${CS3_RELEASE:-false}"
PRINT_ONLY="false"
DRY_RUN="false"
PULL_RETRIES="${OLLAMA_PULL_RETRIES:-3}"

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$EX_USAGE" "$1 needs a value (see --help)"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-models-json) shift ;;
    --models)           need_value "$@"; MODELS_CSV="$2"; shift 2 ;;
    --models-json)      need_value "$@"; MODELS_JSON="$2"; shift 2 ;;
    --profile)          need_value "$@"; PROFILE="$2"; shift 2 ;;
    --bundle-dir)       need_value "$@"; BUNDLE_DIR="$2"; shift 2 ;;
    --release)          RELEASE="true"; shift ;;
    --print-models)     PRINT_ONLY="true"; shift ;;
    --dry-run)          DRY_RUN="true"; shift ;;
    -h|--help)          usage; exit 0 ;;
    *)                  die "$EX_USAGE" "unknown argument: $1 (see --help)" ;;
  esac
done

case "$PROFILE" in cloud|onprem|airgap|edge) ;; *) die "$EX_USAGE" "profile must be cloud, onprem, airgap or edge (got '$PROFILE')" ;; esac
case "$RELEASE" in true|false) ;; *) die "$EX_USAGE" "CS3_RELEASE must be true or false" ;; esac
[[ "$PULL_RETRIES" =~ ^[1-9]$ ]] || die "$EX_USAGE" "OLLAMA_PULL_RETRIES must be 1-9"
[[ "$PROFILE" != "airgap" ]] || RELEASE="true"
command -v jq >/dev/null 2>&1 || die "$EX_FAIL" "jq is required to read models.json"

if [[ -z "$MODELS_JSON" ]]; then
  for candidate in "$SCRIPT_DIR/models.json" /opt/cs3/models.json; do
    if [[ -r "$candidate" ]]; then MODELS_JSON="$candidate"; break; fi
  done
fi
[[ -n "$MODELS_JSON" && -r "$MODELS_JSON" ]] || die "$EX_USAGE" "models.json not found (use --models-json or OLLAMA_MODELS_JSON)"
jq -e '.models | type == "array" and length > 0' "$MODELS_JSON" >/dev/null 2>&1 || die "$EX_USAGE" "$MODELS_JSON is not a valid models.json"

MODELFILES_DIR="${OLLAMA_MODELFILES_DIR:-}"
if [[ -z "$MODELFILES_DIR" ]]; then
  for candidate in "$SCRIPT_DIR/modelfiles" /opt/cs3/modelfiles; do
    if [[ -d "$candidate" ]]; then MODELFILES_DIR="$candidate"; break; fi
  done
fi

safe_id() { printf '%s' "${1//:/_}"; }
model_field() { jq -r --arg id "$1" --arg f "$2" '.models[] | select(.id == $id) | .[$f]' "$MODELS_JSON"; }
is_approved() { jq -e --arg id "$1" '[.models[].id] | index($id) != null' "$MODELS_JSON" >/dev/null 2>&1; }

resolve_models() {
  local csv="$MODELS_CSV" id
  if [[ -z "$csv" ]]; then
    if [[ "$PROFILE" == "edge" ]]; then csv="${FALLBACK_MODEL},${SECURITY_MODEL},${DEEP_MODEL}"; else csv="${PRIMARY_MODEL},${FALLBACK_MODEL},${SECURITY_MODEL},${DEEP_MODEL}"; fi
  fi
  case "$csv" in
    none) return 0 ;;
    all)  jq -r '.models[].id' "$MODELS_JSON"; return 0 ;;
  esac
  local seen=","
  for id in $(printf '%s' "$csv" | tr ',' '\n'); do
    id="${id//[[:space:]]/}"
    [[ -n "$id" ]] || continue
    is_approved "$id" || die "$EX_INTEGRITY" "'$id' is not an approved model tag in $MODELS_JSON"
    if [[ "$seen" != *",$id,"* ]]; then printf '%s\n' "$id"; seen+="$id,"; fi
  done
}

if [[ "$PRINT_ONLY" == "true" ]]; then
  resolve_models
  exit 0
fi

command -v "$OLLAMA_BIN" >/dev/null 2>&1 || die "$EX_FAIL" "ollama CLI not found (OLLAMA_BIN=$OLLAMA_BIN)"

WORK_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/cs3-pull-models.XXXXXX")"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    local IFS=' '
    log "[dry-run] $*"
  else
    "$@"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print tolower($1)}'
  else openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  fi
}

installed_models() { "$OLLAMA_BIN" list 2>/dev/null | awk 'NR > 1 {print $1}'; }
model_installed() { installed_models | grep -qxF "$1"; }

# Prints the SHA-256 digests of the blobs behind a stored model (FROM lines of `ollama show --modelfile`).
stored_digests() {
  "$OLLAMA_BIN" show --modelfile "$1" 2>/dev/null | sed -n 's/^FROM .*sha256-\([0-9a-f]\{64\}\).*/\1/p'
}

# Echoes the pinned digest, or nothing when the sentinel is in place and the policy allows it.
pinned_digest() {
  local id="$1" digest
  digest="$(model_field "$id" sha256)"
  if [[ "$digest" == "$SENTINEL" ]]; then
    [[ "$RELEASE" != "true" ]] || die "$EX_INTEGRITY" "models.json holds the ${SENTINEL} sentinel for $id; run scripts/pin-model-digests.mjs before a release/air-gap deployment"
    warn "$id is unpinned in models.json: its weights are NOT integrity-checked (development only)."
    return 0
  fi
  [[ "$digest" =~ ^[0-9a-fA-F]{64}$ ]] || die "$EX_INTEGRITY" "models.json sha256 for $id is neither 64-hex nor the sentinel: '$digest'"
  printf '%s' "${digest,,}"
}

verify_stored() { # verify_stored <id> <digest>
  if stored_digests "$1" | grep -qx "$2"; then
    log "$1: stored weights match the pinned SHA-256 ${2:0:12}..."
    return 0
  fi
  return 1
}

# models.json `upstream`: the Hub tag whose weights back an approved local id (empty for library tags).
upstream_of() { # upstream_of <id>; prints nothing when the id is its own upstream
  local upstream
  upstream="$(model_field "$1" upstream 2>/dev/null || true)"
  [[ "$upstream" == "null" ]] && upstream=""
  printf '%s' "$upstream"
}

modelfile_for() { # modelfile_for <id>; prints the packaged fragment path, if any
  local safe
  safe="$(safe_id "$1")"
  if [[ -n "$BUNDLE_DIR" && -f "$BUNDLE_DIR/$safe.Modelfile" ]]; then printf '%s' "$BUNDLE_DIR/$safe.Modelfile"
  elif [[ -n "$MODELFILES_DIR" && -f "$MODELFILES_DIR/$safe.Modelfile" ]]; then printf '%s' "$MODELFILES_DIR/$safe.Modelfile"
  fi
}

pull_connected() {
  local id="$1" digest attempt=1 delay=5 source fragment
  digest="$(pinned_digest "$id")"
  source="$(upstream_of "$id")"
  [[ -n "$source" ]] || source="$id"
  if model_installed "$id" && { [[ -z "$digest" ]] || verify_stored "$id" "$digest"; }; then
    log "$id already present — skipping (idempotent)."
    return 0
  fi
  if [[ "$DRY_RUN" == "true" ]]; then log "[dry-run] $OLLAMA_BIN pull $source${source:+ -> $id}"; return 0; fi
  until "$OLLAMA_BIN" pull "$source"; do
    if (( attempt >= PULL_RETRIES )); then die "$EX_FAIL" "ollama pull $source failed after ${PULL_RETRIES} attempts"; fi
    warn "pull of $source failed (attempt ${attempt}/${PULL_RETRIES}); retrying in ${delay}s"
    sleep "$delay"; delay=$(( delay * 2 )); attempt=$(( attempt + 1 ))
  done
  if [[ "$source" != "$id" ]]; then
    fragment="$(modelfile_for "$id")"
    if [[ -n "$fragment" ]]; then
      { printf 'FROM %s\n' "$source"; grep -vE '^[[:space:]]*FROM[[:space:]]' "$fragment" || true; } >"$WORK_DIR/$(safe_id "$id").Modelfile"
      "$OLLAMA_BIN" create "$id" -f "$WORK_DIR/$(safe_id "$id").Modelfile"
    else
      "$OLLAMA_BIN" cp "$source" "$id"
    fi
    log "$id registered from $source."
  fi
  if [[ -n "$digest" ]]; then
    verify_stored "$id" "$digest" || die "$EX_INTEGRITY" "$id: pulled weights do not match the pinned SHA-256 ${digest}; refusing to keep them (run: ollama rm $id)"
  fi
  log "$id pulled."
}

find_bundle_gguf() { # find_bundle_gguf <id> <digest>; prints the path
  local id="$1" digest="$2" safe candidate
  safe="$(safe_id "$id")"
  for candidate in "$BUNDLE_DIR/$safe.gguf" "$BUNDLE_DIR/models/$safe.gguf" \
                   "$BUNDLE_DIR/models/blobs/sha256-$digest" "$BUNDLE_DIR/blobs/sha256-$digest"; do
    if [[ -f "$candidate" ]]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}

build_modelfile() { # build_modelfile <id> <gguf> <out>
  local id="$1" gguf="$2" out="$3" template
  template="$(modelfile_for "$id")"
  printf 'FROM %s\n' "$gguf" >"$out"
  if [[ -n "$template" ]]; then grep -vE '^[[:space:]]*FROM[[:space:]]' "$template" >>"$out" || true; fi
}

load_airgap() {
  local id="$1" digest gguf actual
  digest="$(pinned_digest "$id")"
  [[ -n "$digest" ]] || die "$EX_INTEGRITY" "$id has no pinned digest; air-gap loading requires one"
  if model_installed "$id" && verify_stored "$id" "$digest"; then
    log "$id already loaded with the pinned weights — skipping (idempotent)."
    return 0
  fi
  [[ -n "$BUNDLE_DIR" && -d "$BUNDLE_DIR" ]] || die "$EX_FAIL" "airgap profile needs OLLAMA_AIRGAP_BUNDLE_DIR (or --bundle-dir) pointing at the bundle with the GGUF blobs"
  gguf="$(find_bundle_gguf "$id" "$digest")" || die "$EX_FAIL" "$id: no GGUF in $BUNDLE_DIR (expected $(safe_id "$id").gguf or blobs/sha256-${digest:0:12}...)"
  actual="$(sha256_of "$gguf")"
  [[ "$actual" == "$digest" ]] || die "$EX_INTEGRITY" "$id: SHA-256 mismatch for $gguf: expected ${digest}, got ${actual}"
  log "$id: SHA-256 verified for $(basename "$gguf")"
  build_modelfile "$id" "$gguf" "$WORK_DIR/$(safe_id "$id").Modelfile"
  if [[ "$DRY_RUN" == "true" ]]; then log "[dry-run] $OLLAMA_BIN create $id -f $WORK_DIR/$(safe_id "$id").Modelfile (FROM $gguf)"; return 0; fi
  "$OLLAMA_BIN" create "$id" -f "$WORK_DIR/$(safe_id "$id").Modelfile"
  verify_stored "$id" "$digest" || die "$EX_INTEGRITY" "$id: the registered model does not reference the verified blob ${digest}"
  log "$id loaded from the air-gap bundle."
}

main() {
  local models id
  models="$(resolve_models)"
  if [[ -z "$models" ]]; then log "nothing to provision (OLLAMA_PRELOAD_MODELS=none)."; return 0; fi
  log "profile=$PROFILE release=$RELEASE models: $(printf '%s' "$models" | tr '\n' ' ')"
  for id in $models; do
    if [[ "$PROFILE" == "airgap" ]]; then load_airgap "$id"; else pull_connected "$id"; fi
  done
  log "done."
}

main
