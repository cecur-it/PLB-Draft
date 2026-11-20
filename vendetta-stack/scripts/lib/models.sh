# shellcheck shell=bash
# shellcheck disable=SC2034  # MODELS_* result variables are consumed by the scripts that source this library
#
# scripts/lib/models.sh — reads ollama/models.json and verifies Ollama model blobs against the SHA-256 pins.
#
# Traces: PROMPT §1 Tier 4 / §3 Phase 3 scripts/{enroll-ollama,build-airgap-bundle,verify-bundle,backup-opensearch}.sh;
#         CONTRACT §10 (models.json format; "<pinned-per-release>" sentinel), CS3 §3.3 (digest pins in the bundle).
#
# Pin semantics (identical to scripts/pin-model-digests.mjs): models[].sha256 is the SHA-256 of the model's
# weight layer (mediaType application/vnd.ollama.image.model), stored by Ollama as blobs/sha256-<hex> and
# referenced from manifests/registry.ollama.ai/<namespace>/<name>/<tag>.
#
# I/O is routed through three overridable hooks so the same logic verifies a local models directory
# (default) or a container/remote store (enroll-ollama.sh redefines them):
#   models_io_exists REL   models_io_read REL   models_io_hash REL
#
# Requires lib/common.sh and jq.

MODELS_SENTINEL="<pinned-per-release>"
MODELS_LAYER_TYPE="application/vnd.ollama.image.model"
MODELS_DIR="${MODELS_DIR:-}"
MODELS_RESULT=""

models_io_exists() { [[ -f "$MODELS_DIR/$1" ]]; }
models_io_read() { cat -- "$MODELS_DIR/$1"; }
models_io_hash() { vs_sha256 "$MODELS_DIR/$1"; }

# models_json_ids <models.json> — one approved model id per line
models_json_ids() { jq -r '.models[].id' "$1"; }

# models_json_pin <models.json> <id> — raw sha256 field ("" when unknown id)
models_json_pin() { jq -r --arg id "$2" '.models[] | select(.id == $id) | .sha256 // ""' "$1"; }

# models_pin_state <pin> → "sentinel" | "pinned" | "invalid"
models_pin_state() {
  local p=${1#sha256:}
  p="${p,,}"
  if [[ -z "$p" || "$1" == "$MODELS_SENTINEL" ]]; then printf 'sentinel'
  elif [[ "$p" =~ ^[a-f0-9]{64}$ ]]; then printf 'pinned'
  else printf 'invalid'
  fi
}

models_json_validate() { # <file> — JSON shape sanity (full schema validation lives in validate-models-json.sh)
  [[ -f "$1" ]] || { log_err "models.json not found: $1"; return 1; }
  jq -e '(.releaseTag | type == "string") and (.models | type == "array" and length > 0) and (all(.models[]; has("id") and has("sha256")))' "$1" >/dev/null 2>&1 \
    || { log_err "models.json malformed (releaseTag/models[].id/sha256 required): $1"; return 1; }
}

# models_manifest_rel <id> — path of the manifest relative to the models directory
models_manifest_rel() {
  local id=$1 name tag ns=library
  if [[ "$id" != *:* ]]; then id="$id:latest"; fi
  name=${id%:*}; tag=${id##*:}
  if [[ "$name" == */* ]]; then ns=${name%/*}; name=${name##*/}; fi
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ && "$tag" =~ ^[A-Za-z0-9._-]+$ && "$ns" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
  printf 'manifests/registry.ollama.ai/%s/%s/%s' "$ns" "$name" "$tag"
}

# models_blob_rel <sha256:hex|hex> — blob path relative to the models directory
models_blob_rel() { local h=${1#sha256:}; h=${h#sha256-}; [[ "$h" =~ ^[a-f0-9]{64}$ ]] || return 1; printf 'blobs/sha256-%s' "$h"; }

# models_manifest_digests <manifest-json-on-stdin> — every blob digest (config + layers), one hex per line
models_manifest_digests() { jq -r '[.config.digest // empty, (.layers[]?.digest)] | .[]' | sed 's/^sha256://'; }

# models_manifest_model_digest <manifest-json-on-stdin> — hex digest of the weight layer ("" when absent)
models_manifest_model_digest() {
  jq -r --arg t "$MODELS_LAYER_TYPE" '[.layers[]? | select(.mediaType == $t) | .digest] | first // ""' | sed 's/^sha256://'
}

# models_check_pin <models.json> <id> — verify one model against its pin using the I/O hooks.
# Sets MODELS_RESULT to a one-line explanation. Return: 0 verified, 1 missing/mismatch, 3 pin is the sentinel/invalid.
models_check_pin() {
  local json=$1 id=$2 pin state mrel manifest layer blob actual
  pin="$(models_json_pin "$json" "$id")"
  state="$(models_pin_state "$pin")"
  mrel="$(models_manifest_rel "$id")" || { MODELS_RESULT="$id: invalid model id"; return 1; }
  models_io_exists "$mrel" || { MODELS_RESULT="$id: manifest not found ($mrel)"; return 1; }
  manifest="$(models_io_read "$mrel")" || { MODELS_RESULT="$id: manifest unreadable"; return 1; }
  layer="$(printf '%s' "$manifest" | models_manifest_model_digest 2>/dev/null)" || layer=""
  [[ "$layer" =~ ^[a-f0-9]{64}$ ]] || { MODELS_RESULT="$id: manifest has no $MODELS_LAYER_TYPE layer"; return 1; }
  blob="$(models_blob_rel "$layer")"
  models_io_exists "$blob" || { MODELS_RESULT="$id: weight blob missing ($blob)"; return 1; }
  actual="$(models_io_hash "$blob")" || { MODELS_RESULT="$id: cannot hash $blob"; return 1; }
  if [[ "$actual" != "$layer" ]]; then
    MODELS_RESULT="$id: blob content hashes to $actual but its name/manifest says $layer (corrupt or tampered)"
    return 1
  fi
  case "$state" in
    sentinel) MODELS_RESULT="$id: pin is the sentinel $MODELS_SENTINEL (blob sha256 $actual is self-consistent but unpinned)"; return 3 ;;
    invalid) MODELS_RESULT="$id: models.json sha256 is not a 64-hex digest"; return 3 ;;
  esac
  pin=${pin#sha256:}; pin="${pin,,}"
  if [[ "$actual" != "$pin" ]]; then
    MODELS_RESULT="$id: sha256 mismatch — models.json pins $pin, blob is $actual"
    return 1
  fi
  MODELS_RESULT="$id: sha256 $actual matches models.json"
  return 0
}

# models_collect_files <id> — prints the manifest path and every blob path (relative) of a model, one per line.
models_collect_files() {
  local id=$1 mrel d
  mrel="$(models_manifest_rel "$id")" || return 1
  models_io_exists "$mrel" || return 1
  printf '%s\n' "$mrel"
  while IFS= read -r d; do
    [[ "$d" =~ ^[a-f0-9]{64}$ ]] || return 1
    printf 'blobs/sha256-%s\n' "$d"
  done < <(models_io_read "$mrel" | models_manifest_digests)
}
