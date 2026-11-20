#!/usr/bin/env bash
#
# build-airgap-bundle.sh — assemble the signed, reproducible air-gap bundle for the vendetta-stack.
#
# Traces: PROMPT §3 Phase 3 scripts/build-airgap-bundle.sh; CS3 §3.3 air-gap bundle (SHA256SUMS + CycloneDX SBOM +
#         cosign; cecur-it-cs3-v1.1.0/scripts/{build-airgap-bundle,verify-bundle}.mjs); CONTRACT §1 (pinned images),
#         §10 (ollama/models.json pins; sentinel refused with --release).
#
# Run on a CONNECTED staging host. The bundle is later verified inside the enclave with scripts/verify-bundle.sh.
#
# Bundle layout (tar top directory vendetta-stack-airgap-<releaseTag>/):
#   manifest.json            bundle metadata (release tag, images, models, tool versions)
#   images/<name>.tar        `docker save` of every pinned image (CONTRACT §1 / .env.example *_IMAGE) and of the locally
#                            built images fluentd llm-gateway errow-mcp errow errow-feedback errow-shipper ollama
#                            (vendetta-stack/<name>:<STACK_VERSION>); images/images.tsv = ref<TAB>file<TAB>id
#   errow-sandbox.tar        `docker save` of the Errow sandbox image (ERROW_SANDBOX_IMAGE, default
#                            vendetta-stack/errow-sandbox:<STACK_VERSION>) in the bundle ROOT, deliberately not under
#                            images/: it runs inside errow-dind, so it must not be `docker load`ed into the host daemon.
#                            Deploy: compose ERROW_SANDBOX_IMAGE_TAR=/bundle/errow-sandbox.tar (bundle dir mounted at
#                            /bundle); Helm: key errow-sandbox.tar of the errow-bundle PVC. Listed in SHA256SUMS and the
#                            SBOM and recorded in manifest.json (errowSandbox, builtImages); checked by verify-bundle.sh.
#   models/                  Ollama store layout (manifests/…, blobs/sha256-<hex>) for the approved models + digests.json
#   bin/ollama               Ollama binary (version must equal OLLAMA_PINNED_VERSION, default 0.40.5)
#   llama.cpp/               pinned llama.cpp source archive (tag LLAMA_CPP_PINNED_TAG, default b4000) or a prebuilt dir
#   helm/<chart>-<ver>.tgz   kubernetes/helm/vendetta-stack packaged (when the chart exists)
#   config/                  the stack tree (compose, configs, scripts, ollama/models.json …) — never secrets/pki/pki-archive/.env
#   sbom/<image>.cdx.json    per-image SBOMs when `syft` is installed
#   sbom.cdx.json            CycloneDX 1.5 SBOM: one component per file with SHA-256 hashes and purl
#   SHA256SUMS               sha256 of every file above (sorted, "<hash>  <path>")
#   SHA256SUMS.sig [+ .pem]  cosign sign-blob signature over SHA256SUMS   — or —   UNSIGNED  (marker; see below)
#
# Signing: --cosign-key FILE [--cosign-password-file FILE] (keyed, offline-capable, no transparency log upload).
#   Keyless signing needs an OIDC login and the public Sigstore services, so it is refused for the airgap profile /
#   CS3_AIRGAP_ENCLAVE and requires --cosign-keyless otherwise. Without cosign or a key an `UNSIGNED` marker file is
#   written and the script exits 3 only when --require-signature is given.
#
# Determinism: file list sorted, tar --sort=name --mtime=@SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner,
# normalised modes. Same inputs ⇒ identical bundle bytes (docker save output is deterministic per image id).
#
# Docker note: digest-pinned references survive `docker load` only with the containerd image store (default on
# Docker ≥ 29, optional ≥ 25); on the air-gap host verify with `docker image ls --digests` after loading.
#
# Usage: scripts/build-airgap-bundle.sh [options]        (see --help; --dry-run lists what would be bundled)
#
# Exit codes: 0 ok | 1 failure | 2 usage | 3 policy (sentinel pin with --release, signature required but
#             unavailable, version mismatch, private key material in the config tree) | 4 missing prerequisite
#             5 refused (CS3_AIRGAP_ENCLAVE=true without --offline)

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/models.sh
source "$SCRIPT_DIR/lib/models.sh"
# shellcheck source=lib/images.sh
source "$SCRIPT_DIR/lib/images.sh"

trap 'vs_cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
build-airgap-bundle.sh — build the air-gap bundle (images, models, binaries, Helm chart, config, SBOM, SHA256SUMS, signature).

Usage: scripts/build-airgap-bundle.sh [options]

Output:
  --out DIR                  output directory (default $STACK/dist)
  --release-tag TAG          bundle release tag (default: releaseTag of ollama/models.json)
  --release                  production build: refuse sentinel/invalid model pins and a missing built-image set
                             (all 8 built images incl. the Errow sandbox; they cannot be excluded or skipped)
  --source-date-epoch N      timestamp for tar/SBOM (default: SOURCE_DATE_EPOCH, else models.json "updated" date)
  --dry-run                  list what would be bundled; write nothing
  --offline                  never use the network (no docker pull / downloads); required inside an enclave

Content selection:
  --skip-images | --skip-models | --skip-ollama | --skip-llama-cpp | --skip-helm
  --skip-sandbox             leave out errow-sandbox.tar only (--skip-images skips it too); refused with --release
  --build                    run `docker compose build` (all profiles) first; the Errow sandbox is built separately
                             (errow/RUNTIME.md: two docker builds) and must already exist as ERROW_SANDBOX_IMAGE
  --no-pull                  do not `docker pull` missing pinned images (fail instead)
  --image REF                additional image (repeatable); --exclude-image SUBSTR drops images (repeatable)
  --models-dir DIR           Ollama models directory (default $OLLAMA_MODELS, else ~/.ollama/models)
  --models ID,ID             subset of models.json ids (default: all)
  --ollama-binary FILE       Ollama binary (default: `ollama` on PATH)
  --llama-cpp-dir DIR        prebuilt llama.cpp directory | --llama-cpp-src FILE  source archive (default: download tag)
  --no-syft                  skip per-image SBOMs even when syft is installed

Signing:
  --cosign-key FILE          cosign private key (keyed signing)   --cosign-password-file FILE
  --cosign-keyless           keyless (OIDC) signing; refused for airgap/enclave
  --require-signature        exit 3 when the bundle cannot be signed (UNSIGNED)

Other: --stack-dir DIR  --work-dir DIR  -q  -v  -h
Environment: OLLAMA_MODELS, OLLAMA_PINNED_VERSION (0.40.5), LLAMA_CPP_PINNED_TAG (b4000), LLAMA_CPP_URL,
             STACK_VERSION (1.0.0), ERROW_SANDBOX_IMAGE (default vendetta-stack/errow-sandbox:$STACK_VERSION), SOURCE_DATE_EPOCH, COSIGN_PASSWORD (via file only), CS3_PROFILE, CS3_AIRGAP_ENCLAVE

Exit codes: 0 ok | 1 failure | 2 usage | 3 policy | 4 prerequisite | 5 refused (enclave)
EOF
}

OUT_DIR=""
RELEASE_TAG=""
RELEASE=0
EPOCH="${SOURCE_DATE_EPOCH:-}"
OFFLINE=0
SKIP_IMAGES=0; SKIP_SANDBOX=0; SKIP_MODELS=0; SKIP_OLLAMA=0; SKIP_LLAMA=0; SKIP_HELM=0
DO_BUILD=0
NO_PULL=0
NO_SYFT=0
EXTRA_IMAGES=()
EXCLUDE_IMAGES=()
MODELS_SUBSET=""
OLLAMA_BIN=""
LLAMA_DIR=""
LLAMA_SRC=""
COSIGN_KEY=""
COSIGN_PASS_FILE=""
COSIGN_KEYLESS=0
REQUIRE_SIG=0
WORK_DIR=""

reroot() {
  [[ -d "$1" ]] || die "$EX_USAGE" "stack dir not found: $1"
  STACK_DIR="$(cd "$1" && pwd)"
  ENV_FILE="$STACK_DIR/.env"
}

parse_args() {
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]:-}"
  while (($#)); do
    if [[ -z "$1" ]]; then shift; continue; fi
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --dry-run) VS_DRY_RUN=1; shift ;;
      -q|--quiet) VS_QUIET=1; shift ;;
      -v|--verbose) VS_VERBOSE=1; shift ;;
      --out) vs_need "$@"; OUT_DIR=$2; shift 2 ;;
      --release-tag) vs_need "$@"; RELEASE_TAG=$2; shift 2 ;;
      --release) RELEASE=1; shift ;;
      --source-date-epoch) vs_need "$@"; EPOCH=$2; shift 2 ;;
      --offline) OFFLINE=1; shift ;;
      --skip-images) SKIP_IMAGES=1; shift ;;
      --skip-sandbox) SKIP_SANDBOX=1; shift ;;
      --skip-models) SKIP_MODELS=1; shift ;;
      --skip-ollama) SKIP_OLLAMA=1; shift ;;
      --skip-llama-cpp) SKIP_LLAMA=1; shift ;;
      --skip-helm) SKIP_HELM=1; shift ;;
      --build) DO_BUILD=1; shift ;;
      --no-pull) NO_PULL=1; shift ;;
      --no-syft) NO_SYFT=1; shift ;;
      --image) vs_need "$@"; EXTRA_IMAGES+=("$2"); shift 2 ;;
      --exclude-image) vs_need "$@"; EXCLUDE_IMAGES+=("$2"); shift 2 ;;
      --models-dir) vs_need "$@"; MODELS_DIR=$2; shift 2 ;;
      --models) vs_need "$@"; MODELS_SUBSET=$2; shift 2 ;;
      --ollama-binary) vs_need "$@"; OLLAMA_BIN=$2; shift 2 ;;
      --llama-cpp-dir) vs_need "$@"; LLAMA_DIR=$2; shift 2 ;;
      --llama-cpp-src) vs_need "$@"; LLAMA_SRC=$2; shift 2 ;;
      --cosign-key) vs_need "$@"; COSIGN_KEY=$2; shift 2 ;;
      --cosign-password-file) vs_need "$@"; COSIGN_PASS_FILE=$2; shift 2 ;;
      --cosign-keyless) COSIGN_KEYLESS=1; shift ;;
      --require-signature) REQUIRE_SIG=1; shift ;;
      --stack-dir) vs_need "$@"; reroot "$2"; shift 2 ;;
      --work-dir) vs_need "$@"; WORK_DIR=$2; shift 2 ;;
      *) die "$EX_USAGE" "unknown option: $1 (see --help)" ;;
    esac
  done
  if [[ -n "$EPOCH" ]] && ! vs_is_uint "$EPOCH"; then die "$EX_USAGE" "--source-date-epoch must be an integer"; fi
  if [[ -n "$COSIGN_KEY" && $COSIGN_KEYLESS -eq 1 ]]; then die "$EX_USAGE" "--cosign-key and --cosign-keyless are mutually exclusive"; fi
  if [[ -n "$COSIGN_KEY" && ! -f "$COSIGN_KEY" ]]; then die "$EX_USAGE" "cosign key not found: $COSIGN_KEY"; fi
  if [[ -n "$COSIGN_PASS_FILE" && ! -f "$COSIGN_PASS_FILE" ]]; then die "$EX_USAGE" "cosign password file not found: $COSIGN_PASS_FILE"; fi
  return 0
}

# --- state ---------------------------------------------------------------------------------------------
STAGE=""
TOP=""
MODELS_JSON=""
MODEL_IDS=()
declare -A META=()
OLLAMA_PIN_VER="${OLLAMA_PINNED_VERSION:-0.40.5}"
LLAMA_TAG="${LLAMA_CPP_PINNED_TAG:-b4000}"
LLAMA_URL="${LLAMA_CPP_URL:-https://github.com/ggerganov/llama.cpp/archive/refs/tags/$LLAMA_TAG.tar.gz}"
IMAGE_ROWS=()
SANDBOX_ROW=""
BUILT_BUNDLED=()

# models.sh hook: model files are hashed once (cached) because the same pass feeds SHA256SUMS and the SBOM
models_io_hash() { hash_rel "models/$1"; }

# The cache is on disk (not an array) because callers invoke hash_rel inside $(...) subshells.
hash_rel() { # <path relative to $STAGE> — cached sha256
  local rel=$1 key
  key="$VS_WORK/hashcache/${rel//\//__}"
  if [[ ! -s "$key" ]]; then
    mkdir -p "$VS_WORK/hashcache"
    vs_sha256 "$STAGE/$rel" >"$key"
  fi
  cat -- "$key"
}

meta_add() { META[$1]="$2"$'\t'"$3"$'\t'"$4"$'\t'"$5"$'\t'"${6:-}"; } # path type name version purl [description]

image_excluded() {
  local s
  for s in "${EXCLUDE_IMAGES[@]:-}"; do
    [[ -n "$s" ]] || continue
    if [[ "$1" == *"$s"* ]]; then return 0; fi
  done
  return 1
}

# --- policy / prerequisites ----------------------------------------------------------------------------
check_policy() {
  local profile
  profile="$(vs_cfg CS3_PROFILE "")"
  if [[ "${CS3_AIRGAP_ENCLAVE:-}" == "true" && $OFFLINE -eq 0 ]]; then
    die "$EX_NOTREADY" "refusing to build inside an air-gap enclave (CS3_AIRGAP_ENCLAVE=true): bundles are built on a connected staging host. Use --offline to assemble only from local inputs."
  fi
  if ((COSIGN_KEYLESS)) && [[ "$profile" == airgap || "${CS3_AIRGAP_ENCLAVE:-}" == "true" ]]; then
    die "$EX_POLICY" "keyless signing needs OIDC + public Sigstore services and is refused for the airgap profile — use --cosign-key"
  fi
  if ((COSIGN_KEYLESS && OFFLINE)); then die "$EX_POLICY" "--cosign-keyless cannot work with --offline"; fi
  if ((RELEASE && SKIP_IMAGES == 0)); then
    local ref
    if ((SKIP_SANDBOX)); then die "$EX_POLICY" "--release: the Errow sandbox image is part of the release set — drop --skip-sandbox"; fi
    while IFS= read -r ref; do
      if image_excluded "$ref"; then die "$EX_POLICY" "--release: built image $ref cannot be excluded (--exclude-image)"; fi
    done < <(images_built_refs)
  fi
  return 0
}

load_models_json() {
  MODELS_JSON="$STACK_DIR/ollama/models.json"
  vs_require jq
  models_json_validate "$MODELS_JSON" || exit "$EX_USAGE"
  if [[ -z "$RELEASE_TAG" ]]; then RELEASE_TAG="$(jq -r '.releaseTag' "$MODELS_JSON")"; fi
  [[ "$RELEASE_TAG" =~ ^[A-Za-z0-9._-]+$ ]] || die "$EX_USAGE" "invalid release tag '$RELEASE_TAG'"
  if [[ -z "$EPOCH" ]]; then
    local upd
    upd="$(jq -r '.updated // ""' "$MODELS_JSON")"
    if [[ -n "$upd" ]] && EPOCH="$(vs_date_to_epoch "$upd 00:00:00")"; then :; else
      EPOCH="$(date -u +%s)"
      log_warn "no SOURCE_DATE_EPOCH and no models.json 'updated' date — using the current time (bundle will not be byte-reproducible)"
    fi
  fi
  TOP="vendetta-stack-airgap-$RELEASE_TAG"
  local id
  if [[ -n "$MODELS_SUBSET" ]]; then
    IFS=, read -r -a MODEL_IDS <<<"$MODELS_SUBSET"
    local known
    known="$(models_json_ids "$MODELS_JSON")"
    for id in "${MODEL_IDS[@]}"; do
      if ! grep -qxF -- "$id" <<<"$known"; then die "$EX_USAGE" "model '$id' is not in ollama/models.json"; fi
    done
  else
    while IFS= read -r id; do MODEL_IDS+=("$id"); done < <(models_json_ids "$MODELS_JSON")
  fi
}

# --- collectors ----------------------------------------------------------------------------------------
collect_models() {
  local id rel src dst n=0
  if [[ -z "$MODELS_DIR" ]]; then
    if [[ -n "${OLLAMA_MODELS:-}" ]]; then MODELS_DIR=$OLLAMA_MODELS; else MODELS_DIR="$HOME/.ollama/models"; fi
  fi
  [[ -d "$MODELS_DIR/manifests" ]] || die "$EX_PREREQ" "no Ollama models directory at $MODELS_DIR (pull the models there, or use --models-dir / --skip-models)"
  MODELS_DIR="$(cd "$MODELS_DIR" && pwd)"
  mkdir -p "$STAGE/models"
  local digests='{}' layer
  for id in "${MODEL_IDS[@]}"; do
    models_manifest_rel "$id" >/dev/null || die "$EX_USAGE" "invalid model id '$id'"
    models_collect_files "$id" >"$VS_WORK/files.list" || die "$EX_PREREQ" "model $id not found in $MODELS_DIR (run: ollama pull $id)"
    while IFS= read -r rel; do
      src="$MODELS_DIR/$rel"; dst="$STAGE/models/$rel"
      mkdir -p "$(dirname "$dst")"
      if [[ "$rel" == manifests/* ]]; then cp -p -- "$src" "$dst"; else
        [[ -f "$src" ]] || die "$EX_PREREQ" "model $id: blob missing: $src"
        ln -sf -- "$src" "$dst"
      fi
      n=$((n + 1))
    done <"$VS_WORK/files.list"
    layer="$(models_io_read "$(models_manifest_rel "$id")" | models_manifest_model_digest)"
    digests="$(jq --arg id "$id" --arg d "$layer" '. + {($id): $d}' <<<"$digests")"
    meta_add "models/blobs/sha256-$layer" machine-learning-model "$id" "${id##*:}" "pkg:generic/${id%%:*}@${id##*:}?repository_url=registry.ollama.ai" "Ollama weight layer of $id"
  done
  printf '%s\n' "$digests" | jq -S . >"$STAGE/models/digests.json"
  log_ok "models staged: ${#MODEL_IDS[@]} model(s), $n file(s) from $MODELS_DIR"
}

verify_model_pins() {
  local id rc worst=0 sentinel=0
  MODELS_DIR="$STAGE/models"
  for id in "${MODEL_IDS[@]}"; do
    rc=0
    models_check_pin "$MODELS_JSON" "$id" || rc=$?
    case "$rc" in
      0) log_ok "$MODELS_RESULT" ;;
      3) sentinel=1; log_warn "$MODELS_RESULT" ;;
      *) log_err "$MODELS_RESULT"; worst=1 ;;
    esac
  done
  ((worst == 0)) || die "$EX_FAIL" "model verification failed — the models directory does not match ollama/models.json"
  if ((sentinel && RELEASE)); then
    die "$EX_POLICY" "--release refuses unpinned models: run 'node scripts/pin-model-digests.mjs --from-bundle <dir with models/digests.json>' (digests are written to the bundle's models/digests.json) and commit ollama/models.json"
  fi
  if ((sentinel)); then log_warn "bundle contains models whose pins are still the sentinel — NOT releasable (use --release in CI to enforce)"; fi
}

check_image_present() { # <ref> <local:0|1> → 0 present (after optional pull)
  local ref=$1 islocal=$2
  if docker image inspect "$ref" >/dev/null 2>&1 </dev/null; then return 0; fi
  if ((islocal)); then return 1; fi
  if ((NO_PULL || OFFLINE)); then return 1; fi
  log_info "pulling $ref"
  retry 3 5 docker pull --quiet "$ref" >/dev/null </dev/null
}

list_images() { # prints "ref<TAB>local(0|1)" lines for images/: pinned third-party + built images (the sandbox has its own tar)
  local line ref
  declare -A seen=()
  while IFS= read -r line; do
    ref=${line#*=}
    if image_excluded "$ref"; then continue; fi
    if [[ -z "${seen[$ref]:-}" ]]; then seen[$ref]=1; printf '%s\t0\n' "$ref"; fi
  done < <(images_list)
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    if image_excluded "$ref"; then continue; fi
    if [[ -z "${seen[$ref]:-}" ]]; then seen[$ref]=1; printf '%s\t1\n' "$ref"; fi
  done < <(images_built_refs --no-sandbox)
  for ref in "${EXTRA_IMAGES[@]:-}"; do
    [[ -n "$ref" ]] || continue
    if [[ -z "${seen[$ref]:-}" ]]; then seen[$ref]=1; printf '%s\t0\n' "$ref"; fi
  done
}

docker_ready() {
  vs_require docker
  docker info >/dev/null 2>&1 || die "$EX_PREREQ" "docker daemon not reachable"
}

# save_image <ref> <path relative to the bundle root> <sbom name> — docker save + SBOM component (+ per-image syft SBOM);
# sets SAVED_ID.
save_image() {
  local ref=$1 rel=$2 sbom=$3 digest="" purl
  log_info "saving $ref → $rel"
  docker save -o "$STAGE/$rel" "$ref" </dev/null
  SAVED_ID="$(docker image inspect -f '{{.Id}}' "$ref" </dev/null)"
  if [[ "$ref" == *@sha256:* ]]; then digest=${ref##*@}; fi
  purl="$(images_purl "$ref" "${digest:-$SAVED_ID}")"
  meta_add "$rel" container "${ref%%[:@]*}" "${ref#*:}" "$purl" "docker save of $ref (image id $SAVED_ID)"
  if ((SYFT_OK)); then
    mkdir -p "$STAGE/sbom"
    syft "docker-archive:$STAGE/$rel" -o "cyclonedx-json=$STAGE/sbom/$sbom.cdx.json" -q </dev/null \
      || log_warn "syft failed for $ref — continuing without its per-image SBOM"
  fi
}

collect_images() {
  local ref islocal file missing=()
  docker_ready
  if ((DO_BUILD)); then
    vs_compose_init || die "$EX_PREREQ" "--build needs Docker Compose v2"
    log_step "building local images"
    "${COMPOSE[@]}" --profile '*' build
  fi
  SYFT_OK=0
  if ((NO_SYFT == 0)) && vs_have syft; then SYFT_OK=1; fi
  mkdir -p "$STAGE/images"
  : >"$STAGE/images/images.tsv"
  while IFS=$'\t' read -r ref islocal; do
    if ! check_image_present "$ref" "$islocal"; then
      if ((islocal)); then missing+=("$ref"); continue; fi
      die "$EX_PREREQ" "image $ref is not available locally and cannot be pulled (--no-pull/--offline); pull it or drop it with --exclude-image"
    fi
    file="$(images_file_name "$ref")"
    save_image "$ref" "images/$file" "${file%.tar}"
    if [[ -n "$(images_built_component "$ref")" ]]; then BUILT_BUNDLED+=("$ref"); fi
    printf '%s\t%s\t%s\n' "$ref" "images/$file" "$SAVED_ID" >>"$STAGE/images/images.tsv"
    IMAGE_ROWS+=("$ref"$'\t'"images/$file"$'\t'"$SAVED_ID")
  done < <(list_images)
  if ((${#missing[@]})); then
    if ((RELEASE)); then die "$EX_POLICY" "--release: built image(s) not found locally: $(vs_join ", " "${missing[@]}") — run with --build"; fi
    log_warn "built image(s) not found locally and left out of the bundle: $(vs_join ", " "${missing[@]}") — use --build"
  fi
  meta_add images/images.tsv file images.tsv "" "" "image index (ref, file, image id)"
}

# collect_sandbox — errow-sandbox.tar in the bundle root (see the layout notes in the header).
collect_sandbox() {
  local ref
  ref="$(images_sandbox_ref)"
  if image_excluded "$ref"; then log_info "errow sandbox $ref excluded — no $VS_SANDBOX_TAR"; return 0; fi
  docker_ready
  if ! docker image inspect "$ref" >/dev/null 2>&1 </dev/null; then
    if ((RELEASE)); then die "$EX_POLICY" "--release: Errow sandbox image $ref not found locally — build it first (errow/RUNTIME.md: upstream base + Dockerfile.sandbox)"; fi
    log_warn "Errow sandbox image $ref not found locally — the bundle will have no $VS_SANDBOX_TAR (live Errow scans need it; errow/RUNTIME.md)"
    return 0
  fi
  save_image "$ref" "$VS_SANDBOX_TAR" errow-sandbox
  SANDBOX_ROW="$ref"$'\t'"$VS_SANDBOX_TAR"$'\t'"$SAVED_ID"
  log_ok "errow sandbox → $VS_SANDBOX_TAR"
}

collect_ollama() {
  local bin=$OLLAMA_BIN ver=""
  if [[ -z "$bin" ]]; then bin="$(command -v ollama || true)"; fi
  [[ -n "$bin" && -f "$bin" ]] || die "$EX_PREREQ" "Ollama binary not found — pass --ollama-binary FILE or --skip-ollama"
  if ver="$("$bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)" && [[ -n "$ver" ]]; then
    if [[ "$ver" != "$OLLAMA_PIN_VER" ]]; then
      die "$EX_POLICY" "Ollama binary is $ver but the stack pins $OLLAMA_PIN_VER (OLLAMA_PINNED_VERSION)"
    fi
  else
    log_warn "cannot execute $bin to read its version (cross-architecture?) — assuming $OLLAMA_PIN_VER; verify manually"
    ver=$OLLAMA_PIN_VER
  fi
  mkdir -p "$STAGE/bin"
  install -m 0755 "$bin" "$STAGE/bin/ollama"
  meta_add bin/ollama application ollama "$ver" "pkg:github/ollama/ollama@v$ver" "Ollama binary"
  log_ok "ollama binary $ver"
}

collect_llama() {
  mkdir -p "$STAGE/llama.cpp"
  if [[ -n "$LLAMA_DIR" ]]; then
    [[ -d "$LLAMA_DIR" ]] || die "$EX_USAGE" "--llama-cpp-dir not found: $LLAMA_DIR"
    (cd "$LLAMA_DIR" && "$TAR_BIN" -cf - --exclude=.git --exclude='*.o' .) | "$TAR_BIN" -xf - -C "$STAGE/llama.cpp" --no-same-owner
    log_ok "llama.cpp directory copied from $LLAMA_DIR"
  else
    local f="$STAGE/llama.cpp/llama.cpp-$LLAMA_TAG.tar.gz"
    if [[ -n "$LLAMA_SRC" ]]; then
      [[ -f "$LLAMA_SRC" ]] || die "$EX_USAGE" "--llama-cpp-src not found: $LLAMA_SRC"
      cp -p -- "$LLAMA_SRC" "$f"
    else
      ((OFFLINE == 0)) || die "$EX_PREREQ" "--offline: pass --llama-cpp-dir/--llama-cpp-src or --skip-llama-cpp"
      vs_require curl
      log_info "downloading llama.cpp $LLAMA_TAG"
      retry 3 5 curl -fsSL --proto '=https' --tlsv1.2 -o "$f" "$LLAMA_URL"
    fi
    "$TAR_BIN" -tzf "$f" >/dev/null 2>&1 || die "$EX_FAIL" "llama.cpp archive is not a valid .tar.gz"
    meta_add "llama.cpp/llama.cpp-$LLAMA_TAG.tar.gz" library llama.cpp "$LLAMA_TAG" "pkg:github/ggerganov/llama.cpp@$LLAMA_TAG" "llama.cpp source archive"
    log_ok "llama.cpp $LLAMA_TAG archive"
  fi
}

collect_helm() {
  local chart="$STACK_DIR/kubernetes/helm/vendetta-stack" out ver
  if [[ ! -f "$chart/Chart.yaml" ]]; then log_info "no Helm chart at kubernetes/helm/vendetta-stack — skipped"; return 0; fi
  mkdir -p "$STAGE/helm"
  if vs_have helm; then
    helm package "$chart" --destination "$STAGE/helm" >/dev/null
  elif vs_have docker && ((OFFLINE == 0)); then
    docker run --rm -v "$chart:/chart:ro" -v "$STAGE/helm:/out" --user "$(id -u):$(id -g)" alpine/helm:3.16.4 package /chart --destination /out >/dev/null
  else
    die "$EX_PREREQ" "cannot package the Helm chart: install helm (or pass --skip-helm)"
  fi
  out="$(find "$STAGE/helm" -maxdepth 1 -name '*.tgz' | head -n 1)"
  [[ -n "$out" ]] || die "$EX_FAIL" "helm package produced no archive"
  ver="$(sed -n 's/^version:[[:space:]]*//p' "$chart/Chart.yaml" | head -n 1 | tr -d "\"' ")"
  meta_add "helm/$(basename "$out")" application vendetta-stack-helm-chart "${ver:-0}" "pkg:helm/vendetta-stack@${ver:-0}" "Helm chart"
  log_ok "helm chart packaged: $(basename "$out")"
}

collect_config() {
  local extra=() d
  mkdir -p "$STAGE/config"
  # the output directory and a work directory inside the stack must never end up inside their own bundle
  for d in "$OUT_DIR" "$VS_WORK" "$PKI_ARCHIVE_DIR"; do
    if [[ "$d" == "$STACK_DIR"/* ]]; then extra+=("--exclude=./${d#"$STACK_DIR"/}"); fi
  done
  local anchored=() noanchored=()
  if tar_is_gnu; then anchored=(--anchored); noanchored=(--no-anchored); fi
  "$TAR_BIN" -C "$STACK_DIR" -cf - \
    "${anchored[@]}" --exclude=./secrets --exclude=./pki --exclude=./pki-archive --exclude=./backups --exclude=./dist --exclude=./.env --exclude=./.scratch "${extra[@]}" \
    "${noanchored[@]}" --exclude=.git --exclude=__pycache__ --exclude='.venv*' --exclude=node_modules --exclude=.pytest_cache \
    --exclude='*.pyc' --exclude=.scratch --exclude='.work.*' --exclude=SHA256SUMS --exclude='*.sbom.json' --exclude='*.key' \
    . | "$TAR_BIN" -xf - -C "$STAGE/config" --no-same-owner
  if find "$STAGE/config" -type l | grep -q .; then die "$EX_POLICY" "symbolic links in the config tree are not allowed in a bundle: $(find "$STAGE/config" -type l | head -n 3 | tr '\n' ' ')"; fi
  if grep -rIl -E -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$STAGE/config" >"$VS_WORK/keys.list" 2>/dev/null && [[ -s "$VS_WORK/keys.list" ]]; then
    die "$EX_POLICY" "private key material found in the config tree (refusing to bundle): $(head -n 3 "$VS_WORK/keys.list" | sed "s#^$STAGE/##" | tr '\n' ' ')"
  fi
  log_ok "config tree staged ($(find "$STAGE/config" -type f | wc -l) files)"
}

# --- manifest, hashing, SBOM, signing ------------------------------------------------------------------
write_manifest() {
  local images='[]' row models='[]' ref file id built sandbox=null
  for row in "${IMAGE_ROWS[@]:-}"; do
    [[ -n "$row" ]] || continue
    IFS=$'\t' read -r ref file id <<<"$row"
    images="$(jq --arg r "$ref" --arg f "$file" --arg i "$id" '. + [{ref:$r, file:$f, id:$i}]' <<<"$images")"
  done
  built="$(if ((${#BUILT_BUNDLED[@]})); then printf '%s\n' "${BUILT_BUNDLED[@]}" | jq -R . | jq -s -c 'sort'; else echo '[]'; fi)"
  if [[ -n "$SANDBOX_ROW" ]]; then
    IFS=$'\t' read -r ref file id <<<"$SANDBOX_ROW"
    sandbox="$(jq -n -c --arg r "$ref" --arg f "$file" --arg i "$id" '{ref:$r, file:$f, id:$i}')"
  fi
  if ((SKIP_MODELS == 0)); then
    models="$(jq -c '[to_entries[] | {id: .key, weightDigest: .value}]' "$STAGE/models/digests.json")"
  fi
  jq -n -S \
    --arg tag "$RELEASE_TAG" --arg epoch "$EPOCH" --arg ts "$(vs_epoch_to_iso "$EPOCH")" \
    --arg ollama "$OLLAMA_PIN_VER" --arg llama "$LLAMA_TAG" --arg stackver "$(vs_cfg STACK_VERSION 1.0.0)" \
    --argjson images "$images" --argjson models "$models" --argjson built "$built" --argjson sandbox "$sandbox" \
    --argjson ollamaBin "$((SKIP_OLLAMA == 0 ? 1 : 0))" --argjson llamaCpp "$((SKIP_LLAMA == 0 ? 1 : 0))" \
    '{bundleFormat: 1, name: "vendetta-stack-airgap", releaseTag: $tag, stackVersion: $stackver, createdAt: $ts,
      sourceDateEpoch: ($epoch | tonumber), ollamaPinnedVersion: $ollama, llamaCppTag: $llama,
      contains: {images: ($images | length > 0), errowSandbox: ($sandbox != null), models: ($models | length > 0), ollamaBinary: ($ollamaBin == 1), llamaCpp: ($llamaCpp == 1)},
      images: $images, builtImages: $built, errowSandbox: $sandbox, models: $models}' >"$STAGE/manifest.json"
  meta_add manifest.json file manifest.json "" "" "bundle manifest"
}

list_stage_files() { (cd "$STAGE" && find . \( -type f -o -type l \) -print0 | LC_ALL=C sort -z | tr '\0' '\n' | sed 's#^\./##'); }

check_names() {
  local bad rel
  bad="$(list_stage_files | grep -vE '^[A-Za-z0-9._+@=,/-]+$' || true)"
  if [[ -n "$bad" ]]; then die "$EX_POLICY" "file names with unsafe characters cannot be listed in SHA256SUMS: $(printf '%s' "$bad" | head -n 3 | tr '\n' ' ')"; fi
  while IFS= read -r rel; do
    case "/$rel/" in */../*) die "$EX_POLICY" "path traversal in staged file name: $rel" ;; esac
    if [[ -L "$STAGE/$rel" && ! -f "$STAGE/$rel" ]]; then die "$EX_FAIL" "dangling symlink in staging: $rel"; fi
  done < <(list_stage_files)
}

write_sbom() {
  local rel size sha
  : >"$VS_WORK/hashes.tsv"
  while IFS= read -r rel; do
    if [[ "$rel" == sbom.cdx.json ]]; then continue; fi
    sha="$(hash_rel "$rel")"
    size="$(vs_file_size "$STAGE/$rel")"
    printf '%s\t%s\t%s\n' "$rel" "$sha" "$size" >>"$VS_WORK/hashes.tsv"
  done < <(list_stage_files)
  : >"$VS_WORK/meta.tsv"
  for rel in "${!META[@]}"; do printf '%s\t%s\n' "$rel" "${META[$rel]}" >>"$VS_WORK/meta.tsv"; done
  local serial_hex serial
  serial_hex="$(vs_sha256 "$VS_WORK/hashes.tsv")"
  serial="${serial_hex:0:8}-${serial_hex:8:4}-5${serial_hex:13:3}-8${serial_hex:17:3}-${serial_hex:20:12}"
  jq -n -S \
    --rawfile hashes "$VS_WORK/hashes.tsv" --rawfile meta "$VS_WORK/meta.tsv" \
    --arg serial "urn:uuid:$serial" --arg ts "$(vs_epoch_to_iso "$EPOCH")" --arg tag "$RELEASE_TAG" \
    '
    def rows(s): s | split("\n") | map(select(length > 0) | split("\t"));
    (rows($meta) | map({key: .[0], value: {type: .[1], name: .[2], version: .[3], purl: .[4], desc: (.[5] // "")}}) | from_entries) as $m
    | (rows($hashes) | map(
        . as [$path, $sha, $size]
        | ($m[$path] // {type: "file", name: $path, version: "", purl: "", desc: ""}) as $c
        | {type: $c.type, "bom-ref": ("file:" + $path), name: $c.name}
          + (if $c.version != "" then {version: $c.version} else {} end)
          + (if $c.purl != "" then {purl: $c.purl} else {} end)
          + (if $c.desc != "" then {description: $c.desc} else {} end)
          + {hashes: [{alg: "SHA-256", content: $sha}],
             properties: [{name: "vendetta:path", value: $path}, {name: "vendetta:size", value: $size}]}
      )) as $components
    | {bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: $serial, version: 1,
       metadata: {timestamp: $ts,
                  tools: {components: [{type: "application", name: "vendetta-stack build-airgap-bundle.sh", version: "1"}]},
                  component: {type: "application", "bom-ref": "vendetta-stack-airgap", name: "vendetta-stack-airgap", version: $tag}},
       components: $components,
       dependencies: [{ref: "vendetta-stack-airgap", dependsOn: ($components | map(."bom-ref"))}]}
    ' >"$STAGE/sbom.cdx.json"
  log_ok "SBOM written: sbom.cdx.json ($(jq '.components | length' "$STAGE/sbom.cdx.json") components, CycloneDX 1.5)"
}

write_sums() {
  local rel
  : >"$STAGE/SHA256SUMS"
  while IFS= read -r rel; do
    printf '%s  %s\n' "$(hash_rel "$rel")" "$rel" >>"$STAGE/SHA256SUMS"
  done < <(list_stage_files | grep -vxE 'SHA256SUMS|SHA256SUMS\.sig|SHA256SUMS\.pem|UNSIGNED')
  chmod 0644 "$STAGE/SHA256SUMS"
  log_ok "SHA256SUMS written ($(wc -l <"$STAGE/SHA256SUMS") entries)"
}

sign_bundle() {
  local profile why=""
  profile="$(vs_cfg CS3_PROFILE "")"
  if ! vs_have cosign; then why="cosign is not installed"
  elif [[ -z "$COSIGN_KEY" && $COSIGN_KEYLESS -eq 0 ]]; then why="no --cosign-key given (keyless needs --cosign-keyless and is refused for airgap)"
  fi
  if [[ -z "$why" ]]; then
    local args=(sign-blob --yes --output-signature "$STAGE/SHA256SUMS.sig")
    if [[ -n "$COSIGN_KEY" ]]; then
      args+=(--key "$COSIGN_KEY" --tlog-upload=false)
      if [[ -n "$COSIGN_PASS_FILE" ]]; then
        COSIGN_PASSWORD="$(vs_read_secret "$COSIGN_PASS_FILE")" cosign "${args[@]}" "$STAGE/SHA256SUMS" >/dev/null
      else
        COSIGN_PASSWORD="" cosign "${args[@]}" "$STAGE/SHA256SUMS" >/dev/null
      fi
    else
      [[ "$profile" != airgap ]] || die "$EX_POLICY" "keyless signing refused for the airgap profile"
      cosign "${args[@]}" --output-certificate "$STAGE/SHA256SUMS.pem" "$STAGE/SHA256SUMS" >/dev/null
    fi
    [[ -s "$STAGE/SHA256SUMS.sig" ]] || die "$EX_FAIL" "cosign produced no signature"
    log_ok "SHA256SUMS signed with cosign"
    return 0
  fi
  log_warn "bundle is UNSIGNED: $why"
  printf 'UNSIGNED: this bundle was built without a signature (%s).\nDo not deploy it into an air-gapped or production environment.\nSign with: cosign sign-blob --key <key> --output-signature SHA256SUMS.sig SHA256SUMS\n' "$why" >"$STAGE/UNSIGNED"
  if ((REQUIRE_SIG)); then return 3; fi
  return 0
}

# GNU tar gives byte-identical archives (sort + mtime + ownership); bsdtar lacks --sort/--mtime/--format=gnu,
# so fall back to pax with fixed ownership and say so.
TAR_BIN="$(command -v gtar 2>/dev/null || command -v tar 2>/dev/null || true)"
tar_is_gnu() { [[ -n "$TAR_BIN" ]] && "$TAR_BIN" --version 2>/dev/null | grep -qi 'GNU tar'; }

make_tar() {
  local tar_path=$1 tmp
  tmp="$tar_path.partial.$$"
  vs_register_cleanup "$tmp"
  if tar_is_gnu; then
    "$TAR_BIN" -C "$VS_WORK/root" --sort=name --format=gnu --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
      --mode='u+rwX,go+rX,go-w,a-s' -h -cf "$tmp" "$TOP"
  else
    # bsdtar has no --mtime/--sort: normalise mtimes in the staging tree so repeated builds still agree
    local stamp
    stamp="$(date -u -r "$EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
    find "$VS_WORK/root" -exec touch -h -d "$stamp" {} + 2>/dev/null ||
      log_warn "could not normalise mtimes (touch -d unsupported)"
    # symlinked entries are dereferenced by tar -h, so their targets need the stamp too
    find "$VS_WORK/root" -type l -exec touch -d "$stamp" {} + 2>/dev/null || true
    # ustar (not pax): pax headers carry per-build ctime values and would defeat reproducibility
    "$TAR_BIN" -C "$VS_WORK/root" --format ustar --uid 0 --gid 0 --uname root --gname root -h -cf "$tmp" "$TOP"
    log_warn "GNU tar not found: packed with $(basename "$TAR_BIN") (ustar, fixed ownership, normalised mtimes)"
  fi
  mv -f "$tmp" "$tar_path"
  printf '%s  %s\n' "$(vs_sha256 "$tar_path")" "$(basename "$tar_path")" >"$tar_path.sha256"
}

# --- dry run -------------------------------------------------------------------------------------------
dry_run() {
  local id pin ref islocal count have_docker=0
  log_dry "bundle: $TOP.tar  (release tag $RELEASE_TAG, epoch $EPOCH) → ${OUT_DIR#"$STACK_DIR"/}"
  if vs_have docker && docker info >/dev/null 2>&1; then have_docker=1; fi
  if ((SKIP_IMAGES)); then log_dry "images: skipped"; else
    while IFS=$'\t' read -r ref islocal; do
      if ((have_docker == 0)); then log_dry "image   $ref  (docker unavailable: not checked)"
      elif docker image inspect "$ref" >/dev/null 2>&1; then log_dry "image   $ref  (present locally)"
      elif ((islocal)); then log_dry "image   $ref  (LOCAL BUILD MISSING)"
      else log_dry "image   $ref  (would be pulled)"
      fi
    done < <(list_images)
    ref="$(images_sandbox_ref)"
    if ((SKIP_SANDBOX)) || image_excluded "$ref"; then log_dry "sandbox $VS_SANDBOX_TAR: skipped"
    elif ((have_docker == 0)); then log_dry "sandbox $ref → $VS_SANDBOX_TAR  (docker unavailable: not checked)"
    elif docker image inspect "$ref" >/dev/null 2>&1; then log_dry "sandbox $ref → $VS_SANDBOX_TAR  (present locally)"
    else log_dry "sandbox $ref → $VS_SANDBOX_TAR  (LOCAL BUILD MISSING)"
    fi
  fi
  if ((SKIP_MODELS)); then log_dry "models: skipped"; else
    for id in "${MODEL_IDS[@]}"; do
      pin="$(models_pin_state "$(models_json_pin "$MODELS_JSON" "$id")")"
      log_dry "model   $id  (pin: $pin)"
    done
  fi
  if ((SKIP_OLLAMA)); then log_dry "ollama binary: skipped"; else log_dry "ollama binary: ${OLLAMA_BIN:-$(command -v ollama || echo 'NOT FOUND — pass --ollama-binary')} (must be $OLLAMA_PIN_VER)"; fi
  if ((SKIP_LLAMA)); then log_dry "llama.cpp: skipped"; else log_dry "llama.cpp: ${LLAMA_DIR:-${LLAMA_SRC:-$LLAMA_URL}}"; fi
  if ((SKIP_HELM)); then log_dry "helm chart: skipped"; elif [[ -f "$STACK_DIR/kubernetes/helm/vendetta-stack/Chart.yaml" ]]; then log_dry "helm chart: kubernetes/helm/vendetta-stack"; else log_dry "helm chart: not present — skipped"; fi
  count="$(cd "$STACK_DIR" && find . -type f -not -path './secrets/*' -not -path './pki/*' -not -path './pki-archive/*' -not -path './backups/*' -not -path './dist/*' \
    -not -path './.git/*' -not -path './.scratch/*' -not -name .env -not -path '*/__pycache__/*' | wc -l)"
  log_dry "config tree: about $count file(s) (secrets/ pki/ pki-archive/ backups/ dist/ .env .git excluded)"
  log_dry "plus: manifest.json, sbom.cdx.json (CycloneDX 1.5), SHA256SUMS, $(if [[ -n "$COSIGN_KEY" ]]; then echo "SHA256SUMS.sig (cosign key $COSIGN_KEY)"; elif vs_have cosign; then echo "signature (no key given → UNSIGNED)"; else echo "UNSIGNED marker (cosign not installed)"; fi)"
  if ((REQUIRE_SIG)) && { ! vs_have cosign || [[ -z "$COSIGN_KEY" && $COSIGN_KEYLESS -eq 0 ]]; }; then
    log_warn "--require-signature: a real run would exit 3 (no cosign/key)"
  fi
  log_dry "dry run complete — nothing was written"
}

main() {
  parse_args "$@"
  vs_require tar jq openssl
  check_policy
  load_models_json
  OUT_DIR="${OUT_DIR:-$STACK_DIR/dist}"
  if ((VS_DRY_RUN)); then dry_run; exit "$EX_OK"; fi

  if [[ -n "$WORK_DIR" ]]; then
    mkdir -p "$WORK_DIR"
    VS_WORK_ROOT="$(cd "$WORK_DIR" && pwd)"
  fi
  vs_mkwork bundle
  STAGE="$VS_WORK/root/$TOP"
  mkdir -p "$STAGE" "$OUT_DIR"
  OUT_DIR="$(cd "$OUT_DIR" && pwd)"
  log_step "building $TOP (staging in ${VS_WORK#"$STACK_DIR"/})"

  if ((SKIP_MODELS == 0)); then collect_models; verify_model_pins; fi
  if ((SKIP_IMAGES == 0)); then
    collect_images
    if ((SKIP_SANDBOX == 0)); then collect_sandbox; fi
  fi
  if ((SKIP_OLLAMA == 0)); then collect_ollama; fi
  if ((SKIP_LLAMA == 0)); then collect_llama; fi
  if ((SKIP_HELM == 0)); then collect_helm; fi
  collect_config
  write_manifest
  check_names
  write_sbom
  write_sums
  local rc=0
  sign_bundle || rc=$?
  make_tar "$OUT_DIR/$TOP.tar"
  log_ok "bundle: $OUT_DIR/$TOP.tar ($(vs_file_size "$OUT_DIR/$TOP.tar") bytes), sha256 in $TOP.tar.sha256"
  log_info "verify inside the enclave: scripts/verify-bundle.sh $TOP.tar --release --require-signature --cosign-pub <pubkey>"
  if ((rc == 3)); then die "$EX_POLICY" "--require-signature: bundle is UNSIGNED (install cosign and pass --cosign-key)"; fi
  exit "$EX_OK"
}

main "$@"
