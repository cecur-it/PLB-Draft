#!/usr/bin/env bash
#
# verify-bundle.sh — verify an air-gap bundle produced by build-airgap-bundle.sh before anything is loaded from it.
#
# Traces: PROMPT §3 Phase 3 scripts/verify-bundle.sh; CS3 §3.3 air-gap bundle parity (SHA256SUMS + CycloneDX SBOM +
#         cosign; cecur-it-cs3-v1.1.0/scripts/verify-bundle.mjs); CONTRACT §10 (models.json pins).
#
# Checks (all are reported; any integrity failure wins over a policy failure):
#   1. the outer <bundle>.tar.sha256 (or --expect-sha256) matches the tarball
#   2. the tar listing is safe: one top directory vendetta-stack-airgap-<tag>/, no absolute or ".." paths, no
#      backslashes, no symlinks/hardlinks/devices, only regular files and directories
#   3. SHA256SUMS is well formed (strict "<64-hex>  <safe path>"), every listed file exists and hashes correctly,
#      and NO file exists that is not listed (only SHA256SUMS, SHA256SUMS.sig/.pem and UNSIGNED are exempt)
#   4. sbom.cdx.json is CycloneDX 1.5; each component's SHA-256 equals the file hash; every file has a component
#   5. cosign signature over SHA256SUMS (--cosign-pub KEY, or keyless --cosign-cert-identity/--cosign-cert-oidc-issuer);
#      --require-signature fails (exit 3) for UNSIGNED / unverifiable bundles
#   6. every bundled model's weight blob matches the sha256 pin in config/ollama/models.json; the sentinel
#      "<pinned-per-release>" is a warning, and a failure (exit 3) with --release
#   7. manifest.json sanity and --expect-release-tag
#   8. container images: every manifest image/builtImages entry is listed and a real component of the stack
#      (fluentd llm-gateway errow-mcp errow errow-feedback errow-shipper ollama); errow-sandbox.tar (bundle root) must be
#      declared by the manifest (errowSandbox), listed in SHA256SUMS + SBOM and be a docker-save archive of that image;
#      --release additionally requires every built image and the sandbox tarball to be present (exit 3).
# On success (and unless --no-state) a 0600 record <bundle>.verified.json is written next to the bundle.
#
# Usage: scripts/verify-bundle.sh <bundle.tar | extracted-dir> [options]      (--help for all options)
#
# Needs tar, jq and a sha256 tool (sha256sum, shasum or openssl); cosign only for signature verification. A tarball is extracted to a
# scratch directory first (needs free space ≈ bundle size; choose it with --extract-dir); an extracted directory is
# verified in place.
#
# Exit codes: 0 verified | 1 usage / cannot read input | 2 integrity failure (hash/SBOM/listing/signature mismatch)
#             3 policy failure (signature required but absent/unverifiable, sentinel/unpinned model with --release)

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
verify-bundle.sh — verify an air-gap bundle (SHA256SUMS, CycloneDX SBOM, cosign, model pins, safe layout).

Usage: scripts/verify-bundle.sh <bundle.tar | extracted-dir> [options]

Options:
  --require-signature          fail (exit 3) when the bundle is UNSIGNED or its signature cannot be verified
  --cosign-pub FILE            cosign public key for keyed verification
  --cosign-cert-identity ID    keyless: expected certificate identity   (with --cosign-cert-oidc-issuer URL)
  --release                    refuse the "<pinned-per-release>" sentinel / unpinned models, and a missing built image or
                               errow-sandbox.tar (exit 3)
  --expect-release-tag TAG     bundle manifest releaseTag must equal TAG
  --expect-sha256 HEX          expected sha256 of the tarball (out-of-band value; overrides <bundle>.sha256)
  --extract-dir DIR            where to extract a tarball (default: scratch under $STACK/.scratch)
  --keep-extracted             keep the extracted tree and print its path
  --no-state                   do not write <bundle>.verified.json
  --work-dir DIR               scratch root (default $STACK/.scratch; VS_WORK_ROOT)
  -q | -v | -h                 quiet | verbose | help

Exit codes: 0 verified | 1 usage/IO | 2 integrity failure | 3 policy failure (signature, sentinel pins)
EOF
}

INPUT=""
REQUIRE_SIG=0
COSIGN_PUB=""
COSIGN_ID=""
COSIGN_ISSUER=""
RELEASE=0
EXPECT_TAG=""
EXPECT_SHA=""
EXTRACT_DIR=""
KEEP=0
WRITE_STATE=1
WORK_DIR=""

parse_args() {
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]:-}"
  while (($#)); do
    if [[ -z "$1" ]]; then shift; continue; fi
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -q|--quiet) VS_QUIET=1; shift ;;
      -v|--verbose) VS_VERBOSE=1; shift ;;
      --require-signature) REQUIRE_SIG=1; shift ;;
      --cosign-pub) vs_need "$@"; COSIGN_PUB=$2; shift 2 ;;
      --cosign-cert-identity) vs_need "$@"; COSIGN_ID=$2; shift 2 ;;
      --cosign-cert-oidc-issuer) vs_need "$@"; COSIGN_ISSUER=$2; shift 2 ;;
      --release) RELEASE=1; shift ;;
      --expect-release-tag) vs_need "$@"; EXPECT_TAG=$2; shift 2 ;;
      --expect-sha256) vs_need "$@"; EXPECT_SHA=${2,,}; shift 2 ;;
      --extract-dir) vs_need "$@"; EXTRACT_DIR=$2; shift 2 ;;
      --keep-extracted) KEEP=1; shift ;;
      --no-state) WRITE_STATE=0; shift ;;
      --work-dir) vs_need "$@"; WORK_DIR=$2; shift 2 ;;
      -*) die "$EX_FAIL" "unknown option: $1 (see --help)" ;;
      *)
        if [[ -n "$INPUT" ]]; then die "$EX_FAIL" "only one bundle may be given (got '$INPUT' and '$1')"; fi
        INPUT=$1; shift ;;
    esac
  done
  [[ -n "$INPUT" ]] || { usage >&2; exit "$EX_FAIL"; }
  if [[ -n "$COSIGN_PUB" && ! -f "$COSIGN_PUB" ]]; then die "$EX_FAIL" "cosign public key not found: $COSIGN_PUB"; fi
  if [[ -n "$COSIGN_ID" && -z "$COSIGN_ISSUER" ]] || [[ -z "$COSIGN_ID" && -n "$COSIGN_ISSUER" ]]; then
    die "$EX_FAIL" "--cosign-cert-identity and --cosign-cert-oidc-issuer must be given together"
  fi
  if [[ -n "$EXPECT_SHA" && ! "$EXPECT_SHA" =~ ^[a-f0-9]{64}$ ]]; then die "$EX_FAIL" "--expect-sha256 must be 64 hex characters"; fi
  return 0
}

INTEGRITY_FAILS=0
POLICY_FAILS=0
SIG_STATUS="unchecked"
MODELS_STATUS="not-bundled"
IMAGES_STATUS="not-bundled"
SANDBOX_STATUS="not-bundled"
BUNDLE_DIR=""
TOP=""
declare -A SUMS=()
declare -A LISTED=()

bad() { log_err "integrity: $*"; INTEGRITY_FAILS=$((INTEGRITY_FAILS + 1)); }
policy() { log_err "policy: $*"; POLICY_FAILS=$((POLICY_FAILS + 1)); }

safe_rel_path() { # <path> — relative, no traversal, only [A-Za-z0-9._+@=,/-]
  local p=$1
  [[ "$p" =~ ^[A-Za-z0-9._+@=,/-]+$ ]] || return 1
  case "/$p/" in */../*|*/./*|*//*) return 1 ;; esac
  [[ "$p" != /* ]]
}

# --- stage 1/2: tarball ---------------------------------------------------------------------------------
check_outer_hash() {
  local actual want="" sidecar="$INPUT.sha256"
  actual="$(vs_sha256 "$INPUT")"
  if [[ -n "$EXPECT_SHA" ]]; then want=$EXPECT_SHA
  elif [[ -f "$sidecar" ]]; then want="$(awk 'NF >= 1 {print tolower($1); exit}' "$sidecar")"
  fi
  if [[ -z "$want" ]]; then log_warn "no $(basename "$sidecar") next to the tarball and no --expect-sha256 — tarball hash not checked (inner SHA256SUMS still is)"; return 0; fi
  if [[ "$actual" == "$want" ]]; then log_ok "tarball sha256 $actual"; else bad "tarball sha256 is $actual, expected $want"; fi
}

# GNU tar escapes names safely; bsdtar does not, so only ask for it when supported.
TAR_BIN="$(command -v gtar 2>/dev/null || command -v tar 2>/dev/null || true)"
TAR_LIST_FLAGS=""
[[ -n "$TAR_BIN" ]] && "$TAR_BIN" --version 2>/dev/null | grep -qi 'GNU tar' && TAR_LIST_FLAGS="--quoting-style=escape"
# bsdtar has no --occurrence: fall back to a plain extraction (docker-save archives list each member once).
TAR_OCC_FLAGS=""
[[ -n "$TAR_BIN" ]] && "$TAR_BIN" --occurrence=1 -tf /dev/null >/dev/null 2>&1 && TAR_OCC_FLAGS="--occurrence=1"

# tar_cat_member <tar> <member> — print one archive member to stdout.
tar_cat_member() {
  if [[ -n "$TAR_OCC_FLAGS" ]]; then "$TAR_BIN" "$TAR_OCC_FLAGS" -xOf "$1" "$2" 2>/dev/null
  else "$TAR_BIN" -xOf "$1" "$2" 2>/dev/null; fi
}

# tar_listing — "perm<TAB>name" per entry; tolerates the GNU (7 fields) and bsdtar (8 fields) -tvf layouts.
# GNU layout: perm owner/group size date(3) name; bsdtar: perm uid uname gname size date(3) name.
tar_listing() {
  local raw start=6 def=10
  if [[ -n "$TAR_LIST_FLAGS" ]]; then raw="$("$TAR_BIN" $TAR_LIST_FLAGS -tvf "$INPUT" 2>/dev/null)"; start=4; def=7
  else raw="$("$TAR_BIN" -tvf "$INPUT" 2>/dev/null)"; fi
  awk -v start="$start" -v def="$def" '{
    n = def
    for (i = start; i <= NF; i++) if ($i ~ /^[0-9][0-9]:[0-9][0-9](:[0-9][0-9])?$/ || $i ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ || $i ~ /^[0-9][0-9][0-9][0-9]$/) { n = i + 1; break }
    name = ""
    for (j = n; j <= NF; j++) name = name (j > n ? " " : "") $j
    print $1 "\t" name
  }' <<<"$raw"
}

check_tar_listing() {
  local perm name type first="" n=0 line
  while IFS=$'\t' read -r perm name; do
    n=$((n + 1))
    type=${perm:0:1}
    case "$type" in
      -|d) ;;
      *) bad "tar entry '$name' has type '$type' (only regular files and directories are allowed)"; continue ;;
    esac
    name=${name%/}
    if [[ -z "$name" ]]; then continue; fi
    if [[ "$name" == *\\* ]]; then bad "tar entry with a backslash/escape in its name: $name"; continue; fi
    if [[ "$name" == /* ]]; then bad "absolute path in tar: $name"; continue; fi
    case "/$name/" in */../*) bad "path traversal in tar: $name"; continue ;; esac
    if ! safe_rel_path "$name"; then bad "unsafe characters in tar entry name: $name"; continue; fi
    if [[ -z "$first" ]]; then first=${name%%/*}; fi
    if [[ "${name%%/*}" != "$first" ]]; then bad "tar has more than one top-level entry ('$first' and '${name%%/*}')"; fi
  done < <(tar_listing)
  if ((n == 0)); then die "$EX_FAIL" "cannot list $INPUT (not a readable tar archive?)"; fi
  [[ "$first" =~ ^vendetta-stack-airgap-[A-Za-z0-9._-]+$ ]] || bad "top-level directory '$first' is not vendetta-stack-airgap-<release tag>"
  TOP=$first
  log_ok "tar listing: $n entries, single top directory '$TOP'"
}

extract_tar() {
  local root
  if [[ -n "$EXTRACT_DIR" ]]; then
    mkdir -p "$EXTRACT_DIR"
    root="$(cd "$EXTRACT_DIR" && pwd)/.verify.$$"
    (umask 077; mkdir "$root")
    if ((KEEP == 0)); then vs_register_cleanup "$root"; fi
    VS_WORK=$root
  else
    if [[ -n "$WORK_DIR" ]]; then mkdir -p "$WORK_DIR"; VS_WORK_ROOT="$(cd "$WORK_DIR" && pwd)"; fi
    vs_mkwork verify
    if ((KEEP)); then VS_CLEANUP_PATHS=(); fi
  fi
  log_info "extracting to ${VS_WORK#"$STACK_DIR"/}"
  tar -xf "$INPUT" -C "$VS_WORK" --no-same-owner --no-same-permissions
  BUNDLE_DIR="$VS_WORK/$TOP"
  [[ -d "$BUNDLE_DIR" ]] || die "$EX_FAIL" "extraction produced no $TOP directory"
  if ((KEEP)); then log_info "extracted tree kept at $BUNDLE_DIR"; fi
}

# --- stage 3: SHA256SUMS ----------------------------------------------------------------------------------
check_tree_shape() {
  local entry rel
  while IFS= read -r -d '' entry; do
    rel=${entry#"$BUNDLE_DIR"/}
    bad "non-regular file in bundle (symlink/device/fifo): $rel"
  done < <(find "$BUNDLE_DIR" -mindepth 1 ! -type f ! -type d -print0)
}

check_sums() {
  local f="$BUNDLE_DIR/SHA256SUMS" line sha path actual n=0 lineno=0 rel
  local req
  for req in manifest.json sbom.cdx.json SHA256SUMS; do
    [[ -f "$BUNDLE_DIR/$req" && ! -L "$BUNDLE_DIR/$req" ]] || bad "required file missing: $req"
  done
  [[ -f "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    if [[ -z "$line" ]]; then bad "SHA256SUMS line $lineno is empty"; continue; fi
    if [[ ! "$line" =~ ^([a-f0-9]{64})\ \ (.+)$ ]]; then bad "SHA256SUMS line $lineno is malformed"; continue; fi
    sha=${BASH_REMATCH[1]}; path=${BASH_REMATCH[2]}
    if ! safe_rel_path "$path"; then bad "SHA256SUMS line $lineno: unsafe path '$path'"; continue; fi
    case "$path" in SHA256SUMS|SHA256SUMS.sig|SHA256SUMS.pem|UNSIGNED) bad "SHA256SUMS must not list $path"; continue ;; esac
    if [[ -n "${LISTED[$path]:-}" ]]; then bad "SHA256SUMS lists $path twice"; continue; fi
    LISTED[$path]=1
    if [[ ! -f "$BUNDLE_DIR/$path" || -L "$BUNDLE_DIR/$path" ]]; then bad "listed file is missing: $path"; continue; fi
    actual="$(vs_sha256 "$BUNDLE_DIR/$path")"
    if [[ "$actual" != "$sha" ]]; then bad "hash mismatch: $path (SHA256SUMS $sha, actual $actual)"; continue; fi
    SUMS[$path]=$sha
    n=$((n + 1))
  done <"$f"
  ((lineno > 0)) || bad "SHA256SUMS is empty"
  while IFS= read -r -d '' rel; do
    rel=${rel#"$BUNDLE_DIR"/}
    case "$rel" in SHA256SUMS|SHA256SUMS.sig|SHA256SUMS.pem|UNSIGNED) continue ;; esac
    if [[ -z "${LISTED[$rel]:-}" ]]; then bad "unexpected file not listed in SHA256SUMS: $rel"; fi
  done < <(find "$BUNDLE_DIR" -type f -print0)
  if ((INTEGRITY_FAILS == 0)); then log_ok "SHA256SUMS: $n file(s) verified, no unexpected files"; fi
}

# --- stage 4: SBOM ----------------------------------------------------------------------------------------
check_sbom() {
  local sbom="$BUNDLE_DIR/sbom.cdx.json" path sha n=0
  [[ -f "$sbom" ]] || return 0
  if ! jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5" and (.components | type == "array")' "$sbom" >/dev/null 2>&1; then
    bad "sbom.cdx.json is not a CycloneDX 1.5 document"
    return 0
  fi
  declare -A sbom_hash=()
  while IFS=$'\t' read -r path sha; do
    if [[ -z "$path" ]]; then bad "SBOM component without a vendetta:path property"; continue; fi
    if [[ -n "${sbom_hash[$path]:-}" ]]; then bad "SBOM lists $path twice"; continue; fi
    sbom_hash[$path]=$sha
  done < <(jq -r '.components[] | [((.properties // [])[] | select(.name == "vendetta:path") | .value) // "", ((.hashes // [])[] | select(.alg == "SHA-256") | .content) // ""] | @tsv' "$sbom")
  for path in "${!sbom_hash[@]}"; do
    n=$((n + 1))
    if [[ -z "${LISTED[$path]:-}" ]]; then bad "SBOM component $path is not listed in SHA256SUMS"; continue; fi
    if [[ -z "${SUMS[$path]:-}" ]]; then continue; fi
    if [[ "${sbom_hash[$path]}" != "${SUMS[$path]}" ]]; then bad "SBOM hash for $path (${sbom_hash[$path]}) differs from the file hash (${SUMS[$path]})"; fi
  done
  for path in "${!LISTED[@]}"; do
    if [[ "$path" == sbom.cdx.json ]]; then continue; fi
    if [[ -z "${sbom_hash[$path]:-}" ]]; then bad "file $path has no SBOM component"; fi
  done
  if ((INTEGRITY_FAILS == 0)); then log_ok "SBOM: $n component hash(es) match the files (CycloneDX 1.5)"; fi
}

# --- stage 5: signature -----------------------------------------------------------------------------------
check_signature() {
  local sums="$BUNDLE_DIR/SHA256SUMS" sig="$BUNDLE_DIR/SHA256SUMS.sig"
  if [[ -f "$BUNDLE_DIR/UNSIGNED" ]]; then
    SIG_STATUS="unsigned"
    if ((REQUIRE_SIG)); then policy "bundle is UNSIGNED and --require-signature was given"; else log_warn "bundle is UNSIGNED (no cosign signature) — acceptable for staging only"; fi
    return 0
  fi
  if [[ ! -f "$sig" ]]; then
    SIG_STATUS="absent"
    if ((REQUIRE_SIG)); then policy "no SHA256SUMS.sig in the bundle and --require-signature was given"; else log_warn "no signature file in the bundle"; fi
    return 0
  fi
  if [[ -z "$COSIGN_PUB" && -z "$COSIGN_ID" ]]; then
    SIG_STATUS="unverified"
    if ((REQUIRE_SIG)); then policy "signature present but no trust anchor given (--cosign-pub, or --cosign-cert-identity + --cosign-cert-oidc-issuer)"; else log_warn "signature present but not verified (no --cosign-pub / certificate identity given)"; fi
    return 0
  fi
  if ! vs_have cosign; then
    SIG_STATUS="unverified"
    if ((REQUIRE_SIG)); then policy "cosign is not installed — cannot verify the signature"; else log_warn "cosign is not installed — signature not verified"; fi
    return 0
  fi
  local args=(verify-blob --signature "$sig")
  if [[ -n "$COSIGN_PUB" ]]; then
    args+=(--key "$COSIGN_PUB" --insecure-ignore-tlog=true)
  else
    [[ -f "$BUNDLE_DIR/SHA256SUMS.pem" ]] || { bad "keyless verification needs SHA256SUMS.pem in the bundle"; SIG_STATUS="invalid"; return 0; }
    args+=(--certificate "$BUNDLE_DIR/SHA256SUMS.pem" --certificate-identity "$COSIGN_ID" --certificate-oidc-issuer "$COSIGN_ISSUER")
  fi
  if cosign "${args[@]}" "$sums" >/dev/null 2>&1; then
    SIG_STATUS="verified"
    log_ok "cosign signature over SHA256SUMS verified"
  else
    SIG_STATUS="invalid"
    bad "cosign signature verification FAILED for SHA256SUMS"
  fi
}

# --- stage 6/7: models + manifest ---------------------------------------------------------------------------
# SHA256SUMS entries were hash-checked above, so the pin check reuses those values instead of re-reading
# multi-GB blobs.
models_io_hash() {
  local rel="models/$1"
  if [[ -n "${SUMS[$rel]:-}" ]]; then printf '%s' "${SUMS[$rel]}"; else vs_sha256 "$BUNDLE_DIR/$rel"; fi
}

check_manifest_and_models() {
  local manifest="$BUNDLE_DIR/manifest.json" tag id json rc layer want got sentinel=0 failed=0 n=0
  [[ -f "$manifest" ]] || return 0
  if ! jq -e '.bundleFormat == 1 and (.releaseTag | type == "string") and (.name == "vendetta-stack-airgap")' "$manifest" >/dev/null 2>&1; then
    bad "manifest.json is malformed or has an unsupported bundleFormat"
    return 0
  fi
  tag="$(jq -r '.releaseTag' "$manifest")"
  if [[ "vendetta-stack-airgap-$tag" != "$TOP" ]]; then bad "manifest releaseTag '$tag' does not match the directory name '$TOP'"; fi
  if [[ -n "$EXPECT_TAG" && "$EXPECT_TAG" != "$tag" ]]; then bad "release tag is '$tag', expected '$EXPECT_TAG'"; fi

  if [[ "$(jq -r '.contains.models' "$manifest")" != "true" ]]; then
    if ((RELEASE)); then log_warn "bundle contains no models — nothing to pin-check"; fi
    return 0
  fi
  json="$BUNDLE_DIR/config/ollama/models.json"
  if [[ ! -f "$json" ]]; then bad "bundle contains models but config/ollama/models.json is missing"; return 0; fi
  if ! models_json_validate "$json"; then bad "config/ollama/models.json is malformed"; return 0; fi
  MODELS_DIR="$BUNDLE_DIR/models"
  while IFS= read -r id; do
    n=$((n + 1))
    rc=0
    models_check_pin "$json" "$id" || rc=$?
    case "$rc" in
      0) log_ok "$MODELS_RESULT" ;;
      3) sentinel=1; log_warn "$MODELS_RESULT" ;;
      *) bad "$MODELS_RESULT"; failed=1 ;;
    esac
    layer="$(models_io_read "$(models_manifest_rel "$id")" 2>/dev/null | models_manifest_model_digest 2>/dev/null || true)"
    want="$(jq -r --arg id "$id" '.[$id] // ""' "$BUNDLE_DIR/models/digests.json" 2>/dev/null || true)"
    got=$layer
    if [[ -n "$want" && "$want" != "$got" ]]; then bad "$id: models/digests.json ($want) disagrees with the manifest weight layer ($got)"; failed=1; fi
  done < <(jq -r '.models[].id' "$manifest")
  if ((failed)); then MODELS_STATUS="failed"; elif ((sentinel)); then MODELS_STATUS="sentinel"; else MODELS_STATUS="pinned"; fi
  if ((sentinel)); then
    if ((RELEASE)); then policy "--release: $n bundled model(s) are not pinned in models.json (sentinel) — run scripts/pin-model-digests.mjs and rebuild"; else log_warn "models are unpinned (sentinel) — re-run with --release in production"; fi
  fi
}

# --- stage 6b: container images + the Errow sandbox tarball ---------------------------------------------------
# sandbox_tags <tar> — image names recorded in a docker-save archive (manifest.json RepoTags; OCI index.json annotations)
sandbox_tags() {
  {
    tar_cat_member "$1" manifest.json | jq -r '.[]? | .RepoTags[]?' 2>/dev/null || true
    tar_cat_member "$1" index.json \
      | jq -r '.manifests[]? | (.annotations // {}) | (."io.containerd.image.name" // empty), (."org.opencontainers.image.ref.name" // empty)' 2>/dev/null || true
  } | sort -u
}

check_images() {
  local manifest="$BUNDLE_DIR/manifest.json" ref file ver c comp sb sb_ref sb_file tags ok n=0 known
  [[ -f "$manifest" ]] || return 0
  if ! jq -e '.bundleFormat == 1 and (.images | type == "array")' "$manifest" >/dev/null 2>&1; then return 0; fi
  declare -A bundled=()
  known=" ${VS_BUILT_COMPONENTS[*]} "
  known=${known//$'\n'/ }
  while IFS=$'\t' read -r ref file; do
    n=$((n + 1))
    bundled[$ref]=1
    case "$file" in images/*.tar) ;; *) bad "manifest image $ref: unexpected file location '$file' (must be images/<name>.tar)" ;; esac
    if [[ -z "${LISTED[$file]:-}" ]]; then bad "manifest image $ref: $file is not listed in SHA256SUMS"; fi
    comp="$(images_built_component "$ref")"
    if [[ -n "$comp" && "$known" != *" $comp "* ]]; then
      bad "image $ref is not a component of this stack (built components: $(vs_join ", " "${VS_BUILT_COMPONENTS[@]}"))"
    elif [[ "$comp" == "$VS_SANDBOX_COMPONENT" ]]; then
      bad "the Errow sandbox image must be shipped as $VS_SANDBOX_TAR in the bundle root, not under images/"
    fi
  done < <(jq -r '.images[] | [.ref, .file] | @tsv' "$manifest")
  while IFS= read -r ref; do
    if [[ -z "${bundled[$ref]:-}" ]]; then bad "builtImages lists $ref but it is not among the bundled images"; fi
  done < <(jq -r '.builtImages[]?' "$manifest")

  sb="$(jq -c '.errowSandbox // null' "$manifest")"
  if [[ "$sb" != null ]]; then
    sb_ref="$(jq -r '.ref // ""' <<<"$sb")"
    sb_file="$(jq -r '.file // ""' <<<"$sb")"
    if [[ "$sb_file" != "$VS_SANDBOX_TAR" ]]; then
      bad "manifest errowSandbox.file is '$sb_file' — the sandbox tarball must be $VS_SANDBOX_TAR in the bundle root"
      SANDBOX_STATUS="failed"
    elif [[ -z "${LISTED[$sb_file]:-}" || ! -f "$BUNDLE_DIR/$sb_file" ]]; then
      bad "$VS_SANDBOX_TAR is declared by the manifest but missing from SHA256SUMS or the bundle"
      SANDBOX_STATUS="failed"
    else
      tags="$(sandbox_tags "$BUNDLE_DIR/$sb_file")"
      ok=0
      while IFS= read -r c; do
        if [[ "$c" == "$sb_ref" || "$c" == "docker.io/$sb_ref" ]]; then ok=1; fi
      done <<<"$tags"
      if ((ok)); then
        SANDBOX_STATUS="verified"
        log_ok "$VS_SANDBOX_TAR: docker-save archive of $sb_ref (hash-checked; load it into errow-dind via ERROW_SANDBOX_IMAGE_TAR)"
      else
        bad "$VS_SANDBOX_TAR is not a docker-save archive of $sb_ref (tags found: ${tags:-none})"
        SANDBOX_STATUS="failed"
      fi
    fi
  else
    if [[ -n "${LISTED[$VS_SANDBOX_TAR]:-}" || -e "$BUNDLE_DIR/$VS_SANDBOX_TAR" ]]; then
      bad "$VS_SANDBOX_TAR is present but manifest.json declares no errowSandbox"
      SANDBOX_STATUS="failed"
    fi
  fi

  if ((n == 0)) && [[ "$sb" == null ]]; then
    if ((RELEASE)); then log_warn "bundle contains no container images — nothing to check"; fi
    return 0
  fi
  IMAGES_STATUS="checked"
  if [[ "$SANDBOX_STATUS" == "not-bundled" ]]; then
    SANDBOX_STATUS="absent"
    if ((RELEASE)); then policy "--release: the bundle has no $VS_SANDBOX_TAR (Errow sandbox image) — rebuild with the sandbox image present"; else log_warn "no $VS_SANDBOX_TAR in the bundle — live Errow scans in the enclave need the sandbox image"; fi
  fi
  if ((RELEASE)); then
    ver="$(jq -r '.stackVersion // ""' "$manifest")"
    for c in "${VS_BUILT_COMPONENTS[@]}"; do
      if [[ "$c" == "$VS_SANDBOX_COMPONENT" ]]; then continue; fi
      if [[ -z "${bundled[vendetta-stack/$c:$ver]:-}" ]]; then policy "--release: built image vendetta-stack/$c:$ver is not in the bundle"; fi
    done
  fi
}

write_state() {
  local state="${INPUT%/}.verified.json" sums_sha=""
  if [[ -f "$BUNDLE_DIR/SHA256SUMS" ]]; then sums_sha="$(vs_sha256 "$BUNDLE_DIR/SHA256SUMS")"; fi
  if jq -n -S --arg at "$(vs_now_iso)" --arg b "$(basename "${INPUT%/}")" --arg tag "$(jq -r '.releaseTag' "$BUNDLE_DIR/manifest.json")" \
    --arg sums "$sums_sha" --arg sig "$SIG_STATUS" --arg models "$MODELS_STATUS" --arg images "$IMAGES_STATUS" --arg sandbox "$SANDBOX_STATUS" \
    --argjson release "$((RELEASE ? 1 : 0))" \
    '{result: "verified", verifiedAt: $at, bundle: $b, releaseTag: $tag, sha256sumsSha256: $sums, signature: $sig, models: $models, images: $images, errowSandbox: $sandbox, releaseMode: ($release == 1)}' \
    | vs_atomic_write "$state" 0600 2>/dev/null; then
    log_info "verification record: $state"
  else
    log_warn "could not write $state (read-only location) — use --no-state to silence"
  fi
}

main() {
  parse_args "$@"
  local shatool
  shatool="$(vs_have sha256sum && echo sha256sum || { vs_have shasum && echo shasum || echo openssl; })"
  vs_require jq tar "$shatool"
  if [[ -d "$INPUT" ]]; then
    BUNDLE_DIR="$(cd "$INPUT" && pwd)"
    TOP="$(basename "$BUNDLE_DIR")"
    [[ "$TOP" =~ ^vendetta-stack-airgap-[A-Za-z0-9._-]+$ ]] || bad "directory name '$TOP' is not vendetta-stack-airgap-<release tag>"
  elif [[ -f "$INPUT" ]]; then
    log_step "verifying tarball $INPUT"
    check_outer_hash
    check_tar_listing
    if ((INTEGRITY_FAILS)); then
      log_err "the tarball failed its safety checks — it was NOT extracted"
      exit 2
    fi
    extract_tar
  else
    die "$EX_FAIL" "bundle not found: $INPUT"
  fi
  check_tree_shape
  check_sums
  check_sbom
  check_signature
  check_manifest_and_models
  check_images
  if ((INTEGRITY_FAILS)); then
    log_err "bundle verification FAILED: $INTEGRITY_FAILS integrity problem(s)$(if ((POLICY_FAILS)); then printf ', %s policy problem(s)' "$POLICY_FAILS"; fi)"
    exit 2
  fi
  if ((POLICY_FAILS)); then
    log_err "bundle verification FAILED policy: $POLICY_FAILS problem(s)"
    exit 3
  fi
  if ((WRITE_STATE)); then write_state; fi
  log_ok "bundle verified: signature=$SIG_STATUS models=$MODELS_STATUS"
  exit "$EX_OK"
}

main "$@"
