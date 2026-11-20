# shellcheck shell=bash
# shellcheck disable=SC2016  # single-quoted jq/awk/sed programs and literal $ patterns are intentional
# Cases: sync-mcp-policy.sh, build-airgap-bundle.sh, verify-bundle.sh.

cosign_shim() { # <shim-dir> — deterministic fake cosign: signature = sha256(blob) + sha256(key material)
  write_shim "$1" cosign <<'EOF'
#!/usr/bin/env bash
sub=${1:-}; shift || true
sig=""; key=""; blob=""
while (( $# )); do
  case "$1" in
    --output-signature|--signature) sig=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    --output-certificate|--certificate|--certificate-identity|--certificate-oidc-issuer) shift 2 ;;
    --yes|--tlog-upload=*|--insecure-ignore-tlog=*) shift ;;
    *) blob=$1; shift ;;
  esac
done
digest() { sha256sum <"$1" | cut -d' ' -f1; }
case "$sub" in
  sign-blob) printf '%s:%s\n' "$(digest "$blob")" "$(digest "$key")" >"$sig" ;;
  verify-blob) [[ "$(cat "$sig")" == "$(digest "$blob"):$(digest "$key")" ]] ;;
  *) echo "cosign shim: unsupported: $sub" >&2; exit 1 ;;
esac
EOF
}

bundle_fixture() { # <name> — tree with pinned models, a fake model store, fake ollama binary and llama.cpp dir; sets STORE OLLAMA_FAKE LLAMA_DIR
  new_tree_pki "$1" || return 1
  STORE="$WORK/fx-$1/store"
  fixture_models "$TREE" "$STORE"
  OLLAMA_FAKE="$WORK/fx-$1/ollama-fake"
  printf '#!/bin/sh\necho "ollama version is 0.40.5"\n' >"$OLLAMA_FAKE"
  chmod 0755 "$OLLAMA_FAKE"
  LLAMA_DIR="$WORK/fx-$1/llama-fixture"
  mkdir -p "$LLAMA_DIR"
  printf 'llama.cpp fixture\n' >"$LLAMA_DIR/README"
  printf 'SECRET_THAT_MUST_NOT_SHIP=1\n' >"$TREE/.env"
  # archived key material (a .pem would trip the private-key scan if the archive were not excluded from config/)
  mkdir -p "$TREE/pki-archive/20250101T000000Z"
  cp -p "$TREE/pki/ca.key" "$TREE/pki-archive/20250101T000000Z/ca.key"
  cat "$TREE/pki/errow.key" "$TREE/pki/errow.crt" >"$TREE/pki-archive/20250101T000000Z/errow.pem"
}

build_args() { printf '%s\n' --offline --skip-images --models-dir "$STORE" --ollama-binary "$OLLAMA_FAKE" --llama-cpp-dir "$LLAMA_DIR" --source-date-epoch 1700000000; }

case_sync_mcp_policy() {
  new_tree sp
  t_run "real tree: both policy copies are byte-identical" 0 "$REAL_SCRIPTS/sync-mcp-policy.sh" --check
  t_run "copy: --check passes" 0 "$S/sync-mcp-policy.sh" --check
  printf '\n# drift\n' >>"$TREE/errow/mcp/policy.yaml"
  t_run "drift is detected" 1 "$S/sync-mcp-policy.sh" --check
  out_has "drift reported" '[Dd]rift|differ'
  t_run "default mode is --check" 1 "$S/sync-mcp-policy.sh"
  t_run "--write --dry-run changes nothing" 0 "$S/sync-mcp-policy.sh" --write --dry-run
  t_run "still drifting after the dry run" 1 "$S/sync-mcp-policy.sh" --check
  t_run "--write syncs gateway → errow" 0 "$S/sync-mcp-policy.sh" --write
  t_run "in sync after --write" 0 "$S/sync-mcp-policy.sh" --check
  check "files are byte-identical" cmp "$TREE/llm-gateway/mcp_policy.yaml" "$TREE/errow/mcp/policy.yaml"
  printf '\n# edit in errow\n' >>"$TREE/errow/mcp/policy.yaml"
  t_run "--direction errow-to-gateway" 0 "$S/sync-mcp-policy.sh" --write --direction errow-to-gateway
  check "gateway copy now carries the errow edit" grep -q '# edit in errow' "$TREE/llm-gateway/mcp_policy.yaml"
  rm -f -- "$TREE/errow/mcp/policy.yaml"
  t_run "a missing copy is drift" 1 "$S/sync-mcp-policy.sh" --check
  t_run "bad direction is a usage error" 2 "$S/sync-mcp-policy.sh" --write --direction sideways
}

case_bundle_dry_run() {
  local before
  bundle_fixture bd || return 1
  mapfile -t BA < <(build_args)
  before="$(tree_hashes "$STORE" "$TREE/pki")"
  t_run "build-airgap-bundle --dry-run" 0 "$S/build-airgap-bundle.sh" --dry-run --release "${BA[@]}"
  check_not "dry-run writes no dist/" test -e "$TREE/dist"
  out_has "dry-run lists the models" 'gemma4:26b'
  out_has "dry-run lists the Ollama binary" 'ollama binary'
  out_has "dry-run says the key archives are excluded" 'pki-archive/ .*excluded'
  out_has "dry-run states the signing outcome" 'UNSIGNED|signature'
  eq "inputs untouched" "$before" "$(tree_hashes "$STORE" "$TREE/pki")"
  t_run "--dry-run with --require-signature only warns" 0 "$S/build-airgap-bundle.sh" --dry-run --require-signature "${BA[@]}"
  out_has "dry-run warns that a real run would exit 3" 'would exit 3'
}

case_bundle_build_and_verify() {
  local tar a b top sbom
  mkdir -p "$WORK/fx-mtime"
  bundle_fixture bb || return 1
  mapfile -t BA < <(build_args)
  t_run "real build (--skip-images --release)" 0 "$S/build-airgap-bundle.sh" --release --out "$TREE/dist" "${BA[@]}"
  tar="$(find "$TREE/dist" -maxdepth 1 -name 'vendetta-stack-airgap-*.tar' | head -n 1)"
  check "bundle tarball produced" test -s "$tar"
  check "tarball sha256 sidecar produced" test -s "$tar.sha256"
  check "sidecar matches the tarball" bash -c 'cd "$1" && sha256sum -c "$2" >/dev/null' _ "$TREE/dist" "$(basename "$tar").sha256"
  top="$(tar -tf "$tar" | head -n 1 | cut -d/ -f1)"
  eq "single top-level directory vendetta-stack-airgap-<tag>" "vendetta-stack-airgap-v1.0.0" "$top"
  # GNU tar prints "0/0" and honours --full-time; bsdtar prints "0 root root" and has no --full-time
  check "all entries are owned by 0/0" bash -c '! tar -tvf "$1" | awk "{o=\$2; if (o !~ /\\//) o=\$2\"/\"\$3; gsub(/root/, \"0\", o); print o}" | grep -qvx "0/0"' _ "$tar"
  check "mtimes are the fixed source-date-epoch" bash -c 'tar -xf "$1" -C "$2" --no-same-owner && find "$2" -mindepth 1 | while read -r f; do d="$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f")"; [[ "$d" -le 1700006400 && "$d" -ge 1699920000 ]] || { echo "$f: $d"; exit 1; }; done' _ "$tar" "$WORK/fx-mtime"
  check_not "secrets/pki/pki-archive/.env never ship in the bundle" bash -c 'tar -tf "$1" | grep -Eq "(^|/)(secrets|pki|pki-archive)(/|$)|(^|/)\.env$"' _ "$tar"
  check "tar has SBOM, SHA256SUMS, manifest, UNSIGNED marker" bash -c 'for f in sbom.cdx.json SHA256SUMS manifest.json UNSIGNED bin/ollama; do tar -tf "$1" | grep -q "/$f\$" || exit 1; done' _ "$tar"
  check "tar has model blobs and the models.json pins" bash -c 'tar -tf "$1" | grep -q "/models/blobs/sha256-" && tar -tf "$1" | grep -q "ollama/models.json$"' _ "$tar"
  t_run "build marks the bundle UNSIGNED without cosign" 0 "$S/build-airgap-bundle.sh" --release --out "$TREE/dist2" "${BA[@]}"
  out_has "UNSIGNED warning" 'UNSIGNED'
  b="$(sha256sum <"$TREE/dist2/$(basename "$tar")" | cut -d' ' -f1)"
  a="$(sha256sum <"$tar" | cut -d' ' -f1)"
  eq "the tarball is reproducible (same inputs, same epoch → same sha256)" "$a" "$b"

  mkdir -p "$WORK/fx-bb/x"
  tar -xf "$tar" -C "$WORK/fx-bb/x"
  sbom="$WORK/fx-bb/x/$top/sbom.cdx.json"
  check "SHA256SUMS lists its files in sorted order" bash -c 'awk "{print \$2}" "$1" | LC_ALL=C sort -c' _ "$WORK/fx-bb/x/$top/SHA256SUMS"
  eq "SBOM is CycloneDX 1.5" "CycloneDX 1.5" "$(jq -r '"\(.bomFormat) \(.specVersion)"' "$sbom")"
  check "every non-file SBOM component has a purl" jq -e '[.components[] | select(.type != "file") | select(.purl == null)] | length == 0' "$sbom"
  check "every file component carries a SHA-256 hash" jq -e '[.components[] | select(.type == "file" or .type == "data") | select(((.hashes // []) | map(select(.alg == "SHA-256")) | length) == 0)] | length == 0' "$sbom"
  check "bin/ollama hash in the SBOM equals the file" bash -c 'h="$(jq -r ".components[] | select(.\"bom-ref\" == \"file:bin/ollama\") | .hashes[0].content" "$1")"; [[ "$h" == "$(sha256sum <"$2" | cut -d" " -f1)" ]]' _ "$sbom" "$WORK/fx-bb/x/$top/bin/ollama"
  check "the output directory is not bundled into the config tree" bash -c '! tar -tf "$1" | grep -q "/config/dist"' _ "$tar"

  t_run "verify-bundle on the tarball" 0 "$S/verify-bundle.sh" "$tar" --release --no-state
  out_has "verification passes with the UNSIGNED warning" 'UNSIGNED'
  t_run "verify-bundle on the extracted directory" 0 "$S/verify-bundle.sh" "$WORK/fx-bb/x/$top" --release --no-state
  t_run "verify-bundle writes a verification record" 0 "$S/verify-bundle.sh" "$tar" --release
  check "record <bundle>.verified.json written" test -s "$tar.verified.json"
  t_run "--require-signature rejects an UNSIGNED bundle" 3 "$S/verify-bundle.sh" "$tar" --require-signature --no-state
  t_run "--expect-release-tag mismatch" 2 "$S/verify-bundle.sh" "$tar" --expect-release-tag v9.9.9 --no-state
  t_run "--expect-release-tag match" 0 "$S/verify-bundle.sh" "$tar" --expect-release-tag v1.0.0 --no-state
  t_run "--expect-sha256 with a wrong digest" 2 "$S/verify-bundle.sh" "$tar" --expect-sha256 "$(printf '0%.0s' {1..64})" --no-state
  t_run "--expect-sha256 with the right digest" 0 "$S/verify-bundle.sh" "$tar" --expect-sha256 "$a" --no-state
  t_run "missing bundle path is an I/O error (exit 1)" 1 "$S/verify-bundle.sh" "$TREE/does-not-exist.tar"
}

case_bundle_tamper() {
  local tar top d f
  bundle_fixture bt || return 1
  mapfile -t BA < <(build_args)
  t_run "build for the tamper tests" 0 "$S/build-airgap-bundle.sh" --release --out "$TREE/dist" "${BA[@]}"
  tar="$(find "$TREE/dist" -maxdepth 1 -name 'vendetta-stack-airgap-*.tar' | head -n 1)"
  top="$(tar -tf "$tar" | head -n 1 | cut -d/ -f1)"

  d="$WORK/fx-bt/t1"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  f="$(find "$d/$top/models/blobs" -type f | head -n 1)"
  printf 'tampered' >>"$f"
  t_run "a modified model blob is an integrity failure" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "names SHA256SUMS mismatch" 'mismatch|MISMATCH|FAILED|differs|does not match'

  d="$WORK/fx-bt/t2"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  rm -f -- "$d/$top/bin/ollama"
  t_run "a missing file is an integrity failure" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state

  d="$WORK/fx-bt/t3"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  printf 'backdoor\n' >"$d/$top/extra.sh"
  t_run "an unexpected extra file is rejected" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "extra file named" 'extra\.sh'

  d="$WORK/fx-bt/t4"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  ln -s /etc/passwd "$d/$top/link-out"
  t_run "a symlink inside the bundle is rejected" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state

  d="$WORK/fx-bt/t5"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  jq '(.components[] | select(."bom-ref" == "file:bin/ollama") | .hashes[0].content) = "0000000000000000000000000000000000000000000000000000000000000000"' \
    "$d/$top/sbom.cdx.json" >"$d/sbom.new"
  mv -f "$d/sbom.new" "$d/$top/sbom.cdx.json"
  (cd "$d/$top" && grep -v ' sbom.cdx.json$' SHA256SUMS >SHA256SUMS.new && sha256sum sbom.cdx.json >>SHA256SUMS.new && LC_ALL=C sort -k2 SHA256SUMS.new >SHA256SUMS && rm -f SHA256SUMS.new)
  t_run "an SBOM that disagrees with the files is an integrity failure (even with a consistent SHA256SUMS)" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "SBOM mismatch reported" 'SBOM'

  d="$WORK/fx-bt/t6"; mkdir -p "$d"
  python3 - "$d/evil.tar" <<'EOF'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w") as t:
    for name in ("vendetta-stack-airgap-v1.0.0/SHA256SUMS", "vendetta-stack-airgap-v1.0.0/../../escaped.txt"):
        data = b"x\n"
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
EOF
  t_run "path traversal inside the tarball is rejected" 2 "$S/verify-bundle.sh" "$d/evil.tar" --no-state
  check_not "nothing escaped the extraction directory" test -e "$d/escaped.txt"
  check_not "nothing escaped above the scratch root" test -e "$WORK/fx-bt/escaped.txt"
}

BUILT_COMPONENTS_WANT="errow errow-feedback errow-mcp errow-sandbox errow-shipper fluentd llm-gateway ollama"

bundle_docker_shim() { # <shim-dir> — fake docker; $SHIM_STATE/missing lists refs that `docker image inspect` rejects, calls.log records argv
  write_shim "$1" docker <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SHIM_STATE/calls.log"
case "${1:-}" in
  info) exit 0 ;;
  image)
    shift 2
    fmt=""
    if [[ "$1" == -f ]]; then fmt=$2; shift 2; fi
    if grep -qxF -- "$1" "$SHIM_STATE/missing" 2>/dev/null; then exit 1; fi
    if [[ -n "$fmt" ]]; then printf 'sha256:%s\n' "$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"; fi
    ;;
  save)
    out=$3
    ref=$4
    d="$SHIM_STATE/save.$$"
    mkdir -p "$d"
    printf '[{"Config":"c.json","RepoTags":["%s"],"Layers":[]}]\n' "$ref" >"$d/manifest.json"
    tar -C "$d" -cf "$out" manifest.json
    rm -rf -- "$d"
    ;;
  compose)
    case "$*" in
      *"version --short"*) echo v2.32.4 ;;
      *" build") ;;
      *) echo "docker shim: unsupported: $*" >&2; exit 1 ;;
    esac
    ;;
  *) echo "docker shim: unsupported: $*" >&2; exit 1 ;;
esac
EOF
}

rehash_bundle_file() { # <bundle-dir> <rel> — keep SBOM + SHA256SUMS consistent after a deliberate edit, so only the check under test fires
  local d=$1 rel=$2 h s
  h="$(sha256sum <"$d/$rel" | cut -d' ' -f1)"
  jq --arg r "file:$rel" --arg h "$h" '(.components[] | select(."bom-ref" == $r) | .hashes[0].content) = $h' "$d/sbom.cdx.json" >"$d/sbom.new"
  mv -f "$d/sbom.new" "$d/sbom.cdx.json"
  s="$(sha256sum <"$d/sbom.cdx.json" | cut -d' ' -f1)"
  awk -v r="$rel" -v h="$h" -v s="$s" '$2 == r {print h "  " r; next} $2 == "sbom.cdx.json" {print s "  " $2; next} {print}' "$d/SHA256SUMS" >"$d/SHA256SUMS.new"
  mv -f "$d/SHA256SUMS.new" "$d/SHA256SUMS"
}

case_images_lib() {
  local got
  # ENV_FILE=/dev/null: the host's real .env must not influence the expectations
  imgs() { ENV_FILE=/dev/null bash -c 'source "$1/lib/common.sh"; source "$1/lib/images.sh"; shift; "$@"' _ "$REAL_SCRIPTS" "$@"; }
  got="$(imgs images_built_refs | sed 's|^vendetta-stack/||; s|:.*||' | sort | tr '\n' ' ')"
  eq "built images are exactly the 8 compose/Helm images (no ollama-lb / mock-ollama)" "$BUILT_COMPONENTS_WANT " "$got"
  got="$(imgs images_built_refs --no-sandbox | wc -l | tr -d ' ')"
  eq "--no-sandbox drops only the sandbox" 7 "$got"
  got="$(STACK_VERSION=2.3.4 imgs images_sandbox_ref)"
  eq "the sandbox tag follows STACK_VERSION" "vendetta-stack/errow-sandbox:2.3.4" "$got"
  got="$(ERROW_SANDBOX_IMAGE=registry.example/errow-sbx:7 imgs images_sandbox_ref)"
  eq "ERROW_SANDBOX_IMAGE overrides the sandbox reference" "registry.example/errow-sbx:7" "$got"
  got="$(imgs images_built_component vendetta-stack/errow-mcp:1.0.0; imgs images_built_component nginx:1.27)"
  eq "images_built_component names built images only" "errow-mcp" "$got"
  unset -f imgs
}

case_bundle_images_and_sandbox() {
  local sh st tar top d x ref sb
  bundle_fixture bi || return 1
  sh="$(shims_dir bundle-img)"
  st="$WORK/fx-bi/docker-state"
  mkdir -p "$st"
  bundle_docker_shim "$sh"
  mapfile -t BA < <(build_args | grep -vx -e --skip-images)
  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "dry-run with images (all present)" 0 "$S/build-airgap-bundle.sh" --dry-run --release "${BA[@]}"
  out_has "dry-run lists the sandbox tarball" 'sandbox vendetta-stack/errow-sandbox:1\.0\.0 → errow-sandbox\.tar +\(present locally\)'
  for ref in fluentd llm-gateway errow-mcp errow errow-feedback errow-shipper ollama; do
    out_has "dry-run lists built image $ref" "image +vendetta-stack/$ref:1\\.0\\.0 +\\(present locally\\)"
  done
  out_lacks "ollama-lb and mock-ollama are not bundled images" 'image +vendetta-stack/(ollama-lb|mock-ollama)'
  printf '%s\n' vendetta-stack/errow-sandbox:1.0.0 >"$st/missing"
  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "dry-run with the sandbox image missing" 0 "$S/build-airgap-bundle.sh" --dry-run "${BA[@]}"
  out_has "dry-run flags the missing sandbox image" 'sandbox .*errow-sandbox\.tar +\(LOCAL BUILD MISSING\)'
  : >"$st/missing"
  : >"$st/calls.log"

  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "real build with images + sandbox (--release --build)" 0 "$S/build-airgap-bundle.sh" --release --build --out "$TREE/dist" "${BA[@]}"
  check "--build runs docker compose build for every profile" grep -Fq -- "--profile * build" "$st/calls.log"
  tar="$(find "$TREE/dist" -maxdepth 1 -name 'vendetta-stack-airgap-*.tar' | head -n 1)"
  top="$(tar -tf "$tar" | head -n 1 | cut -d/ -f1)"
  check "errow-sandbox.tar sits in the bundle root" bash -c 'tar -tf "$1" | grep -qx "$2/errow-sandbox.tar"' _ "$tar" "$top"
  check_not "the sandbox is not duplicated under images/" bash -c 'tar -tf "$1" | grep -q "/images/.*errow-sandbox"' _ "$tar"
  for ref in fluentd llm-gateway errow-mcp errow errow-feedback errow-shipper ollama; do
    check "images/ has vendetta-stack/$ref" bash -c 'tar -tf "$1" | grep -qx "$2/images/vendetta-stack_$3_1.0.0.tar"' _ "$tar" "$top" "$ref"
  done
  check_not "no ollama-lb / mock-ollama image tarballs" bash -c 'tar -tf "$1" | grep "/images/" | grep -Eq "ollama-lb|mock-ollama"' _ "$tar"

  x="$WORK/fx-bi/x"
  mkdir -p "$x"
  tar -xf "$tar" -C "$x"
  d="$x/$top"
  check "SHA256SUMS lists errow-sandbox.tar" grep -q '  errow-sandbox\.tar$' "$d/SHA256SUMS"
  check "errow-sandbox.tar hash in SHA256SUMS is correct" bash -c 'cd "$1" && t=$(mktemp) && grep "  errow-sandbox.tar\$" SHA256SUMS >"$t" && sha256sum -c "$t" >/dev/null' _ "$d"
  sb="$(jq -c '.components[] | select(."bom-ref" == "file:errow-sandbox.tar")' "$d/sbom.cdx.json")"
  check "SBOM has an errow-sandbox.tar container component with a purl" jq -e '.type == "container" and (.purl | startswith("pkg:docker/vendetta-stack/errow-sandbox"))' <<<"$sb"
  eq "SBOM hash of errow-sandbox.tar equals the file" "$(sha256sum <"$d/errow-sandbox.tar" | cut -d' ' -f1)" "$(jq -r '.hashes[0].content' <<<"$sb")"
  eq "manifest.errowSandbox names the root tarball and image" "vendetta-stack/errow-sandbox:1.0.0 errow-sandbox.tar" "$(jq -r '.errowSandbox | "\(.ref) \(.file)"' "$d/manifest.json")"
  eq "manifest.builtImages is the 7 compose images" "errow errow-feedback errow-mcp errow-shipper fluentd llm-gateway ollama" \
    "$(jq -r '[.builtImages[] | sub("^vendetta-stack/"; "") | sub(":.*"; "")] | sort | join(" ")' "$d/manifest.json")"
  eq "manifest.contains.errowSandbox is true" true "$(jq -r '.contains.errowSandbox' "$d/manifest.json")"
  eq "images.tsv indexes no sandbox row" 0 "$(grep -c 'errow-sandbox' "$d/images/images.tsv" || true)"

  t_run "verify-bundle accepts the bundle (--release)" 0 "$S/verify-bundle.sh" "$tar" --release --no-state
  out_has "verify reports the sandbox archive" 'errow-sandbox\.tar: docker-save archive of vendetta-stack/errow-sandbox:1\.0\.0'
  t_run "verify-bundle writes a record" 0 "$S/verify-bundle.sh" "$d" --release
  eq "record says the sandbox was verified" verified "$(jq -r '.errowSandbox' "$d.verified.json")"

  d="$x/t1"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  printf 'tampered' >>"$d/$top/errow-sandbox.tar"
  t_run "a modified errow-sandbox.tar is an integrity failure" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "names the sandbox tarball" 'errow-sandbox\.tar'

  d="$x/t2"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  rm -f -- "$d/$top/errow-sandbox.tar"
  t_run "a missing errow-sandbox.tar is an integrity failure" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state

  d="$x/t3"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  jq '.errowSandbox.ref = "vendetta-stack/errow-sandbox:9.9.9"' "$d/$top/manifest.json" >"$d/m.new"
  mv -f "$d/m.new" "$d/$top/manifest.json"
  rehash_bundle_file "$d/$top" manifest.json
  t_run "a sandbox tarball for another image is rejected (hashes consistent)" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "names the mismatching tag" 'not a docker-save archive of vendetta-stack/errow-sandbox:9\.9\.9'

  d="$x/t4"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  jq '.errowSandbox = null | .contains.errowSandbox = false' "$d/$top/manifest.json" >"$d/m.new"
  mv -f "$d/m.new" "$d/$top/manifest.json"
  rehash_bundle_file "$d/$top" manifest.json
  t_run "an undeclared errow-sandbox.tar is rejected" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "undeclared tarball reported" 'declares no errowSandbox'

  d="$x/t5"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  jq '.images += [{"ref": "vendetta-stack/ollama-lb:1.0.0", "file": "images/vendetta-stack_ollama-lb_1.0.0.tar", "id": "sha256:0"}]' "$d/$top/manifest.json" >"$d/m.new"
  mv -f "$d/m.new" "$d/$top/manifest.json"
  rehash_bundle_file "$d/$top" manifest.json
  t_run "a stale ollama-lb image entry is rejected" 2 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "ollama-lb is not a component of the stack" 'vendetta-stack/ollama-lb:1\.0\.0 is not a component'

  d="$x/t6"; mkdir -p "$d"; tar -xf "$tar" -C "$d"
  jq '.images |= map(select(.ref != "vendetta-stack/ollama:1.0.0")) | .builtImages |= map(select(. != "vendetta-stack/ollama:1.0.0"))' "$d/$top/manifest.json" >"$d/m.new"
  mv -f "$d/m.new" "$d/$top/manifest.json"
  rehash_bundle_file "$d/$top" manifest.json
  t_run "--release requires every built image to be in the manifest" 3 "$S/verify-bundle.sh" "$d/$top" --release --no-state
  out_has "names the missing built image" 'built image vendetta-stack/ollama:1\.0\.0 is not in the bundle'
  t_run "without --release a missing built image is tolerated" 0 "$S/verify-bundle.sh" "$d/$top" --no-state
}

case_bundle_images_policy() {
  local sh st tar d
  bundle_fixture bip || return 1
  sh="$(shims_dir bundle-imgp)"
  st="$WORK/fx-bip/docker-state"
  mkdir -p "$st"
  bundle_docker_shim "$sh"
  mapfile -t BA < <(build_args | grep -vx -e --skip-images)
  printf '%s\n' vendetta-stack/errow-sandbox:1.0.0 >"$st/missing"
  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "--release without the sandbox image exits 3" 3 "$S/build-airgap-bundle.sh" --release --out "$TREE/dist-r" "${BA[@]}"
  out_has "names the sandbox build instructions" 'sandbox image .*not found locally.*RUNTIME\.md'
  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "--release --skip-sandbox is refused" 3 "$S/build-airgap-bundle.sh" --release --skip-sandbox --out "$TREE/dist-r2" "${BA[@]}"
  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "--release --exclude-image <built image> is refused" 3 "$S/build-airgap-bundle.sh" --release --exclude-image vendetta-stack/ollama --out "$TREE/dist-r3" "${BA[@]}"
  out_has "names the excluded built image" 'built image vendetta-stack/ollama:1\.0\.0 cannot be excluded'
  printf '%s\n' vendetta-stack/ollama:1.0.0 >>"$st/missing"
  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "non-release build tolerates missing built images + sandbox (warns)" 0 "$S/build-airgap-bundle.sh" --out "$TREE/dist" "${BA[@]}"
  out_has "warns about the missing built image" 'built image\(s\) not found locally.*vendetta-stack/ollama:1\.0\.0'
  out_has "warns about the missing sandbox" 'sandbox image .*not found locally'
  tar="$(find "$TREE/dist" -maxdepth 1 -name 'vendetta-stack-airgap-*.tar' | head -n 1)"
  check_not "no errow-sandbox.tar in the degraded bundle" bash -c 'tar -tf "$1" | grep -q "/errow-sandbox.tar$"' _ "$tar"
  t_run "verify-bundle accepts it without --release (warns)" 0 "$S/verify-bundle.sh" "$tar" --no-state
  out_has "verify warns about the absent sandbox tarball" 'no errow-sandbox\.tar in the bundle'
  t_run "verify-bundle --release rejects a bundle lacking the sandbox + a built image" 3 "$S/verify-bundle.sh" "$tar" --release --no-state
  out_has "release verify names the sandbox tarball" 'bundle has no errow-sandbox\.tar'
  out_has "release verify names the missing built image" 'built image vendetta-stack/ollama:1\.0\.0 is not in the bundle'

  : >"$st/missing"
  SHIM_STATE="$st" PATH="$sh:$PATH" t_run "--skip-sandbox (non-release) leaves the sandbox out" 0 "$S/build-airgap-bundle.sh" --skip-sandbox --out "$TREE/dist-s" "${BA[@]}"
  tar="$(find "$TREE/dist-s" -maxdepth 1 -name 'vendetta-stack-airgap-*.tar' | head -n 1)"
  check_not "no sandbox tarball with --skip-sandbox" bash -c 'tar -tf "$1" | grep -q "/errow-sandbox.tar$"' _ "$tar"
  check "built images are still bundled" bash -c 'tar -tf "$1" | grep -q "/images/vendetta-stack_ollama_1.0.0.tar$"' _ "$tar"
  d="$WORK/fx-bip/x"
  mkdir -p "$d"
  tar -xf "$tar" -C "$d"
  eq "manifest.errowSandbox is null" null "$(jq -c '.errowSandbox' "$d"/*/manifest.json)"
  t_run "--skip-images skips the sandbox too" 0 "$S/build-airgap-bundle.sh" --skip-images --out "$TREE/dist-n" "${BA[@]}"
}

case_bundle_signing() {
  local sh tar top
  bundle_fixture bs2 || return 1
  mapfile -t BA < <(build_args)
  sh="$(shims_dir bundle-sign)"
  cosign_shim "$sh"
  printf 'SHIM-COSIGN-KEY-1\n' >"$TREE/cosign.key"
  printf 'SHIM-COSIGN-KEY-1\n' >"$TREE/cosign.pub"
  printf 'SHIM-COSIGN-KEY-2\n' >"$TREE/other.pub"
  PATH="$sh:$PATH" t_run "signed build (--cosign-key, --require-signature)" 0 "$S/build-airgap-bundle.sh" --release --require-signature --cosign-key "$TREE/cosign.key" --out "$TREE/dist" "${BA[@]}"
  tar="$(find "$TREE/dist" -maxdepth 1 -name 'vendetta-stack-airgap-*.tar' | head -n 1)"
  top="$(tar -tf "$tar" | head -n 1 | cut -d/ -f1)"
  check "SHA256SUMS.sig is inside the bundle" bash -c 'tar -tf "$1" | grep -q "/SHA256SUMS.sig$"' _ "$tar"
  check_not "no UNSIGNED marker in a signed bundle" bash -c 'tar -tf "$1" | grep -q "/UNSIGNED$"' _ "$tar"
  PATH="$sh:$PATH" t_run "verify with the right public key (--require-signature)" 0 "$S/verify-bundle.sh" "$tar" --release --require-signature --cosign-pub "$TREE/cosign.pub" --no-state
  out_has "signature verified" 'cosign signature .*verified'
  PATH="$sh:$PATH" t_run "verify with the wrong public key" 2 "$S/verify-bundle.sh" "$tar" --release --cosign-pub "$TREE/other.pub" --no-state
  PATH="$sh:$PATH" t_run "--require-signature without a trust anchor is a policy failure" 3 "$S/verify-bundle.sh" "$tar" --release --require-signature --no-state
  t_run "--require-signature without cosign installed is a policy failure" 3 env PATH="$(plain_path_dir):/usr/bin:/bin" "$S/verify-bundle.sh" "$tar" --release --require-signature --cosign-pub "$TREE/cosign.pub" --no-state

  t_run "--require-signature build without cosign exits 3" 3 env PATH="$(plain_path_dir):/usr/bin:/bin" "$S/build-airgap-bundle.sh" --release --require-signature --cosign-key "$TREE/cosign.key" --out "$TREE/dist3" "${BA[@]}"
  out_has "UNSIGNED explained" 'UNSIGNED'
  CS3_PROFILE=airgap PATH="$sh:$PATH" t_run "keyless signing is refused for the airgap profile" 3 "$S/build-airgap-bundle.sh" --release --cosign-keyless --out "$TREE/dist4" "${BA[@]}"
  : "$top"
}

case_bundle_sentinel() {
  local tar
  new_tree_pki bsent || return 1
  STORE="$WORK/fx-bsent/store"
  fixture_models "$TREE" "$STORE"
  jq '(.models[].sha256) = "<pinned-per-release>"' "$TREE/ollama/models.json" >"$TREE/ollama/models.json.sentinel" \
    && mv -f "$TREE/ollama/models.json.sentinel" "$TREE/ollama/models.json"   # back to what the pinner leaves per release
  OLLAMA_FAKE="$WORK/fx-bsent/ollama-fake"
  printf '#!/bin/sh\necho "ollama version is 0.40.5"\n' >"$OLLAMA_FAKE"
  chmod 0755 "$OLLAMA_FAKE"
  LLAMA_DIR="$WORK/fx-bsent/llama-fixture"
  mkdir -p "$LLAMA_DIR"
  printf 'x\n' >"$LLAMA_DIR/README"
  mapfile -t BA < <(build_args)
  t_run "--release refuses the <pinned-per-release> sentinel" 3 "$S/build-airgap-bundle.sh" --release --out "$TREE/dist" "${BA[@]}"
  out_has "sentinel named" 'pinned-per-release|sentinel'
  t_run "a non-release build tolerates the sentinel (staging)" 0 "$S/build-airgap-bundle.sh" --out "$TREE/dist2" "${BA[@]}"
  tar="$(find "$TREE/dist2" -maxdepth 1 -name 'vendetta-stack-airgap-*.tar' | head -n 1)"
  t_run "verify-bundle --release refuses the sentinel (exit 3)" 3 "$S/verify-bundle.sh" "$tar" --release --no-state
  t_run "verify-bundle without --release only warns" 0 "$S/verify-bundle.sh" "$tar" --no-state
  printf '#!/bin/sh\necho "ollama version is 0.39.0"\n' >"$OLLAMA_FAKE"
  t_run "an Ollama binary that is not the pinned version is a policy failure" 3 "$S/build-airgap-bundle.sh" --out "$TREE/dist3" "${BA[@]}"
  t_run "missing Ollama binary is a prerequisite error" 4 "$S/build-airgap-bundle.sh" --out "$TREE/dist5" --offline --skip-images --models-dir "$STORE" --ollama-binary "$TREE/nope" --llama-cpp-dir "$LLAMA_DIR"
}
