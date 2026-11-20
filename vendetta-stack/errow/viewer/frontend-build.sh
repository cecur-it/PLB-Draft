#!/usr/bin/env bash
# frontend-build.sh - build the Errow viewer's React/Vite frontend with a pinned node image, without touching the upstream tree.
# Traces: CONTRACT §0 (shell rules), §1 (pinned images), §2 (viewer :8765), §8 (viewer addendum), §11 (RUNTIME.md), §12 (idempotent).
# What it does:
#   * mounts errow/errow/interface/viewer/frontend READ-ONLY, copies it into a private work dir inside the container,
#     runs `npm ci` + `npm run build` (vite writes to ../static there) and publishes the bundle to --out (default viewer/dist/static);
#   * is idempotent: a hash of the sources + node image is stored beside the bundle, an unchanged input is a no-op (--force rebuilds);
#   * air-gap: every online run fills the npm cache dir (--cache, default viewer/.npm-cache). Copy that directory to the offline build
#     host and run with --offline: `npm ci --offline` against the cache and `docker run --network none` (no registry, no internet).
# Using the result: docker build ... --build-arg VIEWER_SOURCE=external  (Dockerfile.errow stage `viewer-external`, stack context
# path viewer/dist/static). The default VIEWER_SOURCE=prebuilt ships the bundle committed upstream, VIEWER_SOURCE=built builds in-image.
# Exit codes: 0 ok | 64 usage | 66 missing source / cache | 69 container runtime unavailable | else: the build's own status.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

PROG=${0##*/}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

NODE_IMAGE=${NODE_IMAGE:-node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee}
SRC=${ERROW_FRONTEND_SRC:-${HERE}/../../../errow/errow/interface/viewer/frontend}
OUT=${ERROW_FRONTEND_OUT:-${HERE}/dist/static}
CACHE=${NPM_CACHE_DIR:-${HERE}/.npm-cache}
DOCKER=${DOCKER:-docker}
WORK=${ERROW_FRONTEND_WORK:-${HERE}/.work}
OFFLINE=false
FORCE=false
DRY_RUN=false
KEEP_WORK=false

usage() {
  cat <<EOF
Usage: ${PROG} [options]

Build the Errow viewer frontend (React + Vite) in a pinned node container; the upstream source is mounted read-only.

Options:
  --src DIR          frontend source (default: errow/errow/interface/viewer/frontend)   [ERROW_FRONTEND_SRC]
  --out DIR          bundle destination (default: viewer/dist/static)                    [ERROW_FRONTEND_OUT]
  --cache DIR        npm cache dir, filled by online runs (default: viewer/.npm-cache)   [NPM_CACHE_DIR]
  --node-image REF   node image (default: pinned node:22-bookworm-slim@sha256:...)       [NODE_IMAGE]
  --offline          air-gap build: npm ci --offline from --cache, container without network
  --force            rebuild even when the input hash is unchanged
  --keep-work        keep the scratch directory (default: removed)
  --dry-run          print the resolved settings and the container command; change nothing
  -h, --help         show this help

Environment: DOCKER (container CLI, default docker; podman works), ERROW_FRONTEND_WORK (scratch dir, default viewer/.work).
Next step: docker build ... --build-arg VIEWER_SOURCE=external   (see errow/README.md and errow/RUNTIME.md)
EOF
}

die() { local code=$1; shift; printf '%s: %s\n' "$PROG" "$*" >&2; exit "$code"; }

while (($#)); do
  case $1 in
    --src) (($# >= 2)) || die 64 "--src needs a value"; SRC=$2; shift 2 ;;
    --out) (($# >= 2)) || die 64 "--out needs a value"; OUT=$2; shift 2 ;;
    --cache) (($# >= 2)) || die 64 "--cache needs a value"; CACHE=$2; shift 2 ;;
    --node-image) (($# >= 2)) || die 64 "--node-image needs a value"; NODE_IMAGE=$2; shift 2 ;;
    --offline) OFFLINE=true; shift ;;
    --force) FORCE=true; shift ;;
    --keep-work) KEEP_WORK=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die 64 "unknown argument: $1" ;;
  esac
done

[[ -f ${SRC}/package.json && -f ${SRC}/package-lock.json ]] || die 66 "no package.json + package-lock.json in ${SRC}"
SRC=$(cd -- "$SRC" && pwd)
mkdir -p -- "$(dirname -- "$OUT")"
OUT=$(cd -- "$(dirname -- "$OUT")" && pwd)/$(basename -- "$OUT")

# input_hash covers every source file (not node_modules / build output) and the node image; --offline does not change the output.
input_hash() {
  {
    printf 'node-image %s\n' "$NODE_IMAGE"
    (cd -- "$SRC" && find . -type f -not -path './node_modules/*' -not -path './dist/*' -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum)
  } | sha256sum | awk '{print $1}'
}

HASH=$(input_hash)
STAMP=$(dirname -- "$OUT")/.$(basename -- "$OUT").input-hash

if [[ $FORCE != true && -f ${OUT}/index.html && -f $STAMP && $(cat -- "$STAMP") == "$HASH" ]]; then
  echo "${PROG}: ${OUT} is up to date (input ${HASH:0:12}); use --force to rebuild"
  exit 0
fi

if [[ $OFFLINE == true ]]; then
  [[ -d ${CACHE}/_cacache ]] || die 66 "--offline needs a populated npm cache in ${CACHE} (run once online, then copy it)"
  NPM_CI_FLAGS="--offline"
  NETWORK_ARGS=(--network none)
else
  NPM_CI_FLAGS="--prefer-offline"
  NETWORK_ARGS=()
fi

# The container script is a fixed string; all variable parts arrive through -e.
read -r -d '' CONTAINER_SCRIPT <<'EOS' || true
set -eu
mkdir -p /work/frontend
cp -a /src/. /work/frontend/
cd /work/frontend
rm -rf node_modules
npm ci --no-audit --no-fund ${NPM_CI_FLAGS}
npm run build
test -f /work/static/index.html
cp -a /work/static/. /out/
EOS

RUN_ARGS=(run --rm --user "$(id -u):$(id -g)" "${NETWORK_ARGS[@]}"
  --cap-drop ALL --security-opt no-new-privileges
  -e HOME=/work -e CI=true -e NPM_CI_FLAGS="$NPM_CI_FLAGS" -e npm_config_cache=/npm-cache -e npm_config_update_notifier=false
  -v "${SRC}:/src:ro" -v "${WORK}/job:/work" -v "${CACHE}:/npm-cache" -v "${OUT}.new:/out"
  -w /work "$NODE_IMAGE" sh -c "$CONTAINER_SCRIPT")

if [[ $DRY_RUN == true ]]; then
  cat <<EOF
${PROG} (dry-run): nothing is changed
  source        ${SRC} (mounted read-only)
  output        ${OUT}
  npm cache     ${CACHE}
  node image    ${NODE_IMAGE}
  mode          $([[ $OFFLINE == true ]] && echo "offline (npm ci --offline, --network none)" || echo "online (cache is filled)")
  input hash    ${HASH}
  command       ${DOCKER} ${RUN_ARGS[*]:0:$((${#RUN_ARGS[@]} - 1))} <fixed npm ci + npm run build script>
EOF
  exit 0
fi

command -v "$DOCKER" >/dev/null 2>&1 || die 69 "container CLI '${DOCKER}' not found (set DOCKER=podman or install Docker)"
"$DOCKER" info >/dev/null 2>&1 || die 69 "cannot reach the container engine via '${DOCKER}'"

# shellcheck disable=SC2317  # installed as an EXIT trap
cleanup() {
  [[ $KEEP_WORK == true ]] || rm -rf -- "${WORK}/job"
  rm -rf -- "${OUT}.new"
  rmdir -- "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf -- "${WORK}/job" "${OUT}.new"
mkdir -p -- "${WORK}/job" "$CACHE" "${OUT}.new"

echo "${PROG}: building ${SRC} -> ${OUT} ($([[ $OFFLINE == true ]] && echo offline || echo online))"
"$DOCKER" "${RUN_ARGS[@]}"

[[ -f ${OUT}.new/index.html ]] || die 70 "build produced no index.html"
printf '%s\n' "$HASH" >"${OUT}.new/.stamp"
rm -rf -- "${OUT}.old"
[[ ! -e $OUT ]] || mv -- "$OUT" "${OUT}.old"
mv -- "${OUT}.new" "$OUT"
mv -- "${OUT}/.stamp" "$STAMP"
rm -rf -- "${OUT}.old"
echo "${PROG}: wrote ${OUT} (input ${HASH:0:12}); use: --build-arg VIEWER_SOURCE=external"
