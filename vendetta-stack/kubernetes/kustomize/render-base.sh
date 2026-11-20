#!/usr/bin/env bash
#
# render-base.sh - render the Helm chart's default values into kubernetes/kustomize/base/resources.yaml.
#
# Traces: PROMPT section 1 Tier 3 (kustomize overlays); CONTRACT section 2 (one manifest set, two packagings).
#
# The kustomize base is not maintained by hand: it is `helm template` output of kubernetes/helm/vendetta-stack with its
# default values (release and namespace "vendetta-stack"), so the Helm chart stays the single source of truth. The overlays
# dev/onprem/airgap patch that output. Helm is taken from PATH, otherwise from the alpine/helm container image.
#
#   --check  (default)  exit 1 when base/resources.yaml differs from a fresh render
#   --write             regenerate base/resources.yaml
#
# Exit codes: 0 up to date (or written) | 1 drift or render failure | 2 usage

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELM_DIR="$(cd "$SCRIPT_DIR/../helm" && pwd)"
OUT="$SCRIPT_DIR/base/resources.yaml"
RELEASE="vendetta-stack"
NAMESPACE="vendetta-stack"
HELM_IMAGE="${HELM_IMAGE:-alpine/helm:3.16.4}"
ACTION="check"

usage() {
  cat <<'EOF'
render-base.sh - render kubernetes/kustomize/base/resources.yaml from the Helm chart defaults.

Usage: render-base.sh [--check | --write] [-h]

  --check   (default) exit 1 when base/resources.yaml differs from a fresh render
  --write   regenerate base/resources.yaml

Environment:
  HELM_IMAGE   container image used when `helm` is not on PATH (default alpine/helm:3.16.4)

Exit codes: 0 up to date/written | 1 drift or render failure | 2 usage
EOF
}

while (($#)); do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --check) ACTION="check" ;;
    --write) ACTION="write" ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

render() {
  if command -v helm >/dev/null 2>&1; then
    (cd "$HELM_DIR" && helm template "$RELEASE" ./vendetta-stack --namespace "$NAMESPACE")
  elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v "$HELM_DIR":/w:ro -w /w "$HELM_IMAGE" template "$RELEASE" ./vendetta-stack --namespace "$NAMESPACE"
  else
    echo "neither helm nor docker is available to render the chart" >&2
    return 1
  fi
}

case "$ACTION" in
  write)
    rendered="$(render)"
    printf '%s\n' "$rendered" >"$OUT"
    echo "wrote kubernetes/kustomize/${OUT#"$SCRIPT_DIR"/}"
    ;;
  check)
    [[ -f "$OUT" ]] || { echo "missing $OUT (run with --write)" >&2; exit 1; }
    rendered="$(render)"
    if ! diff -u "$OUT" <(printf '%s\n' "$rendered") >/dev/null; then
      echo "kustomize base is out of date; run kubernetes/kustomize/render-base.sh --write" >&2
      exit 1
    fi
    echo "kustomize base is up to date"
    ;;
esac
