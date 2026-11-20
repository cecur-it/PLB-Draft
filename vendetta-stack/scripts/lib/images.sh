# shellcheck shell=bash
# shellcheck disable=SC2034  # VS_PINNED_IMAGES is consumed by the scripts that source this library
#
# scripts/lib/images.sh — the pinned container images of the stack (CONTRACT §1) and helpers to enumerate them.
#
# Traces: PROMPT §3 Phase 3 scripts/build-airgap-bundle.sh; CONTRACT §1 (name:tag@sha256:digest pins, digests
#         verified 2026-11-12), §0 item 8 (locally built images are vendetta-stack/<component>:${STACK_VERSION:-1.0.0}).
#
# images_list prefers the *_IMAGE=name:tag@sha256:… entries of $STACK/.env.example (so the bundle always mirrors
# what compose will pull) and falls back to the built-in contract list when that file is absent.
#
# Requires lib/common.sh.

readonly VS_PINNED_IMAGES=(
  "FLUENT_BIT_IMAGE=fluent/fluent-bit:3.2.10-debug@sha256:ddc7932ed69e1e7bc34a62c57525c49f3947dc5fcee8b92256a33ae1836f3cda"
  "FLUENT_BIT_DISTROLESS_IMAGE=fluent/fluent-bit:3.2.10@sha256:d6dec000c4929a439562525728c708f6e99800d7ddc82efd6aa4f45f3a20b562"
  "FLUENTD_BASE_IMAGE=fluent/fluentd:v1.17-debian-1@sha256:d6114e87fb46d67fef988014cfeb9025df5d48984063dfde94c74cf4a1857440"
  "OPENSEARCH_IMAGE=opensearchproject/opensearch:2.17.1@sha256:1193b7c29c5d63028523728243cc4da047ac49f697a8f8105e5aeee2f89bcc4c"
  "DASHBOARDS_IMAGE=opensearchproject/opensearch-dashboards:2.17.1@sha256:dc12b6f576aae6024780c01b3cc81abdf611d34340371980ef8edc7738479b8f"
  "PROMETHEUS_IMAGE=prom/prometheus:v2.55.1@sha256:2659f4c2ebb718e7695cb9b25ffa7d6be64db013daba13e05c875451cf51b0d3"
  "ALERTMANAGER_IMAGE=prom/alertmanager:v0.27.0@sha256:e13b6ed5cb929eeaee733479dce55e10eb3bc2e9c4586c705a4e8da41e5eacf5"
  "GRAFANA_IMAGE=grafana/grafana:10.4.19@sha256:a9043254ba16fb10945cc27333963dfd08eccbb43b51f1222d831cc564e3a1f4"
  "HAPROXY_IMAGE=haproxy:3.0-alpine@sha256:d2b3567d836f3b7d174edb6d6f611ed5308e7966e53a9cd9a597e0415a298efd"
  "NGINX_IMAGE=nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"
  "PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"
  "OLLAMA_IMAGE=ollama/ollama:0.40.5@sha256:5d3a2f25f9825628daba94dc0b1d421c7d57d6c03ae5faa9ba050e058bab8241"
  "DIND_IMAGE=docker:27-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce"
  "BUSYBOX_IMAGE=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
  "CURL_IMAGE=curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b"
  "VENDETTA_MANAGER_IMAGE=wazuh/wazuh-manager:4.9.2@sha256:b906ebfc77d78446e9b676e1a0b3cd78e2bf3ac2341688f1726b09c29e0aa826"
)

# Components built locally from the repo (CONTRACT §0 item 8 / §13): exactly the `image: vendetta-stack/<name>:${STACK_VERSION}`
# references of docker-compose.yml and the Helm chart. ollama-lb and mock-ollama are stock-image services, not built images.
# errow-sandbox is not part of `docker compose build` (two-step build, errow/RUNTIME.md) and runs INSIDE errow-dind, so the
# air-gap bundle ships it as <bundle>/errow-sandbox.tar (ERROW_SANDBOX_IMAGE_TAR) instead of images/.
readonly VS_BUILT_COMPONENTS=(fluentd llm-gateway errow-mcp errow errow-sandbox errow-feedback errow-shipper ollama)
readonly VS_SANDBOX_COMPONENT=errow-sandbox
readonly VS_SANDBOX_TAR=errow-sandbox.tar

# images_list — "VAR=ref" lines, deduplicated by ref (first variable name wins).
images_list() {
  local f="$STACK_DIR/.env.example" line var ref found=0
  declare -A seen=()
  if [[ -f "$f" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line=${line%$'\r'}
      [[ "$line" =~ ^([A-Z][A-Z0-9_]*_IMAGE)=(.+)$ ]] || continue
      var=${BASH_REMATCH[1]}; ref=${BASH_REMATCH[2]}
      ref=${ref%\"}; ref=${ref#\"}; ref=${ref%\'}; ref=${ref#\'}
      vs_image_pinned "$ref" || continue
      if [[ -z "${seen[$ref]:-}" ]]; then seen[$ref]=1; found=1; printf '%s=%s\n' "$var" "$ref"; fi
    done <"$f"
  fi
  if ((found == 0)); then
    for line in "${VS_PINNED_IMAGES[@]}"; do
      ref=${line#*=}
      if [[ -z "${seen[$ref]:-}" ]]; then seen[$ref]=1; printf '%s\n' "$line"; fi
    done
  fi
}

# images_sandbox_ref — the Errow sandbox image compose runs (ERROW_SANDBOX_IMAGE, default vendetta-stack/errow-sandbox:<version>).
images_sandbox_ref() {
  vs_cfg ERROW_SANDBOX_IMAGE "vendetta-stack/$VS_SANDBOX_COMPONENT:$(vs_cfg STACK_VERSION 1.0.0)"
}

# images_built_refs [--no-sandbox] — references of the locally built images (the sandbox one honours ERROW_SANDBOX_IMAGE).
images_built_refs() {
  local ver c skip_sandbox=0
  if [[ "${1:-}" == --no-sandbox ]]; then skip_sandbox=1; fi
  ver="$(vs_cfg STACK_VERSION 1.0.0)"
  for c in "${VS_BUILT_COMPONENTS[@]}"; do
    if [[ "$c" == "$VS_SANDBOX_COMPONENT" ]]; then
      if ((skip_sandbox)); then continue; fi
      images_sandbox_ref
      printf '\n'
    else
      printf 'vendetta-stack/%s:%s\n' "$c" "$ver"
    fi
  done
}

# images_built_component <ref> — component name of a vendetta-stack/<component>:<tag> reference, empty for anything else
images_built_component() {
  local c
  [[ "$1" == vendetta-stack/*:* ]] || return 0
  c=${1#vendetta-stack/}
  printf '%s' "${c%%:*}"
}

# images_file_name <ref> — deterministic, filesystem-safe tar file name for an image reference
images_file_name() {
  local n=${1%%@*}
  n=${n//\//_}; n=${n//:/_}
  printf '%s.tar' "$n"
}

# images_purl <ref> [digest] — Package URL of an image: pkg:docker/<name>@<digest>?repository_url=<registry>&tag=<tag>
# Locally built images (vendetta-stack/…) carry no repository_url.
images_purl() {
  local ref=$1 digest=${2:-} tag="" name host="" q=""
  if [[ "$ref" == *@sha256:* ]]; then digest=${digest:-${ref##*@}}; ref=${ref%@*}; fi
  if [[ "${ref##*/}" == *:* ]]; then tag=${ref##*:}; ref=${ref%:*}; fi
  name=$ref
  if [[ "$name" == */* && "${name%%/*}" == *.* ]]; then host=${name%%/*}; name=${name#*/}
  elif [[ "$name" != vendetta-stack/* ]]; then host=docker.io
  fi
  name=${name#library/}
  if [[ -n "$host" ]]; then q="repository_url=$host"; fi
  if [[ -n "$tag" ]]; then q+="${q:+&}tag=$tag"; fi
  printf 'pkg:docker/%s%s%s' "$name" "${digest:+@$digest}" "${q:+?$q}"
}
