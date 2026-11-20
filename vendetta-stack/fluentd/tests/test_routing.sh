#!/usr/bin/env bash
# Traces: PROMPT §4.3 telemetry-loop prevention, §3 Data flow, §6 Closed loop, §4 Phase 4 (validation); CONTRACT §3, §5, §6
# Proves, on the real Fluentd image, that
#   1. (static, source tree)    only 13-filter-ai-ollama.conf and 15-routing.conf mention cs3.ai.ollama, its match is the FIRST root match and
#                               relabels to @ESOC_SIEM only, and no tag-rewriting plugin exists anywhere in the tree;
#   2. (static, rendered tree)  routing_graph.rb (Fluentd's own config parser + MatchPattern) walks match/copy/relabel for 29 tags in
#                               four variants (default, node 2 + all aggregator legs, live execd leg) and checks the terminal outputs;
#   3. (behavioural)            a throw-away docker network runs the aggregator against tests/stubs.py (OpenSearch with 409-on-duplicate-create,
#                               mTLS gateway, Vendetta manager, feedback, ESOC, SIEM, cloud) and flow_test.py sends events over mTLS and asserts.
# --static-only skips (3). The behavioural run needs ~90 s and ~400 MB RAM. Scratch lives in fluentd/.scratch/ and is removed on exit.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLUENTD_DIR="$(dirname "$HERE")"
STACK="$(dirname "$FLUENTD_DIR")"
IMAGE="${FLUENTD_IMAGE:-vendetta-stack/fluentd:dev}"
RUNNER_IMAGE="${FLB_IMAGE:-fluent/fluent-bit:3.2.10-debug@sha256:ddc7932ed69e1e7bc34a62c57525c49f3947dc5fcee8b92256a33ae1836f3cda}"
RUN_ID="$$"
SCRATCH="$FLUENTD_DIR/.scratch/routing-$RUN_ID"
NET="vs-fluentd-test-$RUN_ID"
STUBS="vs-fluentd-stubs-$RUN_ID"
AGG="vs-fluentd-agg-$RUN_ID"
WAIT="${TEST_WAIT:-90}"
STATIC_ONLY=false
KEEP=false
PASS=0
FAIL=0

usage() {
  cat <<EOF
Usage: test_routing.sh [--static-only] [--keep] [-h|--help]
  Static + behavioural routing proof for the Fluentd aggregator (see header). Image: built from ../ as $IMAGE unless FLUENTD_IMAGE names a prebuilt one.
  --static-only  skip the docker-network behavioural run     --keep  keep fluentd/.scratch/routing-* and the metrics dump
  Env: TEST_WAIT (seconds to wait for flushes, default $WAIT), FLB_IMAGE (python runner = pinned Fluent Bit debug image)
EOF
}
for arg in "$@"; do
  case "$arg" in
    -h | --help) usage; exit 0 ;;
    --static-only) STATIC_ONLY=true ;;
    --keep) KEEP=true ;;
    *) usage >&2; exit 2 ;;
  esac
done

cleanup() {
  local rc=$?
  docker rm -f "$AGG" "$STUBS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [[ $KEEP == false ]]; then
    rm -rf "$SCRATCH" 2>/dev/null || docker run --rm -v "$FLUENTD_DIR/.scratch:/s" --entrypoint rm "$RUNNER_IMAGE" -rf "/s/routing-$RUN_ID" >/dev/null 2>&1 || true
  fi
  return "$rc"
}
trap cleanup EXIT

ok() { PASS=$((PASS + 1)); echo "  PASS  $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $*" >&2; }
retry() { # retry <attempts> <delay> <command...>
  local n=$1 d=$2 i
  shift 2
  for ((i = 1; i <= n; i++)); do
    if "$@"; then return 0; fi
    ((i < n)) && sleep "$d"
  done
  return 1
}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 3; }
mkdir -p "$SCRATCH/out" "$SCRATCH/data" "$SCRATCH/secrets"
chmod 0777 "$SCRATCH/out" "$SCRATCH/data"
if [[ -n ${FLUENTD_IMAGE:-} ]]; then docker image inspect "$IMAGE" >/dev/null; else retry 2 5 docker build -q -t "$IMAGE" "$FLUENTD_DIR" >/dev/null; fi

"$STACK/fluent-bit/tests/make-pki.sh" "$SCRATCH/pki" fluent-bit fluentd-1 fluentd-2 opensearch llm-gateway vendetta-manager esoc-sink siem-sink cloud-sink >/dev/null
for s in opensearch_admin_password llm_gateway_token feedback_webhook_token errow_api_token vendetta_api_password esoc_token siem_token; do
  [[ -s "$SCRATCH/secrets/$s" ]] || printf 'fixture-%s' "$s" >"$SCRATCH/secrets/$s"
done
chmod -R a+rX "$SCRATCH/pki" "$SCRATCH/secrets"

echo "== 1. static source-tree invariants"
active() { grep -vE '^[[:space:]]*#' "$@"; } # config lines without comments
mention=$(cd "$FLUENTD_DIR" && for f in fluent.conf conf.d/*.conf optional/*.conf edge/*.conf; do
  if active "$f" | grep -q 'cs3\.ai\.ollama'; then echo "$f"; fi
done | sort | tr '\n' ' ')
if [[ $mention == "conf.d/13-filter-ai-ollama.conf conf.d/15-routing.conf " ]]; then ok "only 13-filter-ai-ollama.conf and 15-routing.conf reference cs3.ai.ollama"; else bad "unexpected files reference cs3.ai.ollama: $mention"; fi
first_match=$(active "$FLUENTD_DIR/conf.d/15-routing.conf" | grep -m1 -E '^[[:space:]]*<match')
if [[ $first_match == *"cs3.ai.ollama"* ]]; then ok "the first root <match> in 15-routing.conf is cs3.ai.ollama"; else bad "first root match is: $first_match"; fi
block=$(active "$FLUENTD_DIR/conf.d/15-routing.conf" | awk '/<match cs3\.ai\.ollama>/{f=1} f{print} /<\/match>/{if(f) exit}')
if [[ $block == *"@type relabel"* && $block == *"@label @ESOC_SIEM"* && $(grep -c '@label' <<<"$block") -eq 1 && $block != *"@type copy"* ]]; then ok "cs3.ai.ollama relabels to @ESOC_SIEM and nothing else"; else bad "ollama match block: $block"; fi
if (cd "$FLUENTD_DIR" && active conf.d/*.conf optional/*.conf edge/*.conf fluent.conf | grep -qE '@type[[:space:]]+(rewrite_tag_filter|route|rewrite_tag)|<rule>'); then
  bad "a tag-rewriting plugin is configured; the static proof assumes tags are immutable"
else ok "no rewrite_tag_filter / route / <rule> anywhere in the tree"; fi

echo "== 2. rendered-tree routing graph (Fluentd's own parser)"
run_graph() { # run_graph <label> <docker env args...> -- <extra shell>
  local label=$1 extra=$2
  shift 2
  local out
  if out=$(docker run --rm --entrypoint sh "$@" -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/secrets:/run/secrets:ro" -v "$HERE/routing_graph.rb:/t/routing_graph.rb:ro" "$IMAGE" \
    -c "cs3-fluentd-entrypoint --check >/dev/null 2>&1 && $extra ruby /t/routing_graph.rb /fluentd/etc/fluent.conf" 2>&1); then
    ok "$label: $(tail -1 <<<"$out")"
  else
    bad "$label"
    echo "$out" | tail -15 >&2
  fi
}
run_graph "node 1, no optional legs (ollama -> *-disabled null sinks)" "" -e FLUENTD_NODE_ID=1
run_graph "node 2, esoc + siem + cloud legs enabled" "" -e FLUENTD_NODE_ID=2 -e CS3_AGGREGATOR_LEGS=esoc,siem -e CS3_ESOC_URL=https://esoc.test -e CS3_SIEM_URL=https://siem.test \
  -e ERROW_CLOUD_ENABLED=true -e ERROW_CLOUD_URL=https://cloud.test
run_graph "node 1, live execd leg selected" "cp /fluentd/etc/optional/vendetta-execd-live.conf /fluentd/etc/enabled.d/40-vendetta-execd.conf &&" -e FLUENTD_NODE_ID=1 \
  -e VENDETTA_API_URL=https://manager.test -e VENDETTA_EXECD_AGENT_REGEX='^(001)$'

if [[ $STATIC_ONLY == true ]]; then
  echo "RESULT: $PASS passed, $FAIL failed (static only)"
  ((FAIL == 0))
  exit $?
fi

echo "== 3. behavioural run (docker network $NET)"
docker network create "$NET" >/dev/null
docker run -d --name "$STUBS" --network "$NET" \
  --network-alias opensearch --network-alias llm-gateway --network-alias vendetta-manager --network-alias errow-feedback \
  --network-alias esoc-sink --network-alias siem-sink --network-alias cloud-sink \
  -e STUB_OS_PASSWORD=fixture-opensearch_admin_password -e STUB_MANAGER_PASSWORD=fixture-vendetta_api_password \
  -v "$HERE/stubs.py:/stubs.py:ro" -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/out:/out" --entrypoint python3 "$RUNNER_IMAGE" \
  /stubs.py /out /pki opensearch=9200 gateway=9101 manager=55000 feedback=9102 esoc=4318 siem=8443 cloud=443 >/dev/null
retry 20 1 test -e "$SCRATCH/out/cloud.ndjson" || { docker logs "$STUBS" >&2; bad "stubs did not start"; exit 1; }

docker run -d --name "$AGG" --network "$NET" --network-alias fluentd-1 --read-only \
  --tmpfs /fluentd/etc/enabled.d:uid=999,gid=999,mode=0755 --tmpfs /run/fluentd:uid=999,gid=999,mode=0700 --tmpfs /tmp \
  -e FLUENTD_NODE_ID=1 -e SSL_CERT_FILE=/pki/ca.crt \
  -e CS3_AGGREGATOR_LEGS=esoc,siem -e CS3_ESOC_URL=https://esoc-sink:4318 -e CS3_ESOC_TOKEN_FILE=/run/secrets/esoc_token \
  -e CS3_SIEM_URL=https://siem-sink:8443/ingest -e CS3_SIEM_TOKEN_FILE=/run/secrets/siem_token \
  -e ERROW_CLOUD_ENABLED=true -e ERROW_CLOUD_URL=https://cloud-sink \
  -e ERROW_FEEDBACK_LIVE=true -e 'VENDETTA_EXECD_AGENT_REGEX=^(000|001)$' -e VENDETTA_JWT_ATTEMPTS=3 -e VENDETTA_JWT_RETRY_SEC=2 \
  -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/secrets:/run/secrets:ro" -v "$SCRATCH/data:/var/log/fluentd" "$IMAGE" >/dev/null

healthy() { [[ $(docker inspect -f '{{.State.Running}}' "$AGG") == true ]] && docker exec "$AGG" ruby -rnet/http -e 'exit(Net::HTTP.get_response(URI("http://127.0.0.1:24231/metrics")).code == "200" ? 0 : 1)'; }
if retry 40 2 healthy; then ok "aggregator booted read-only with every optional leg and answers on :24231/metrics"; else
  docker logs "$AGG" 2>&1 | tail -30 >&2
  bad "aggregator did not become healthy"
  exit 1
fi

if docker run --rm --network "$NET" -v "$STACK:/stack:ro" -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/out:/out" -v "$SCRATCH/data:/data:ro" --entrypoint python3 "$RUNNER_IMAGE" \
  /stack/fluentd/tests/flow_test.py --outdir /out --pki /pki --fwd fluentd-1:24224 --metrics-url http://fluentd-1:24231/metrics --data /data --wait "$WAIT" \
  --metrics-out /out/metrics.txt | tee "$SCRATCH/flow.log"; then
  PASS=$((PASS + $(grep -c '^  PASS' "$SCRATCH/flow.log")))
else
  FAIL=$((FAIL + $(grep -c '^  FAIL' "$SCRATCH/flow.log")))
  docker logs "$AGG" 2>&1 | tail -40 >&2
fi

logs=$(docker logs "$AGG" 2>&1)
leaked=$(grep -oE 'fixture-(opensearch_admin_password|llm_gateway_token|feedback_webhook_token|errow_api_token|vendetta_api_password|esoc_token|siem_token)|stub-jwt-token' <<<"$logs" | sort -u | tr '\n' ' ' || true)
if [[ -z $leaked ]]; then ok "no token/password value in the container log"; else bad "secret values in the container log: $leaked"; fi
errs=$(grep -E '\[(error|fatal)\]' <<<"$logs" || true)
if [[ -z $errs ]]; then ok "no [error]/[fatal] lines in the Fluentd log"; else
  bad "error lines in the Fluentd log"
  head -5 <<<"$errs" >&2
fi
if [[ $KEEP == true && -s $SCRATCH/out/metrics.txt ]]; then cp "$SCRATCH/out/metrics.txt" "$FLUENTD_DIR/.scratch/fluentd-metrics.txt"; fi

echo "RESULT: $PASS passed, $FAIL failed"
((FAIL == 0))
