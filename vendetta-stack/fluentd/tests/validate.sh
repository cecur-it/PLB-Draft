#!/usr/bin/env bash
# Traces: PROMPT §4 Phase 4 (validation); CONTRACT §1 (pinned image), §5 (gems), §8.3/§8.13 (legs on/off, Dockerfile)
# Builds the Fluentd image from the pinned base and validates the config tree the way Fluentd itself does:
#   1. static: bash -n / ruby -c on every script and plugin, Gemfile.lock pins every Gemfile gem;
#   2. image: runs as `fluent`, installed gem versions == Gemfile.lock, custom plugins register (`fluentd --dry-run` loads them);
#   3. `cs3-fluentd-entrypoint --check` (render enabled.d + `fluentd --dry-run`) for node 1/2 x every leg combination, the live execd
#      leg (dry-run of the rendered file), the edge forwarder, and negative cases that must be refused;
#   4. warning allow-list: a dry run may only print the three documented benign warnings.
# --relock regenerates plugins/Gemfile.lock inside the pinned base image (needs rubygems.org) and exits.
# The live execd entrypoint path (JWT mint) and every sink are exercised by tests/test_routing.sh.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
STACK="$(dirname "$ROOT")"
RUN_ID="$$"
IMAGE="vendetta-stack/fluentd:validate-$RUN_ID"
SCRATCH="$ROOT/.scratch/validate-$RUN_ID"
BASE="$(sed -n 's/^ARG FLUENTD_BASE=//p' "$ROOT/Dockerfile")"
KEEP_IMAGE=false
PASS=0
FAIL=0

usage() {
  cat <<EOF
Usage: validate.sh [--relock] [--keep-image] [-h|--help]
  Builds $IMAGE from $ROOT (base: $BASE) and runs the dry-run matrix.
  --relock      regenerate plugins/Gemfile.lock with bundler in the pinned base image, then exit
  --keep-image  do not remove the built image on exit
EOF
}

ACTION=validate
for arg in "$@"; do
  case "$arg" in
    -h | --help) usage; exit 0 ;;
    --relock) ACTION=relock ;;
    --keep-image) KEEP_IMAGE=true ;;
    *) usage >&2; exit 2 ;;
  esac
done

cleanup() {
  local rc=$?
  if [[ $KEEP_IMAGE == false && $ACTION == validate ]]; then docker rmi -f "$IMAGE" >/dev/null 2>&1 || true; fi
  rm -rf "$SCRATCH" 2>/dev/null || docker run --rm -v "$ROOT/.scratch:/s" --entrypoint rm "$BASE" -rf "/s/validate-$RUN_ID" >/dev/null 2>&1 || true
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

if [[ $ACTION == relock ]]; then
  retry 3 5 docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e BUNDLE_GEMFILE=/work/Gemfile -v "$ROOT/plugins:/work" -w /work --entrypoint bundle "$BASE" lock >/dev/null
  echo "plugins/Gemfile.lock regenerated; review the diff and rebuild"
  exit 0
fi

mkdir -p "$SCRATCH"
"$STACK/fluent-bit/tests/make-pki.sh" "$SCRATCH/pki" fluent-bit fluentd-1 fluentd-2 >/dev/null
mkdir -p "$SCRATCH/secrets"
for s in opensearch_admin_password llm_gateway_token feedback_webhook_token errow_api_token vendetta_api_password; do
  printf 'fixture-%s' "$s" >"$SCRATCH/secrets/$s"
done
chmod -R a+rX "$SCRATCH"

echo "== 1. static checks"
for f in "$ROOT/entrypoint.sh" "$HERE"/*.sh; do
  if bash -n "$f"; then ok "bash -n ${f#"$ROOT"/}"; else bad "bash -n ${f#"$ROOT"/}"; fi
done

echo "== 2. image build"
if retry 2 10 docker build -q -t "$IMAGE" "$ROOT" >/dev/null; then ok "docker build ($BASE)"; else bad "docker build"; exit 1; fi
RB=(docker run --rm --entrypoint ruby -v "$HERE:/t:ro" -v "$ROOT/plugins:/p:ro" "$IMAGE")
for f in /p/out_http_bearer.rb /p/out_otlp_http.rb /t/routing_graph.rb; do
  if "${RB[@]}" -c "$f" >/dev/null; then ok "ruby -c ${f#/}"; else bad "ruby -c ${f#/}"; fi
done
if python3 -m py_compile "$HERE/stubs.py" "$HERE/flow_test.py"; then ok "py_compile stubs.py flow_test.py"; else bad "py_compile"; fi
rm -rf "$HERE/__pycache__"

if [[ $(docker run --rm --entrypoint id "$IMAGE" -un) == fluent ]]; then ok "image runs as user fluent"; else bad "image user is not fluent"; fi
mismatch=$(docker run --rm --entrypoint ruby -v "$ROOT/plugins:/p:ro" "$IMAGE" -e '
  lock = File.read("/p/Gemfile.lock")
  specs = lock[/^  specs:\n(.*?)\n\n/m, 1].to_s.scan(/^    (\S+) \(([^)]+)\)$/)
  bad = specs.reject { |n, v| Gem::Specification.find_all_by_name(n).any? { |s| s.version.to_s == v } }
  gemfile = File.read("/p/Gemfile").scan(/^gem \x27([^\x27]+)\x27, \x27([^\x27]+)\x27/)
  missing = gemfile.reject { |n, v| specs.include?([n, v]) }
  puts (bad.map { |n, v| "installed != lock: #{n} #{v}" } + missing.map { |n, v| "Gemfile pin not in lock: #{n} #{v}" }).join("; ")')
if [[ -z $mismatch ]]; then ok "every gem in Gemfile.lock is installed at exactly the locked version and every Gemfile pin is in the lock"; else bad "$mismatch"; fi

echo "== 3. entrypoint --check matrix"
# run_case <description> <expected exit: 0|nonzero> <docker env args...>
run_case() {
  local desc=$1 want=$2 rc=0 out
  shift 2
  out=$(docker run --rm -e FLUENTD_WAIT_SEC=2 "$@" -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/secrets:/run/secrets:ro" "$IMAGE" --check 2>&1) || rc=$?
  if [[ $want == 0 && $rc -eq 0 ]] || [[ $want == nonzero && $rc -ne 0 ]]; then ok "$desc"; else
    bad "$desc (exit $rc)"
    tail -8 <<<"$out" >&2
  fi
}
run_case "node 1, defaults (all optional legs disabled)" 0 -e FLUENTD_NODE_ID=1
run_case "node 2, defaults" 0 -e FLUENTD_NODE_ID=2
run_case "node from hostname fluentd-2" 0 --hostname fluentd-2
run_case "node 1, esoc + siem legs" 0 -e FLUENTD_NODE_ID=1 -e CS3_AGGREGATOR_LEGS=esoc,siem -e CS3_ESOC_URL=https://esoc.example.test -e CS3_SIEM_URL=https://siem.example.test/ingest
run_case "node 2, siem leg only, bearer scheme Splunk" 0 -e FLUENTD_NODE_ID=2 -e CS3_AGGREGATOR_LEGS=siem -e CS3_SIEM_URL=https://siem.example.test/ingest -e CS3_SIEM_AUTH_SCHEME=Splunk
run_case "node 1, Errow cloud leg" 0 -e FLUENTD_NODE_ID=1 -e ERROW_CLOUD_ENABLED=true -e ERROW_CLOUD_URL=https://cloud.example.test
run_case "node 2, every leg except live execd" 0 -e FLUENTD_NODE_ID=2 -e CS3_AGGREGATOR_LEGS=esoc,siem -e CS3_ESOC_URL=https://esoc.example.test \
  -e CS3_SIEM_URL=https://siem.example.test/ingest -e ERROW_CLOUD_ENABLED=true -e ERROW_CLOUD_URL=https://cloud.example.test
run_case "edge forwarder (FLUENTD_CONF=edge/forwarder.conf)" 0 -e FLUENTD_CONF=edge/forwarder.conf
run_case "edge forwarder with custom aggregators and port" 0 -e FLUENTD_CONF=edge/forwarder.conf -e EDGE_AGGREGATOR_1=agg-a.example.test -e EDGE_AGGREGATOR_2=agg-b.example.test -e EDGE_FORWARD_PORT=24444
run_case "refused: FLUENTD_NODE_ID=3" nonzero -e FLUENTD_NODE_ID=3
run_case "refused: esoc leg without CS3_ESOC_URL" nonzero -e FLUENTD_NODE_ID=1 -e CS3_AGGREGATOR_LEGS=esoc
run_case "refused: unknown leg name" nonzero -e FLUENTD_NODE_ID=1 -e CS3_AGGREGATOR_LEGS=splunk
run_case "refused: live execd with an unreachable manager (JWT cannot be minted)" nonzero -e FLUENTD_NODE_ID=1 -e ERROW_FEEDBACK_LIVE=true \
  -e VENDETTA_API_URL=https://vendetta-manager.invalid:55000 -e VENDETTA_JWT_ATTEMPTS=1
out=$(docker run --rm -e FLUENTD_WAIT_SEC=2 -e FLUENTD_NODE_ID=1 -v "$SCRATCH/pki:/pki:ro" "$IMAGE" --check 2>&1) && rc=0 || rc=$?
if [[ $rc -ne 0 && $out == *"required file missing"* ]]; then ok "refused: missing /run/secrets with a clear message"; else bad "missing secrets were not reported (exit $rc)"; fi

echo "== 4. live execd leg, rendered config (dry-run) and warning allow-list"
live=$(docker run --rm --entrypoint sh -e FLUENTD_NODE_ID=1 -e VENDETTA_API_URL=https://manager.example.test:55000 -e VENDETTA_EXECD_AGENT_REGEX='^(001)$' \
  -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/secrets:/run/secrets:ro" "$IMAGE" -c '
  cs3-fluentd-entrypoint --check >/dev/null 2>&1 || exit 90
  printf x >/run/fluentd/vendetta.jwt
  cp /fluentd/etc/optional/vendetta-execd-live.conf /fluentd/etc/enabled.d/40-vendetta-execd.conf
  fluentd --dry-run -c /fluentd/etc/fluent.conf -p /fluentd/plugins 2>&1; echo "dry-run-exit=$?"') || true
if [[ $live == *"dry-run-exit=0"* ]]; then ok "live execd leg parses (dry-run)"; else bad "live execd leg dry-run"; tail -8 <<<"$live" >&2; fi
unexpected=$(grep -E '"level":"(warn|error|fatal)"|\[(warn|error|fatal)\]| (warn|error): ' <<<"$live" |
  grep -vE "private_key_passphrase|reserved prefix|<secondary> with 'retry_forever'" || true)
if [[ -z $unexpected ]]; then ok "dry-run prints only the three documented benign warnings (@timestamp prefix, key passphrase, secondary+retry_forever)"; else
  bad "unexpected warnings"
  head -5 <<<"$unexpected" >&2
fi

echo "RESULT: $PASS passed, $FAIL failed"
((FAIL == 0))
