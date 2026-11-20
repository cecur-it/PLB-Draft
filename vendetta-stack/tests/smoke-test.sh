#!/usr/bin/env bash
# tests/smoke-test.sh — end-to-end smoke test of the whole vendetta-stack on one Docker host.
#
# What it proves (each item becomes a JUnit case in tests/results/junit.xml):
#   ingest -> Fluent Bit (edge sanitization) -> Fluentd -> OpenSearch (vendetta-alerts, errow-*, cs3-ai-*)
#   Errow artifacts -> errow-shipper -> pipeline;  SARIF -> alert transform;  hash-chained AI audit
#   Console / ESOC-SIEM legs and the telemetry-loop guard (cs3.ai.ollama never reaches Console/OpenSearch)
#   llm-gateway guardrails, strict JSON schema, MCP policy matrix, errow-mcp bridge (dry-run)
#   3-tier failover: nemotron down -> gemma; every model down -> "Cecur Heuristics"
#   Errow finding >= HIGH -> errow-feedback (dry-run: isolate/ticket/retest + advisory /forensic proposals)
#   Prometheus targets + alert rules; Fluentd/gateway metric families
#
# The LLM is the mock Ollama (profile `mock-llm`): the REAL Ollama image + GPU are not needed (nor exercised).
# Everything stays dry-run: MCP_LIVE=false, ERROW_FEEDBACK_LIVE=false, telemetry off, no external egress.
#
# Usage: tests/smoke-test.sh [--keep] [--no-build] [--with-errow] [--skip-bootstrap] [--only-up] [--down]
#   --keep            leave the stack running afterwards (default: collect logs, `down -v`)
#   --no-build        do not rebuild images (they must already exist)
#   --with-errow      also start the real `errow` + DinD + viewer (heavy: needs the Errow image and a privileged DinD)
#   --skip-bootstrap  reuse existing secrets/ and pki/
#   --only-up         bring the stack up and wait for health, run no checks
#   --down            just tear down a previous run (`down -v --remove-orphans`) and exit
#   Env: SMOKE_ENV_FILE (default .env.smoke), SMOKE_UP_TIMEOUT (default 900 s), SMOKE_TRIAGE_WAIT (default 90 s),
#        SMOKE_FLAT_NETWORK (auto|1|0, default auto: use one flat network only if the daemon's embedded DNS is not
#        scoped per network — see tests/flatten-networks.py)
# Exit: 0 all checks passed | 1 a check failed | 2 usage/prerequisite error
set -euo pipefail
IFS=$'\n\t'

STACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STACK"

ENV_FILE="${SMOKE_ENV_FILE:-.env.smoke}"
UP_TIMEOUT="${SMOKE_UP_TIMEOUT:-900}"
TRIAGE_WAIT="${SMOKE_TRIAGE_WAIT:-90}"
RESULTS="$STACK/tests/results"
KEEP=0 BUILD=1 WITH_ERROW=0 BOOTSTRAP=1 ONLY_UP=0 ONLY_DOWN=0

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
log() { printf '\033[34m[smoke]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[smoke] WARN:\033[0m %s\n' "$*" >&2; }
die() { local code=$1; shift; printf '\033[31m[smoke] ERROR:\033[0m %s\n' "$*" >&2; exit "$code"; }

while (($#)); do
  case "$1" in
    --keep) KEEP=1 ;;
    --no-build) BUILD=0 ;;
    --with-errow) WITH_ERROW=1 ;;
    --skip-bootstrap) BOOTSTRAP=0 ;;
    --only-up) ONLY_UP=1; KEEP=1 ;;
    --down) ONLY_DOWN=1 ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die 2 "unknown option: $1" ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || die 2 "docker is required"
docker compose version >/dev/null 2>&1 || die 2 "Docker Compose v2 is required (docker compose …)"
command -v jq >/dev/null 2>&1 || die 2 "jq is required"
[[ -f $ENV_FILE ]] || die 2 "env file $ENV_FILE not found"

PROFILES=(--profile mock-llm --profile test --profile lab)
((WITH_ERROW)) && PROFILES+=(--profile errow)
FLAT_FILE="$RESULTS/compose.flat.yml"
USE_FLAT=0
[[ -f $FLAT_FILE ]] && USE_FLAT=1   # a previous run used the flat-network fallback: --down must remove that network too
dc() {
  local files=()
  ((USE_FLAT)) && files=(-f docker-compose.yml -f "$FLAT_FILE")
  docker compose --env-file "$ENV_FILE" "${files[@]}" "${PROFILES[@]}" "$@"
}
vp() { dc exec -T smoke-runner python3 /tests/validate-pipeline.py "$@"; }   # validate-pipeline stage

if ((ONLY_DOWN)); then
  dc down -v --remove-orphans
  rm -f "$FLAT_FILE"
  exit 0
fi

# ---------------------------------------------------------------------------------------------- prerequisites
max_map="$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)"
if ((max_map < 262144)); then
  if [[ $(id -u) -eq 0 ]] && sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
    log "raised vm.max_map_count to 262144 (OpenSearch requirement)"
  else
    die 2 "vm.max_map_count is $max_map; OpenSearch needs >= 262144 — run: sudo sysctl -w vm.max_map_count=262144"
  fi
fi
mem_mb="$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
((mem_mb >= 3000)) || warn "only ${mem_mb} MB RAM available; the smoke stack needs about 3-4 GB"

mkdir -p "$RESULTS"
chmod 0777 "$RESULTS"   # the in-network runner writes junit.xml as its own uid
: >"$RESULTS/smoke.log"

# Some Docker daemons answer embedded-DNS queries with a peer's address on a network the caller is NOT attached to; with the
# stack's six segmented networks that makes healthy multi-homed services unreachable. Probe for it and, only if broken,
# run the smoke on one flat network (tests/flatten-networks.py). SMOKE_FLAT_NETWORK=auto|1|0 overrides the probe.
dns_scope_ok() {
  local img a="vs-dnsprobe-a-$$" b="vs-dnsprobe-b-$$" want got
  img="$(sed -n 's/^PYTHON_IMAGE=//p' "$ENV_FILE" | tr -d "\"'" | head -n1)"
  [[ -n $img ]] || return 0
  if ! { docker network create "$a" >/dev/null 2>&1 && docker network create "$b" >/dev/null 2>&1; }; then
    docker network rm "$a" "$b" >/dev/null 2>&1 || true
    return 0
  fi
  if docker run -d --name "$a" --network "$a" --entrypoint sleep "$img" 30 >/dev/null 2>&1; then
    docker network connect "$b" "$a" >/dev/null 2>&1 || true
  fi
  want="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$b\").IPAddress}}" "$a" 2>/dev/null || true)"
  got="$(docker run --rm --network "$b" --entrypoint python "$img" -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "$a" 2>/dev/null || true)"
  docker rm -f "$a" >/dev/null 2>&1 || true
  docker network rm "$a" "$b" >/dev/null 2>&1 || true
  [[ -z $want || $got == "$want" ]]
}
case "${SMOKE_FLAT_NETWORK:-auto}" in
  1) USE_FLAT=1 ;;
  0) USE_FLAT=0 ;;
  *)
    if dns_scope_ok; then USE_FLAT=0; else
      warn "this Docker daemon's embedded DNS is not scoped per network; using one flat network for the smoke run"
      USE_FLAT=1
    fi
    ;;
esac
if ((USE_FLAT)); then
  USE_FLAT=0   # render the base model first (dc would otherwise reference the file that does not exist yet)
  dc config --format json | python3 tests/flatten-networks.py >"$FLAT_FILE"
  USE_FLAT=1
else
  rm -f "$FLAT_FILE"
fi

if ((BOOTSTRAP)); then
  log "bootstrap: secrets + throw-away PKI (dev-readable so container uids can read them)"
  bash scripts/bootstrap.sh --dev-readable-keys --dev-readable-secrets --skip-preflight -q
fi

# ---------------------------------------------------------------------------------------------- teardown
finish() {
  local rc=$?
  trap - EXIT
  if docker compose --env-file "$ENV_FILE" "${PROFILES[@]}" ps -q >/dev/null 2>&1; then
    dc logs --no-color --timestamps >"$RESULTS/compose.log" 2>&1 || true
    dc ps -a >"$RESULTS/compose-ps.txt" 2>&1 || true
  fi
  if ((KEEP)); then
    log "stack left running (--keep). Tear down with: tests/smoke-test.sh --down"
  else
    log "tearing down (containers, volumes, networks)"
    dc down -v --remove-orphans >/dev/null 2>&1 || warn "compose down reported a problem"
    rm -f "$FLAT_FILE"
  fi
  exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------------------------- bring-up
log "building and starting the stack (timeout ${UP_TIMEOUT}s) — profiles: ${PROFILES[*]//--profile /}"
up_args=(up -d --wait --wait-timeout "$UP_TIMEOUT")
((BUILD)) && up_args+=(--build)
if ! dc "${up_args[@]}" 2>&1 | tee -a "$RESULTS/smoke.log"; then
  dc ps -a >&2 || true
  die 1 "stack did not become healthy within ${UP_TIMEOUT}s (see tests/results/compose.log)"
fi
dc ps --format 'table {{.Service}}\t{{.State}}\t{{.Health}}' >&2
((ONLY_UP)) && { log "stack is up"; exit 0; }

# ---------------------------------------------------------------------------------------------- helpers
mock() { # mock '<json>' — control the mock Ollama (down_models, reset, latency_ms, bad_output_models)
  dc exec -T mock-ollama python -c \
    "import sys,urllib.request as u; print(u.urlopen(u.Request('http://127.0.0.1:11434/__control', sys.argv[1].encode(), {'Content-Type':'application/json'}), timeout=10).read().decode())" \
    "$1" >/dev/null
}
record() { # record <name> <pass|fail> <message>
  vp record "$1" --status "$2" --message "$3" --group smoke-exec >/dev/null || true
  if [[ $2 == pass ]]; then log "PASS  $1"; else warn "FAIL  $1: $3"; fi
}
wait_until() { # wait_until <seconds> <cmd...>
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || return 1
    sleep 3
  done
}
FAILED=0
stage() { # stage <name>
  log "stage: $1"
  vp "$1" 2>&1 | tee -a "$RESULTS/smoke.log" || FAILED=1
}

# ---------------------------------------------------------------------------------------------- stages
vp reset >/dev/null || true
mock '{"reset":true}'

stage ingest
log "waiting up to ${TRIAGE_WAIT}s for Fluentd -> OpenSearch to catch up"
wait_until "$TRIAGE_WAIT" dc exec -T smoke-runner python3 - <<'PY' || warn "alert not indexed yet; the pipeline stage will retry with its own budget"
import json, os, ssl, urllib.request, base64
pw = open(os.environ["OPENSEARCH_PASSWORD_FILE"]).read().strip()
req = urllib.request.Request(os.environ["OPENSEARCH_URL"] + "/vendetta-alerts*/_count")
req.add_header("Authorization", "Basic " + base64.b64encode(f"{os.environ['OPENSEARCH_USER']}:{pw}".encode()).decode())
ctx = ssl.create_default_context(cafile=os.environ["CA_FILE"])
raise SystemExit(0 if json.load(urllib.request.urlopen(req, context=ctx, timeout=10))["count"] > 0 else 1)
PY
stage pipeline
stage guardrails
stage mcp
stage baseline

log "failover 1: nemotron-3-nano:30b down -> forensic model must answer"
mock '{"down_models":["nemotron-3-nano:30b"]}'
stage failover1
log "failover 2: every model down -> deterministic heuristics must answer"
mock '{"down_models":["nemotron-3-nano:30b","gemma4:26b","gemma4:31b"]}'
stage failover2
mock '{"reset":true}'
log "mock Ollama restored"

# Errow -> Vendetta feedback loop (dry-run): Fluentd forwards findings >= high to errow-feedback.
log "feedback loop: waiting for the dry-run actions + advisory proposals"
fb() { dc exec -T errow-feedback "$@"; }
if wait_until 120 fb grep -q 'DRY-RUN: would isolate' /var/log/feedback-loop/feedback.log; then
  record feedback_isolate_dry_run pass "errow-feedback planned (did not perform) the isolation"
else
  record feedback_isolate_dry_run fail "no 'DRY-RUN: would isolate' in /var/log/feedback-loop/feedback.log"
fi
if fb grep -q 'DRY-RUN: would open SOAR ticket' /var/log/feedback-loop/feedback.log 2>/dev/null; then
  record feedback_soar_ticket_dry_run pass "SOAR ticket planned"
else
  record feedback_soar_ticket_dry_run fail "no SOAR ticket line"
fi
if fb grep -q 'LIVE:' /var/log/feedback-loop/feedback.log 2>/dev/null; then
  record feedback_never_live fail "a LIVE: action was logged although ERROW_FEEDBACK_LIVE=false"
else
  record feedback_never_live pass "no live action logged"
fi
if wait_until 60 fb grep -q pending_analyst_review /var/log/feedback-loop/proposals.ndjson; then
  if fb grep -q '"applied": *true' /var/log/feedback-loop/proposals.ndjson; then
    record forensic_proposals_not_applied fail "a proposal is marked applied"
  else
    record forensic_proposals_not_applied pass "proposals pending analyst review, none applied"
  fi
else
  record forensic_proposals_not_applied fail "no proposals.ndjson entry (is /forensic reachable from errow-feedback?)"
fi

# Safety net: the Ollama journald record must be in the local safety file and nowhere else.
if wait_until 60 dc exec -T fluent-bit sh -c 'grep -rqs "model runner crashed" /var/log/fluent-bit/'; then
  record ollama_safety_file pass "cs3.ai.ollama captured in the local safety sink"
else
  record ollama_safety_file fail "cs3-ai-ollama.ndjson did not receive the journald record"
fi

# Schema round trip (SARIF -> alert, AIIncidentAnalysis -> alert) inside the feedback image.
if fb python3 /opt/feedback-loop/schema-validate.py sarif /dev/stdin --run smoke-run -q <tests/synthetic-logs/errow-finding.sarif.json >>"$RESULTS/smoke.log" 2>&1; then
  record schema_sarif_to_alert pass "SARIF fixture validates and maps to a normalized alert"
else
  record schema_sarif_to_alert fail "schema-validate.py sarif failed (see smoke.log)"
fi
if fb python3 /opt/feedback-loop/schema-validate.py ai /dev/stdin --no-merge -q <tests/synthetic-logs/ai-incident-analysis.json >>"$RESULTS/smoke.log" 2>&1; then
  record schema_ai_incident_analysis pass "AIIncidentAnalysis fixture is strictly valid"
else
  record schema_ai_incident_analysis fail "schema-validate.py ai failed (see smoke.log)"
fi

stage metrics

# Optional: real operator health script (published ports on 127.0.0.1) — informational, never fails the run.
if [[ -x scripts/healthcheck.sh ]]; then
  bash scripts/healthcheck.sh --json >"$RESULTS/healthcheck.json" 2>>"$RESULTS/smoke.log" || warn "scripts/healthcheck.sh reported problems (informational; see tests/results/healthcheck.json)"
fi

log "report"
if ! vp report 2>&1 | tee -a "$RESULTS/smoke.log"; then FAILED=1; fi

if ((FAILED)); then
  die 1 "smoke test FAILED — see tests/results/junit.xml, smoke.log and compose.log"
fi
log "smoke test PASSED"
