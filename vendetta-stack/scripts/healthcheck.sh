#!/usr/bin/env bash
#
# healthcheck.sh — stack-wide health report for the vendetta-stack (Docker Compose or Kubernetes).
#
# Traces: PROMPT §3 Phase 3 scripts/healthcheck.sh; CONTRACT §2 (ports, FailClosed), §4.4 (gateway /health, /metrics),
#         §5 (Fluent Bit ↔ Fluentd wiring), CS3 §4.3 (telemetry-loop prevention: cs3.ai.ollama never leaves the host).
#
# What is checked (each row = OK | WARN | FAIL | SKIP; "crit" rows make the stack unhealthy, "soft" rows degrade it):
#   fluent-bit    :2020 /api/v1/health, /api/v1/storage backlog chunks                       crit
#   fluentd-1/2   :24220 monitor_agent (buffer queue length, retry count), :24231 /metrics    soft each, crit if both down
#   opensearch    :9200 /_cluster/health with basic auth + CA (green OK, yellow WARN, red FAIL)  crit
#   dashboards    :5601 /api/status | prometheus :9090 /-/ready | grafana :3000 /api/health | alertmanager :9093 /-/ready   soft
#   llm-gateway   :9101 /health (status ok | degraded semantics, backend models, spool depth) and /metrics
#                 (llm_gateway_audit_chain_ok must be 1)                                      crit
#   errow-mcp     :9103 /health (mTLS) | errow-feedback :9102 /health                         soft, SKIP when not deployed
#   ollama        11434 must NOT be published/listening beyond loopback (docker port bindings, host listeners,
#                 or K8s Service/hostPort); models loaded (via the gateway); LB ready (127.0.0.1:8404 in the gateway netns)
#   loopguard     no Fluent Bit Console leg can match cs3.ai.* and no network output can match cs3.ai.ollama
#   failclosed    CS3_PROFILE onprem/airgap + cloud LLM keys in the environment ⇒ FailClosedError
#   pki           every pki/*.crt valid; < 30 days left ⇒ WARN, expired ⇒ FAIL
#   manager       (ERROW_FEEDBACK_LIVE=true only) the manager API presents the pinned, CA-trusted certificate with
#                 the right SAN — a rotated or unpinned certificate makes every live action 503   crit
#   pods          (--kubernetes) every pod Ready
#
# Transports: auto (default) — the published host port on 127.0.0.1 first; when that port is not reachable (Compose
#   publishes only some ports: Fluentd 24220/24231, errow-mcp 9103 and errow-feedback 9102 stay internal) and the
#   service's container is running (`docker compose ps -q <svc>`, else `docker inspect <project>-<svc>-1`, project =
#   COMPOSE_PROJECT_NAME), the first container IP the host can open a TCP connection to (TLS is still verified with
#   pki/ca.crt against the service DNS name via curl --resolve). When neither the host port nor any container IP answers
#   but Docker reports the container healthy, the row is WARN "healthy per docker, HTTP not reachable from host" —
#   never OK. host — published ports on 127.0.0.1 only; kube — `kubectl port-forward` per service.
#   Any base URL can be forced with HC_URL_<NAME> (e.g. HC_URL_OPENSEARCH=https://127.0.0.1:9200,
#   HC_URL_DASHBOARDS, HC_URL_PROMETHEUS, HC_URL_GRAFANA, HC_URL_ALERTMANAGER, HC_URL_FLUENT_BIT, HC_URL_FLUENTD_1,
#   HC_URL_FLUENTD_2, HC_URL_FLUENTD_1_METRICS, HC_URL_FLUENTD_2_METRICS, HC_URL_LLM_GATEWAY, HC_URL_ERROW_MCP,
#   HC_URL_ERROW_FEEDBACK) — from the environment or $STACK/.env. TLS is always verified with pki/ca.crt; there is
#   no insecure mode.
#
# Usage: scripts/healthcheck.sh [--kubernetes [--namespace NS]] [--json] [--only a,b] [--skip a,b] [--wait SECS] …
#
# Exit codes: 0 healthy | 1 degraded (WARN or soft FAIL) | 2 unhealthy (crit FAIL, or no check passed)
#             4 missing prerequisite | 64 usage error

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/pki.sh
source "$SCRIPT_DIR/lib/pki.sh"

trap 'vs_cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
healthcheck.sh — stack-wide health report (Docker Compose or Kubernetes).

Usage: scripts/healthcheck.sh [options]

  --kubernetes, -k           check a Kubernetes deployment (kubectl + port-forward); --namespace NS (default vendetta-stack)
  --transport auto|host|kube how probes reach services (default auto: host ports, falling back to Compose container IPs)
  --json                     machine-readable report on stdout (the table is the default)
  --only a,b | --skip a,b    restrict / exclude checks: fluent-bit fluentd opensearch dashboards prometheus grafana
                             alertmanager llm-gateway errow manager ollama loopguard failclosed pki pods
  --no-docker                do not use docker/compose (container-based checks become SKIP)
  --wait SECS                re-run every 5 s until healthy or SECS elapsed (use after `compose up`)
  --timeout SECS             per-request timeout (default 5)
  --cert-warn-days N         warn when a certificate has fewer days left (default 30)
  --fluent-bit-dir DIR       config tree for the loop-guard check (default $STACK/fluent-bit); --rendered-dir DIR adds
                             an already rendered enabled.d (e.g. from `entrypoint.sh --render-only`)
  --stack-dir DIR  -q  -v  -h

Thresholds (env): HC_FB_BACKLOG_WARN=200 HC_FB_BACKLOG_FAIL=2000 (Fluent Bit filesystem chunks)
  HC_FLUENTD_QUEUE_WARN=32 HC_FLUENTD_QUEUE_FAIL=256 (buffer queue length) HC_FLUENTD_RETRY_WARN=3
  HC_SPOOL_WARN=100 HC_SPOOL_FAIL=5000 (llm-gateway spool depth)
Credentials: OpenSearch admin password from $STACK/secrets/opensearch_admin_password (OPENSEARCH_USER, default admin;
  OPENSEARCH_PASSWORD_FILE overrides); mTLS client identity HC_CLIENT_CERT / HC_CLIENT_KEY (default pki/errow.crt|key).

Exit codes: 0 healthy | 1 degraded | 2 unhealthy | 4 missing prerequisite | 64 usage error
EOF
}

KUBE=0
NAMESPACE="vendetta-stack"
TRANSPORT="auto"
AS_JSON=0
ONLY=""
SKIP=""
NO_DOCKER=0
WAIT=0
TIMEOUT=5
CERT_WARN_DAYS=30
FB_DIR=""
RENDERED_DIR=""

parse_args() {
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]:-}"
  while (($#)); do
    if [[ -z "$1" ]]; then shift; continue; fi
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -q|--quiet) VS_QUIET=1; shift ;;
      -v|--verbose) VS_VERBOSE=1; shift ;;
      -k|--kubernetes) KUBE=1; shift ;;
      --namespace) vs_need "$@"; NAMESPACE=$2; shift 2 ;;
      --transport) vs_need "$@"; TRANSPORT=$2; shift 2 ;;
      --json) AS_JSON=1; shift ;;
      --only) vs_need "$@"; ONLY=$2; shift 2 ;;
      --skip) vs_need "$@"; SKIP=$2; shift 2 ;;
      --no-docker) NO_DOCKER=1; shift ;;
      --wait) vs_need "$@"; WAIT=$2; shift 2 ;;
      --timeout) vs_need "$@"; TIMEOUT=$2; shift 2 ;;
      --cert-warn-days) vs_need "$@"; CERT_WARN_DAYS=$2; shift 2 ;;
      --fluent-bit-dir) vs_need "$@"; FB_DIR=$2; shift 2 ;;
      --rendered-dir) vs_need "$@"; RENDERED_DIR=$2; shift 2 ;;
      --stack-dir)
        vs_need "$@"
        [[ -d "$2" ]] || die 64 "stack dir not found: $2"
        STACK_DIR="$(cd "$2" && pwd)"; SECRETS_DIR="$STACK_DIR/secrets"; PKI_DIR="$STACK_DIR/pki"; ENV_FILE="$STACK_DIR/.env"
        shift 2 ;;
      *) die 64 "unknown option: $1 (see --help)" ;;
    esac
  done
  case "$TRANSPORT" in auto|host|kube) ;; *) die 64 "--transport must be auto, host or kube" ;; esac
  if ((KUBE)); then TRANSPORT=kube; fi
  local list name known=" fluent-bit fluentd opensearch dashboards prometheus grafana alertmanager llm-gateway errow manager ollama loopguard failclosed pki pods "
  for list in "$ONLY" "$SKIP"; do
    [[ -n "$list" ]] || continue
    while IFS= read -r name; do
      [[ "$known" == *" $name "* ]] || die 64 "unknown check '$name' (see --help)"
    done < <(tr ',' '\n' <<<"$list")
  done
  vs_is_uint "$WAIT" || die 64 "--wait must be a non-negative integer"
  vs_is_uint "$TIMEOUT" || die 64 "--timeout must be a positive integer"
  vs_is_uint "$CERT_WARN_DAYS" || die 64 "--cert-warn-days must be a non-negative integer"
  return 0
}

# --- result bookkeeping --------------------------------------------------------------------------------
RESULTS=""
RUNNING_KNOWN=0
RUNNING_LIST=""
DOCKER_OK=0
CA_FILE=""
EP_BASE=""
EP_RESOLVE=""
declare -A PF_PORT=()
declare -A EP_CACHE=()
PF_NEXT=0
PROBE_RC=0
EP_DOCKER_HEALTHY=0
PROBE_DOCKER_HEALTHY=0
DOCKER_ONLY_MARK="healthy per docker, HTTP not reachable from host"

check_enabled() { # <name>
  if [[ -n "$ONLY" && ",$ONLY," != *",$1,"* ]]; then return 1; fi
  if [[ -n "$SKIP" && ",$SKIP," == *",$1,"* ]]; then return 1; fi
  return 0
}

record() { # <name> <OK|WARN|FAIL|SKIP> <crit|soft> <detail…>
  local name=$1 status=$2 sev=$3 detail
  shift 3
  detail="$*"
  detail=${detail//$'\t'/ }
  detail=${detail//$'\n'/ }
  RESULTS+="$name"$'\t'"$status"$'\t'"$sev"$'\t'"$detail"$'\n'
}

num() { if [[ "${1:-}" =~ ^[0-9]+$ ]]; then printf '%s' "$1"; else printf '0'; fi; }

# --- endpoints -----------------------------------------------------------------------------------------
svc_running() { # <svc> → 0 running, 1 not running, 2 unknown
  if ((RUNNING_KNOWN == 0)); then return 2; fi
  if grep -qxF -- "$1" <<<"$RUNNING_LIST"; then return 0; fi
  return 1
}

container_id() { # <svc> → id or name of the running container: `compose ps -q`, else <project>-<svc>-1 / <project>_<svc>_1
  local svc=$1 id cand
  id="$("${COMPOSE[@]}" ps -q "$svc" 2>/dev/null | head -n 1)" || id=""
  if [[ -n "$id" ]]; then printf '%s' "$id"; return 0; fi
  for cand in "$COMPOSE_PROJECT-$svc-1" "${COMPOSE_PROJECT}_${svc}_1"; do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$cand" 2>/dev/null || true)" == true ]]; then printf '%s' "$cand"; return 0; fi
  done
  return 1
}

container_ips() { # <id> → one container IP per line
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$1" 2>/dev/null | tr ' ' '\n' | awk 'NF' || true
}

container_health() { # <id> → healthy | unhealthy | starting | none | unknown
  local h
  h="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$1" 2>/dev/null)" || h=""
  printf '%s' "${h:-unknown}"
}

tcp_open() { # <host> <port> — short TCP connect probe (HC_TCP_TIMEOUT seconds, default 2)
  local t
  t="$(num "${HC_TCP_TIMEOUT:-2}")"
  if ((t < 1)); then t=2; fi
  if vs_have timeout; then
    timeout "$t" bash -c "exec 3<>\"/dev/tcp/\$1/\$2\"" _ "$1" "$2" 2>/dev/null
  else
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null
  fi
}

kube_forward() { # <svc> <port> → sets EP_PORT
  local key="$1:$2" lport pid i
  if [[ -n "${PF_PORT[$key]:-}" ]]; then EP_PORT=${PF_PORT[$key]}; return 0; fi
  lport=$((${HC_PF_BASE:-18100} + PF_NEXT))
  PF_NEXT=$((PF_NEXT + 1))
  kubectl -n "$NAMESPACE" port-forward --address 127.0.0.1 "svc/$1" "$lport:$2" >/dev/null 2>&1 &
  pid=$!
  vs_on_exit "kill $pid"
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$lport") 2>/dev/null; then PF_PORT[$key]=$lport; EP_PORT=$lport; return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    vs_sleep 0.5
  done
  return 1
}

# endpoint <svc> <scheme> <port> <override-var> — sets EP_BASE / EP_RESOLVE / EP_DOCKER_HEALTHY; returns 2 when the service is not deployed
# auto transport: published host port → container IP the host can reach (TLS verified via --resolve) → host URL (the probe then fails)
endpoint() {
  local svc=$1 scheme=$2 port=$3 var=$4 ov ip id key="$1:$3" rc=0
  EP_BASE=""; EP_RESOLVE=""; EP_DOCKER_HEALTHY=0
  ov="$(vs_cfg "HC_URL_$var" "")"
  if [[ -n "$ov" ]]; then EP_BASE=${ov%/}; return 0; fi
  if [[ "$TRANSPORT" == kube ]]; then
    kube_forward "$svc" "$port" || return 2
    EP_BASE="$scheme://127.0.0.1:$EP_PORT"
    return 0
  fi
  svc_running "$svc" || rc=$?
  if ((rc == 1)); then return 2; fi
  EP_BASE="$scheme://127.0.0.1:$port"
  if [[ "$TRANSPORT" != auto || $DOCKER_OK -ne 1 ]]; then return 0; fi
  if [[ -n "${EP_CACHE[$key]:-}" ]]; then
    EP_BASE=${EP_CACHE[$key]%%|*}
    EP_RESOLVE=${EP_CACHE[$key]#*|}
    return 0
  fi
  if tcp_open 127.0.0.1 "$port"; then EP_CACHE[$key]="$EP_BASE|"; return 0; fi
  id="$(container_id "$svc")" || return 0
  if [[ "$(uname -s)" == Linux ]]; then
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      if tcp_open "$ip" "$port"; then
        EP_BASE="$scheme://$svc:$port"
        EP_RESOLVE="$svc:$port:$ip"
        EP_CACHE[$key]="$EP_BASE|$EP_RESOLVE"
        return 0
      fi
    done < <(container_ips "$id")
  fi
  if [[ "$(container_health "$id")" == healthy ]]; then EP_DOCKER_HEALTHY=1; fi
  return 0
}

# probe <svc> <scheme> <port> <var> <path> [vs_http options…] → PROBE_RC / VS_HTTP_CODE / VS_HTTP_BODY; returns 2 = not deployed
probe() {
  local svc=$1 scheme=$2 port=$3 var=$4 path=$5 args=() rc=0
  shift 5
  PROBE_RC=0
  endpoint "$svc" "$scheme" "$port" "$var" || return 2
  PROBE_DOCKER_HEALTHY=$EP_DOCKER_HEALTHY
  if [[ "$EP_BASE" == https://* ]]; then
    if [[ ! -f "$CA_FILE" ]]; then VS_HTTP_CODE=000; VS_HTTP_BODY="CA file missing: $CA_FILE (run scripts/bootstrap.sh)"; PROBE_RC=77; return 1; fi
    args+=(--ca "$CA_FILE")
  fi
  if [[ -n "$EP_RESOLVE" ]]; then args+=(--resolve "$EP_RESOLVE"); fi
  vs_http GET "$EP_BASE$path" "${args[@]}" --max-time "$TIMEOUT" "$@" || rc=$?
  PROBE_RC=$rc
  return "$rc"
}

# why <rc> — one-line reason for a failed probe
why() {
  local body=${VS_HTTP_BODY//$'\n'/ }
  case "$PROBE_RC" in
    7) printf 'connection refused (is the service up?)' ;;
    28) printf 'timed out after %ss' "$TIMEOUT" ;;
    35|51|58|60) printf 'TLS verification failed against pki/ca.crt (%s)' "${body:0:100}" ;;
    22) printf 'HTTP %s' "$VS_HTTP_CODE" ;;
    77) printf '%s' "$body" ;;
    *) printf 'curl error %s (%s)' "$PROBE_RC" "${body:0:100}" ;;
  esac
}

# fail_or_skip <name> <sev> — record the failure of the last probe (not-deployed ⇒ SKIP)
fail_or_skip() {
  local name=$1 sev=$2 prc=${3:-1} reason
  if ((prc == 2)); then record "$name" SKIP "$sev" "service not deployed / not running"; return 0; fi
  if ((PROBE_DOCKER_HEALTHY)) && [[ "$PROBE_RC" == 7 || "$PROBE_RC" == 28 ]]; then
    if [[ "$PROBE_RC" == 7 ]]; then reason="connection refused"; else reason="timed out after ${TIMEOUT}s"; fi
    record "$name" WARN "$sev" "$DOCKER_ONLY_MARK ($reason; publish the port, set HC_URL_*, or fix the in-container bind)"
    return 0
  fi
  record "$name" FAIL "$sev" "$(why)"
}

# --- checks --------------------------------------------------------------------------------------------
check_fluent_bit() {
  local prc=0 chunks down over detail
  probe fluent-bit http 2020 FLUENT_BIT /api/v1/health || prc=$?
  if ((prc)); then fail_or_skip fluent-bit crit "$prc"; return 0; fi
  detail="health HTTP $VS_HTTP_CODE"
  if probe fluent-bit http 2020 FLUENT_BIT /api/v1/storage && jq -e '.storage_layer' >/dev/null 2>&1 <<<"$VS_HTTP_BODY"; then
    chunks="$(num "$(jq -r '.storage_layer.chunks.fs_chunks // .storage_layer.chunks.total_chunks // 0' <<<"$VS_HTTP_BODY")")"
    down="$(num "$(jq -r '.storage_layer.chunks.fs_chunks_down // 0' <<<"$VS_HTTP_BODY")")"
    over="$(jq -r '[.input_chunks[]?.status.overlimit // false] | any' <<<"$VS_HTTP_BODY" 2>/dev/null || echo false)"
    detail+="; backlog $chunks chunk(s), $down paused"
    if ((chunks >= $(num "${HC_FB_BACKLOG_FAIL:-2000}"))); then record fluent-bit FAIL soft "$detail (≥ ${HC_FB_BACKLOG_FAIL:-2000}: Fluentd/OpenSearch not draining)"; return 0; fi
    if ((chunks >= $(num "${HC_FB_BACKLOG_WARN:-200}"))) || [[ "$over" == true ]]; then record fluent-bit WARN soft "$detail$(if [[ "$over" == true ]]; then printf ', input over its storage limit'; fi)"; return 0; fi
  else
    detail+="; storage metrics not exposed"
  fi
  record fluent-bit OK crit "$detail"
}

check_fluentd_one() { # <svc>
  local svc=$1 var=${1^^} prc=0 q r qb detail
  var=${var//-/_}
  probe "$svc" http 24220 "$var" /api/plugins.json || prc=$?
  if ((prc)); then fail_or_skip "$svc" soft "$prc"; return 0; fi
  if ! jq -e '.plugins' >/dev/null 2>&1 <<<"$VS_HTTP_BODY"; then record "$svc" FAIL soft "monitor_agent returned no plugin list"; return 0; fi
  q="$(num "$(jq -r '[.plugins[] | select(.output_plugin == true) | (.buffer_queue_length // 0)] | max // 0' <<<"$VS_HTTP_BODY")")"
  qb="$(num "$(jq -r '[.plugins[] | select(.output_plugin == true) | (.buffer_total_queued_size // 0)] | max // 0' <<<"$VS_HTTP_BODY")")"
  r="$(num "$(jq -r '[.plugins[] | select(.output_plugin == true) | (.retry_count // 0)] | max // 0' <<<"$VS_HTTP_BODY")")"
  detail="monitor_agent ok; buffer queue $q ($qb bytes), max retries $r"
  prc=0
  probe "$svc" http 24231 "${var}_METRICS" /metrics || prc=$?
  if ((prc == 2)); then detail+="; metrics endpoint not deployed"
  elif ((prc)); then record "$svc" WARN soft "$detail; :24231/metrics: $(why)"; return 0
  else detail+="; :24231/metrics ok"
  fi
  if ((q >= $(num "${HC_FLUENTD_QUEUE_FAIL:-256}"))); then record "$svc" FAIL soft "$detail — buffer not draining"; return 0; fi
  if ((q >= $(num "${HC_FLUENTD_QUEUE_WARN:-32}"))) || ((r >= $(num "${HC_FLUENTD_RETRY_WARN:-3}"))); then record "$svc" WARN soft "$detail"; return 0; fi
  record "$svc" OK soft "$detail"
}

check_fluentd() {
  local real dockeronly skipped note=""
  check_fluentd_one fluentd-1
  check_fluentd_one fluentd-2
  real="$(printf '%s' "$RESULTS" | awk -F'\t' -v m="$DOCKER_ONLY_MARK" '$1 ~ /^fluentd-[12]$/ && ($2 == "OK" || ($2 == "WARN" && index($4, m) == 0)) {n++} END {print n + 0}')"
  dockeronly="$(printf '%s' "$RESULTS" | awk -F'\t' -v m="$DOCKER_ONLY_MARK" '$1 ~ /^fluentd-[12]$/ && $2 == "WARN" && index($4, m) > 0 {n++} END {print n + 0}')"
  skipped="$(printf '%s' "$RESULTS" | awk -F'\t' '$1 ~ /^fluentd-[12]$/ && $2 == "SKIP" {n++} END {print n + 0}')"
  if ((dockeronly > 0)); then note="; $dockeronly aggregator(s) only $DOCKER_ONLY_MARK"; fi
  if ((real == 2)); then record "fluentd (active-active)" OK crit "both aggregators healthy"
  elif ((real == 1)); then record "fluentd (active-active)" WARN soft "only one aggregator healthy (no redundancy)$note"
  elif ((dockeronly > 0)); then record "fluentd (active-active)" WARN soft "no aggregator verified over HTTP$note"
  elif ((skipped < 2)); then record "fluentd (active-active)" FAIL crit "no Fluentd aggregator is healthy — Fluent Bit is spooling to disk"
  fi
}

check_opensearch() {
  local prc=0 pwfile user status nodes unassigned active pct auth=() detail
  user="$(vs_cfg OPENSEARCH_USER admin)"
  pwfile="$(vs_cfg OPENSEARCH_PASSWORD_FILE "$SECRETS_DIR/opensearch_admin_password")"
  if [[ -r "$pwfile" ]]; then auth=(--basic "$user:$pwfile"); fi
  probe opensearch https 9200 OPENSEARCH "/_cluster/health" "${auth[@]}" || prc=$?
  if ((prc == 22)) && [[ "$VS_HTTP_CODE" == 401 ]]; then
    record opensearch WARN crit "reachable (TLS ok) but authentication failed — check $pwfile / OPENSEARCH_USER"
    return 0
  fi
  if ((prc)); then fail_or_skip opensearch crit "$prc"; return 0; fi
  if [[ ${#auth[@]} -eq 0 ]]; then record opensearch WARN crit "no admin password file ($pwfile) — answered without credentials"; return 0; fi
  status="$(jq -r '.status // "unknown"' <<<"$VS_HTTP_BODY" 2>/dev/null || echo unknown)"
  nodes="$(num "$(jq -r '.number_of_nodes // 0' <<<"$VS_HTTP_BODY" 2>/dev/null)")"
  unassigned="$(num "$(jq -r '.unassigned_shards // 0' <<<"$VS_HTTP_BODY" 2>/dev/null)")"
  active="$(jq -r '.active_shards_percent_as_number // 0' <<<"$VS_HTTP_BODY" 2>/dev/null || echo 0)"
  pct=${active%.*}
  detail="cluster $status; $nodes node(s); $unassigned unassigned shard(s); ${pct:-0}% active"
  case "$status" in
    green) record opensearch OK crit "$detail" ;;
    yellow) record opensearch WARN crit "$detail (replicas unassigned — normal on a single node only if replicas=0)" ;;
    red) record opensearch FAIL crit "$detail" ;;
    *) record opensearch FAIL crit "unexpected cluster health response" ;;
  esac
}

check_simple() { # <name> <svc> <scheme> <port> <var> <path> <jq-filter|-> <crit|soft> <opt:0|1>
  local name=$1 svc=$2 scheme=$3 port=$4 var=$5 path=$6 filter=$7 sev=$8 prc=0 ext=""
  probe "$svc" "$scheme" "$port" "$var" "$path" || prc=$?
  if ((prc)); then fail_or_skip "$name" "$sev" "$prc"; return 0; fi
  if [[ "$filter" != - ]]; then
    if ! ext="$(jq -r "$filter" <<<"$VS_HTTP_BODY" 2>/dev/null)" || [[ -z "$ext" || "$ext" == null ]]; then
      record "$name" WARN "$sev" "HTTP $VS_HTTP_CODE but the response was not the expected JSON"
      return 0
    fi
  fi
  record "$name" OK "$sev" "HTTP $VS_HTTP_CODE${ext:+; $ext}"
}

check_dashboards() { check_simple opensearch-dashboards opensearch-dashboards http 5601 DASHBOARDS /api/status '"state " + (.status.overall.state // .status.overall.level // "unknown")' soft; }
check_prometheus() { check_simple prometheus prometheus http 9090 PROMETHEUS /-/ready - soft; }
check_grafana() { check_simple grafana grafana http 3000 GRAFANA /api/health '"database " + (.database // "unknown")' soft; }
check_alertmanager() { check_simple alertmanager alertmanager http 9093 ALERTMANAGER /-/ready - soft; }

HEALTH_BODY=""
check_gateway() {
  local prc=0 status gwsum reach models names fbr spool ver primary
  probe llm-gateway https 9101 LLM_GATEWAY /health || prc=$?
  if ((prc)); then fail_or_skip llm-gateway crit "$prc"; return 0; fi
  HEALTH_BODY=$VS_HTTP_BODY
  if ! jq -e 'type == "object" and has("status")' >/dev/null 2>&1 <<<"$HEALTH_BODY"; then record llm-gateway FAIL crit "/health did not return the contract JSON"; return 0; fi
  IFS='|' read -r status reach models names fbr spool ver < <(jq -r '[(.status // "?"), ((.backend.reachable // false) | tostring),
    ((.backend.models // 0) | if type == "array" then length else . end | tostring),
    ((.backend.models // []) | if type == "array" then join(",") else "" end),
    ((.fluent_bit.reachable // false) | tostring), ((.fluent_bit.spool_depth // 0) | tostring), (.version // "?")] | join("|")' <<<"$HEALTH_BODY")
  gwsum="$status; ollama backend reachable=$reach models=$models; fluent-bit reachable=$fbr; version $ver"
  case "$status" in
    ok) record llm-gateway OK crit "$gwsum" ;;
    degraded) record llm-gateway WARN crit "$gwsum — gateway is serving with heuristic fallback" ;;
    *) record llm-gateway FAIL crit "status '$status'" ;;
  esac
  spool="$(num "$spool")"
  if ((spool >= $(num "${HC_SPOOL_FAIL:-5000}"))); then record "llm-gateway spool" FAIL soft "$spool spooled event(s) (≥ ${HC_SPOOL_FAIL:-5000}) — Fluent Bit unreachable or not draining"
  elif ((spool >= $(num "${HC_SPOOL_WARN:-100}"))); then record "llm-gateway spool" WARN soft "$spool spooled event(s)"
  else record "llm-gateway spool" OK soft "$spool spooled event(s)"
  fi
  primary="$(vs_cfg OLLAMA_PRIMARY_MODEL "")"
  security="$(vs_cfg OLLAMA_SECURITY_MODEL nemotron-3-nano:30b)"
  if [[ "$reach" != true ]]; then record "ollama models" FAIL soft "backend not reachable from the gateway — no model can answer"
  elif (($(num "$models") == 0)); then record "ollama models" WARN soft "backend reachable but no model loaded (pull-models.sh / enroll-ollama.sh)"
  elif [[ -n "$names" && -n "$primary" && ",$names," != *",$primary,"* ]]; then record "ollama models" WARN soft "primary model $primary not loaded (have: $names)"
  else record "ollama models" OK soft "$models model(s) available${names:+: $names}"
  fi
  if [[ "$reach" == true && -n "$names" && -n "$security" && ",$names," != *",$security,"* \
    && "$(vs_cfg GATEWAY_SECURITY_ENABLED true)" != false ]]; then
    record "ollama security model" WARN soft "security model $security not loaded — /security and Errow will fail closed (502)"
  fi
  prc=0
  probe llm-gateway https 9101 LLM_GATEWAY /metrics || prc=$?
  if ((prc)); then record "llm-gateway audit chain" WARN soft "/metrics: $(why)"; return 0; fi
  local chain
  chain="$(awk '/^llm_gateway_audit_chain_ok([ {])/ {print $NF; exit}' <<<"$VS_HTTP_BODY")"
  case "$chain" in
    1|1.0) record "llm-gateway audit chain" OK crit "audit hash chain intact (llm_gateway_audit_chain_ok 1)" ;;
    0|0.0) record "llm-gateway audit chain" FAIL crit "audit hash chain BROKEN (llm_gateway_audit_chain_ok 0) — treat the audit log as tampered" ;;
    *) record "llm-gateway audit chain" WARN soft "llm_gateway_audit_chain_ok not exposed by /metrics" ;;
  esac
}

check_errow() {
  local prc=0 cert key args=()
  check_simple errow-feedback errow-feedback http 9102 ERROW_FEEDBACK /health - soft
  cert="$(vs_cfg HC_CLIENT_CERT "$PKI_DIR/errow.crt")"
  key="$(vs_cfg HC_CLIENT_KEY "$PKI_DIR/errow.key")"
  if [[ -r "$cert" && -r "$key" ]]; then args=(--cert "$cert" --key "$key"); fi
  probe errow-mcp https 9103 ERROW_MCP /health "${args[@]}" || prc=$?
  if ((prc)); then fail_or_skip errow-mcp soft "$prc"; return 0; fi
  record errow-mcp OK soft "HTTP $VS_HTTP_CODE (mTLS ok)"
}

# --- manager TLS pin (only meaningful for live actions) ------------------------------------------------
check_manager() {
  local live bundle out rc=0
  live="$(vs_cfg ERROW_FEEDBACK_LIVE false)"
  if [[ "$live" != true ]]; then record manager SKIP soft "ERROW_FEEDBACK_LIVE is not true — live actions are off"; return 0; fi
  if ((KUBE)); then
    bundle="$(vs_cfg VENDETTA_API_CA_FILE "")"
    if [[ -z "$bundle" || ! -s "$bundle" ]]; then
      record manager SKIP soft "Kubernetes: no readable VENDETTA_API_CA_FILE (cert-manager owns the pin)"; return 0
    fi
  fi
  if ! vs_have openssl; then record manager SKIP soft "openssl not installed"; return 0; fi
  local args=(--quiet)
  if [[ -d "$STACK_DIR/pki" ]]; then args+=(--stack-dir "$STACK_DIR"); fi
  bundle="$(vs_cfg VENDETTA_API_CA_FILE "")"
  case "$bundle" in /*) [[ -s "$bundle" ]] && args+=(--bundle "$bundle") ;; esac
  args+=(--connect "127.0.0.1:$(vs_cfg HC_MANAGER_PORT "$(vs_cfg VENDETTA_API_PORT 55000)")")
  out="$("$SCRIPT_DIR/verify-manager.sh" "${args[@]}" 2>&1)" || rc=$?
  case "$rc" in
    0) record manager OK crit "manager certificate pinned and verified" ;;
    4) record manager SKIP soft "verify-manager.sh prerequisite missing" ;;
    *) record manager FAIL crit "${out:-verify-manager.sh failed}" ;;
  esac
}

# --- Ollama loopback-only invariant --------------------------------------------------------------------
check_ollama_loopback() {
  local bad=() id name ports listeners
  if ((KUBE)); then
    if ! vs_have kubectl; then record "ollama loopback-only" SKIP crit "kubectl not installed"; return 0; fi
    local svc pods
    svc="$(kubectl -n "$NAMESPACE" get svc -o json 2>/dev/null)" || { record "ollama loopback-only" FAIL crit "cannot list services in namespace $NAMESPACE"; return 0; }
    pods="$(kubectl -n "$NAMESPACE" get pods -o json 2>/dev/null)" || pods='{"items":[]}'
    while IFS= read -r name; do bad+=("$name"); done < <(jq -r '.items[] | select(.spec.type == "NodePort" or .spec.type == "LoadBalancer")
      | select([.spec.ports[]? | (.port, .targetPort, .nodePort)] | any(. == 11434)) | "Service " + .metadata.name + " (" + .spec.type + ")"' <<<"$svc")
    while IFS= read -r name; do bad+=("$name"); done < <(jq -r '.items[] | . as $p | $p.spec.containers[] | select([.ports[]? | .hostPort] | any(. == 11434)) | "Pod " + $p.metadata.name + " hostPort"' <<<"$pods")
    while IFS= read -r name; do bad+=("$name"); done < <(jq -r '.items[] | select(.spec.hostNetwork == true) | select([.spec.containers[] | .ports[]? | .containerPort] | any(. == 11434)) | "Pod " + .metadata.name + " hostNetwork"' <<<"$pods")
  else
    if ((DOCKER_OK)); then
      while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        ports="$(docker inspect -f '{{.Name}}|{{json .HostConfig.PortBindings}}' "$id" 2>/dev/null)" || continue
        name=${ports%%|*}; ports=${ports#*|}
        if jq -e 'to_entries | any(.key | test("^11434/")) and (map(select(.key | test("^11434/")) | .value[]? | select(.HostIp != "127.0.0.1" and .HostIp != "::1")) | length > 0)' >/dev/null 2>&1 <<<"$ports"; then
          bad+=("container ${name#/} publishes 11434 beyond loopback")
        fi
      done < <(docker ps -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" 2>/dev/null)
    fi
    if vs_have ss; then
      listeners="$(ss -H -ltn 2>/dev/null | awk '{n = split($4, a, ":"); if (a[n] == "11434") print $4}')" || listeners=""
      while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        case "$name" in 127.0.0.1:11434|\[::1\]:11434|::1:11434) ;; *) bad+=("host listener $name") ;; esac
      done <<<"$listeners"
    fi
    if ((DOCKER_OK == 0)) && ! vs_have ss; then record "ollama loopback-only" SKIP crit "neither docker nor ss available"; return 0; fi
  fi
  if ((${#bad[@]})); then record "ollama loopback-only" FAIL crit "11434 is exposed: $(vs_join '; ' "${bad[@]}")"; else record "ollama loopback-only" OK crit "11434 is not published or bound beyond 127.0.0.1"; fi
}

check_ollama_lb() {
  local gw out
  if ((KUBE || DOCKER_OK == 0)); then record "ollama-lb ready" SKIP soft "needs Compose + docker (checked inside the gateway network namespace)"; return 0; fi
  if ! svc_running llm-gateway; then record "ollama-lb ready" SKIP soft "llm-gateway not running"; return 0; fi
  gw="$("${COMPOSE[@]}" ps -q llm-gateway 2>/dev/null | head -n 1)"
  local img
  img="$(vs_cfg CURL_IMAGE "")"
  if [[ -z "$img" ]]; then img="$(images_curl_default)"; fi
  if [[ -z "$gw" ]] || ! docker image inspect "$img" >/dev/null 2>&1; then record "ollama-lb ready" SKIP soft "curl helper image not present locally (docker pull $img)"; return 0; fi
  if out="$(docker run --rm --network "container:$gw" --entrypoint curl "$img" -fsS --max-time "$TIMEOUT" http://127.0.0.1:8404/ready 2>&1)"; then
    record "ollama-lb ready" OK soft "at least one healthy Ollama worker behind the LB"
  else
    record "ollama-lb ready" WARN soft "LB reports no healthy worker: ${out:0:100}"
  fi
}

images_curl_default() { printf 'curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b'; }

# --- loop guard ----------------------------------------------------------------------------------------
# lg_outputs <file…> — one line per [OUTPUT]: file, name, alias, match, match_regex, uri separated by US (0x1f); a regex may contain "|"
lg_outputs() {
  awk '
    function flush() { if (inout) printf "%s\037%s\037%s\037%s\037%s\037%s\n", fname, name, alias, match_g, rx, uri; inout = 0; name = alias = match_g = rx = uri = "" }
    FNR == 1 { flush() }
    /^[[:space:]]*\[[A-Za-z_]+\]/ { flush(); if (toupper($1) == "[OUTPUT]") { inout = 1; fname = FILENAME } next }
    inout && NF >= 2 && $0 !~ /^[[:space:]]*#/ {
      k = tolower($1); v = $0; sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v)
      if (k == "name") name = v; else if (k == "alias") alias = v; else if (k == "match") match_g = v
      else if (k == "match_regex") rx = v; else if (k == "uri") uri = v
    }
    END { flush() }
  ' "$@"
}

lg_matches() { # <match> <regex> <tag> → 0 when the output would receive the tag; 3 undecidable
  local m=$1 rx=$2 tag=$3
  if [[ -n "$rx" ]]; then
    if [[ "$rx" == *"(?"* ]]; then
      printf '%s\n' "$tag" | grep -qP -- "$rx" 2>/dev/null && return 0
      [[ $? -eq 2 ]] && return 3
      return 1
    fi
    [[ "$tag" =~ $rx ]] && return 0
    return 1
  fi
  # shellcheck disable=SC2053  # Fluent Bit "Match" is a glob: the unquoted right-hand side is intentional
  [[ "$tag" == $m ]] && return 0
  return 1
}

check_loopguard() {
  local dir files=() f line file name alias m rx uri tag allowed=0 other=0 console=0 problems=() undecidable=0 rc
  local sinks=" opentelemetry file stdout null prometheus_exporter counter "
  dir="${FB_DIR:-$STACK_DIR/fluent-bit}"
  for f in "$dir"/legs/*.conf "$dir"/conf.d/*.conf "$dir"/enabled.d/*.conf "$RENDERED_DIR"/*.conf; do
    if [[ -f "$f" ]]; then files+=("$f"); fi
  done
  if ((DOCKER_OK && KUBE == 0)) && svc_running fluent-bit; then
    local rendered
    if rendered="$("${COMPOSE[@]}" exec -T fluent-bit sh -c 'cat /etc/fluent-bit/enabled.d/*.conf' 2>/dev/null)" && [[ -n "$rendered" ]]; then
      vs_mkwork lg
      printf '%s\n' "$rendered" >"$VS_WORK/rendered-running.conf"
      files+=("$VS_WORK/rendered-running.conf")
    fi
  fi
  if ((${#files[@]} == 0)); then record loopguard SKIP crit "no Fluent Bit configuration found under $dir"; return 0; fi
  while IFS=$'\037' read -r file name alias m rx uri; do
    [[ -n "$name" ]] || continue
    if [[ "$uri" == /api/cecur/logs/ingest* || "$alias" == console_ingest ]]; then
      console=$((console + 1))
      for tag in cs3.ai.ollama cs3.ai.inference cs3.ai.tool_call cs3.ai.enrichment cs3.ai.x; do
        rc=0; lg_matches "$m" "$rx" "$tag" || rc=$?
        if ((rc == 0)); then problems+=("Console leg in ${file#"$STACK_DIR"/} matches $tag"); elif ((rc == 3)); then undecidable=1; fi
      done
    elif [[ "$sinks" == *" ${name,,} "* || "${alias,,}" == siem* || "${alias,,}" == esoc* ]]; then
      allowed=$((allowed + 1))
    else
      other=$((other + 1))
      rc=0; lg_matches "$m" "$rx" cs3.ai.ollama || rc=$?
      if ((rc == 0)); then problems+=("${name} output '${alias:-?}' in ${file#"$STACK_DIR"/} would forward cs3.ai.ollama"); elif ((rc == 3)); then undecidable=1; fi
    fi
  done < <(lg_outputs "${files[@]}")
  if ((${#problems[@]})); then record loopguard FAIL crit "telemetry loop possible: $(vs_join '; ' "${problems[@]}")"; return 0; fi
  if ((console == 0)); then record loopguard WARN crit "no Console leg output found in ${#files[@]} file(s) — invariant not provable here"; return 0; fi
  if ((undecidable)); then record loopguard WARN crit "a Match_Regex needs PCRE (grep -P) to evaluate; install GNU grep"; return 0; fi
  record loopguard OK crit "Console leg Match_Regex cannot match cs3.ai.*; cs3.ai.ollama reaches only ESOC/SIEM/file sinks ($allowed allowed, $other other output(s) excluded) (${#files[@]} config file(s))"
}

# --- remaining checks ----------------------------------------------------------------------------------
check_failclosed() {
  local out rc=0
  out="$(vs_failclosed_check 2>&1)" || rc=$?
  if ((rc == 0)); then record failclosed OK crit "no cloud LLM credentials for profile '$(vs_cfg CS3_PROFILE "unset")'"; return 0; fi
  printf '%s\n' "$out" >&2
  record failclosed FAIL crit "${out#FailClosedError: }"
}

check_pki() {
  local f min=99999 minname="" days n=0 expired=() warn=() name
  if [[ ! -d "$PKI_DIR" ]]; then record pki SKIP soft "no $PKI_DIR (Kubernetes: cert-manager owns the certificates)"; return 0; fi
  for f in "$PKI_DIR"/*.crt; do
    [[ -f "$f" ]] || continue
    name="$(basename "$f" .crt)"
    case "$name" in ca-signer|ca-next) continue ;; esac
    days="$(pki_cert_days_left "$f")"
    n=$((n + 1))
    if ((days < min)); then min=$days; minname=$name; fi
    if ((days < 0)); then expired+=("$name"); elif ((days < CERT_WARN_DAYS)); then warn+=("$name ($days d)"); fi
  done
  if ((n == 0)); then record pki WARN soft "no certificates in $PKI_DIR (run scripts/bootstrap.sh)"; return 0; fi
  if ((${#expired[@]})); then record pki FAIL crit "expired or unreadable: $(vs_join ', ' "${expired[@]}") — run scripts/rotate-certs.sh"; return 0; fi
  if ((${#warn[@]})); then record pki WARN soft "expiring within $CERT_WARN_DAYS d: $(vs_join ', ' "${warn[@]}") — run scripts/rotate-certs.sh"; return 0; fi
  record pki OK soft "$n certificate(s), soonest expiry $minname in $min day(s)"
}

check_pods() {
  local pods total ready names
  if ! ((KUBE)); then return 0; fi
  if ! vs_have kubectl; then record pods SKIP crit "kubectl not installed"; return 0; fi
  if ! pods="$(kubectl -n "$NAMESPACE" get pods -o json 2>&1)"; then record pods FAIL crit "kubectl: ${pods:0:100}"; return 0; fi
  total="$(jq '.items | length' <<<"$pods")"
  ready="$(jq '[.items[] | select(.status.phase == "Running" and ((.status.containerStatuses // []) | all(.ready)))] | length' <<<"$pods")"
  names="$(jq -r '[.items[] | select(.status.phase != "Running" or ((.status.containerStatuses // []) | any(.ready | not))) | .metadata.name] | .[0:5] | join(", ")' <<<"$pods")"
  if ((total == 0)); then record pods FAIL crit "no pods in namespace $NAMESPACE"
  elif ((ready == total)); then record pods OK crit "$ready/$total pods Ready"
  else record pods FAIL soft "$ready/$total pods Ready (not ready: $names)"
  fi
}

# --- report --------------------------------------------------------------------------------------------
STATUS_WORD="healthy"
EXIT_CODE=0

summarize() {
  local ok warn fail skip crit_fail soft_fail
  ok="$(printf '%s' "$RESULTS" | awk -F'\t' '$2 == "OK" {n++} END {print n + 0}')"
  warn="$(printf '%s' "$RESULTS" | awk -F'\t' '$2 == "WARN" {n++} END {print n + 0}')"
  fail="$(printf '%s' "$RESULTS" | awk -F'\t' '$2 == "FAIL" {n++} END {print n + 0}')"
  skip="$(printf '%s' "$RESULTS" | awk -F'\t' '$2 == "SKIP" {n++} END {print n + 0}')"
  crit_fail="$(printf '%s' "$RESULTS" | awk -F'\t' '$2 == "FAIL" && $3 == "crit" {n++} END {print n + 0}')"
  soft_fail=$((fail - crit_fail))
  SUM_OK=$ok; SUM_WARN=$warn; SUM_FAIL=$fail; SUM_SKIP=$skip
  if ((crit_fail > 0 || ok + warn == 0)); then STATUS_WORD="unhealthy"; EXIT_CODE=2
  elif ((warn > 0 || soft_fail > 0)); then STATUS_WORD="degraded"; EXIT_CODE=1
  else STATUS_WORD="healthy"; EXIT_CODE=0
  fi
}

SUM_OK=0; SUM_WARN=0; SUM_FAIL=0; SUM_SKIP=0

print_table() {
  local name status sev detail col
  printf '%-30s %-6s %-5s %s\n' CHECK STATUS SEV DETAIL
  while IFS=$'\t' read -r name status sev detail; do
    [[ -n "$name" ]] || continue
    case "$status" in OK) col=$O_GRN ;; WARN) col=$O_YEL ;; FAIL) col=$O_RED ;; *) col="" ;; esac
    printf '%-30s %s%-6s%s %-5s %s\n' "$name" "$col" "$status" "$O_RST" "$sev" "$detail"
  done <<<"$RESULTS"
  printf '\n%s: %s ok, %s warn, %s fail, %s skipped → %s (exit %s)\n' "$VS_NAME" "$SUM_OK" "$SUM_WARN" "$SUM_FAIL" "$SUM_SKIP" "$STATUS_WORD" "$EXIT_CODE"
}

print_json() {
  printf '%s' "$RESULTS" | jq -R -s -S --arg status "$STATUS_WORD" --arg ts "$(vs_now_iso)" --argjson code "$EXIT_CODE" \
    --arg mode "$(if ((KUBE)); then echo kubernetes; else echo compose; fi)" \
    'split("\n") | map(select(length > 0) | split("\t") | {name: .[0], status: .[1], severity: .[2], detail: (.[3] // "")}) as $c
     | {status: $status, exitCode: $code, timestamp: $ts, mode: $mode,
        summary: {ok: ($c | map(select(.status == "OK")) | length), warn: ($c | map(select(.status == "WARN")) | length),
                  fail: ($c | map(select(.status == "FAIL")) | length), skip: ($c | map(select(.status == "SKIP")) | length)},
        checks: $c}'
}

setup_environment() {
  CA_FILE="$PKI_DIR/ca.crt"
  if ((NO_DOCKER == 0 && KUBE == 0)) && vs_have docker && vs_compose_init; then
    if docker info >/dev/null 2>&1; then
      DOCKER_OK=1
      RUNNING_LIST="$(vs_compose_running_services || true)"
      if [[ -n "$RUNNING_LIST" ]]; then RUNNING_KNOWN=1; fi
    fi
  elif ((KUBE)); then
    vs_have kubectl || die "$EX_PREREQ" "kubectl is required for --kubernetes"
    vs_have docker && DOCKER_OK=0
  fi
}

run_checks() {
  RESULTS=""
  EP_CACHE=()
  if check_enabled fluent-bit; then check_fluent_bit; fi
  if check_enabled fluentd; then check_fluentd; fi
  if check_enabled opensearch; then check_opensearch; fi
  if check_enabled dashboards; then check_dashboards; fi
  if check_enabled prometheus; then check_prometheus; fi
  if check_enabled grafana; then check_grafana; fi
  if check_enabled alertmanager; then check_alertmanager; fi
  if check_enabled llm-gateway; then check_gateway; fi
  if check_enabled errow; then check_errow; fi
  if check_enabled manager; then check_manager; fi
  if check_enabled ollama; then check_ollama_loopback; check_ollama_lb; fi
  if check_enabled loopguard; then check_loopguard; fi
  if check_enabled failclosed; then check_failclosed; fi
  if check_enabled pki; then check_pki; fi
  if check_enabled pods; then check_pods; fi
  summarize
}

main() {
  parse_args "$@"
  vs_require curl jq awk
  setup_environment
  local start now
  start="$(date +%s)"
  run_checks
  while ((EXIT_CODE != 0 && WAIT > 0)); do
    now="$(date +%s)"
    if ((now - start >= WAIT)); then break; fi
    log_info "not healthy yet ($STATUS_WORD) — retrying in 5 s (--wait $WAIT)"
    vs_sleep 5
    run_checks
  done
  if ((AS_JSON)); then print_json; else print_table; fi
  exit "$EXIT_CODE"
}

main "$@"
