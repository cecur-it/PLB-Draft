#!/usr/bin/env bash
# Traces: PROMPT §4 Phase 4 (validation), §5 Observability; CONTRACT §1 (pinned prom images), §8.11
# Validates prometheus.yml, alerts.yml and alertmanager.yml with the PINNED images:
#   promtool check config / check rules / test rules (tests/alerts.test.yml), amtool check-config + routing tests,
#   a real boot of Prometheus + Alertmanager on a throw-away network (rules loaded, Alertmanager discovered, targets registered),
#   runbook-anchor consistency (alerts.yml <-> runbook-anchors.txt <-> docs/runbooks.md when it exists), yamllint when installed.
# Everything is created under prometheus/.scratch and removed on exit.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
STACK="$(dirname "$ROOT")"
RUN_ID="$$"
PROM_IMAGE="${PROMETHEUS_IMAGE:-prom/prometheus:v2.55.1@sha256:2659f4c2ebb718e7695cb9b25ffa7d6be64db013daba13e05c875451cf51b0d3}"
AM_IMAGE="${ALERTMANAGER_IMAGE:-prom/alertmanager:v0.27.0@sha256:e13b6ed5cb929eeaee733479dce55e10eb3bc2e9c4586c705a4e8da41e5eacf5}"
SCRATCH="$ROOT/.scratch/validate-$RUN_ID"
NET="vs-prom-$RUN_ID"
PASS=0
FAIL=0
STRICT_DOCS=false
BOOT=true

usage() {
  cat <<EOF
Usage: validate.sh [--strict-docs] [--no-boot] [-h|--help]
  Images: PROMETHEUS_IMAGE=$PROM_IMAGE
          ALERTMANAGER_IMAGE=$AM_IMAGE
  --strict-docs  fail (instead of warn) when docs/runbooks.md does not define every runbook anchor
  --no-boot      skip the Prometheus + Alertmanager container boot
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h | --help) usage; exit 0 ;;
    --strict-docs) STRICT_DOCS=true ;;
    --no-boot) BOOT=false ;;
    *) usage >&2; exit 2 ;;
  esac
done

cleanup() {
  local rc=$?
  docker rm -f "vs-prom-$RUN_ID" "vs-am-$RUN_ID" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH" 2>/dev/null || true
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
check() { # check <description> <command...>
  local desc=$1 out
  shift
  if out=$("$@" 2>&1); then ok "$desc"; else
    bad "$desc"
    tail -12 <<<"$out" >&2
  fi
}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 3; }
mkdir -p "$SCRATCH/secrets"
"$STACK/fluent-bit/tests/make-pki.sh" "$SCRATCH/pki" prometheus llm-gateway errow-mcp >/dev/null
printf 'fixture-llm-gateway-token-0123456789' >"$SCRATCH/secrets/llm_gateway_token"
chmod -R a+rX "$SCRATCH"

for img in "$PROM_IMAGE" "$AM_IMAGE"; do
  docker image inspect "$img" >/dev/null 2>&1 || retry 3 10 docker pull -q "$img" >/dev/null
done

promtool() {
  docker run --rm --entrypoint promtool -v "$ROOT:/etc/prometheus:ro" -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/secrets:/run/secrets:ro" "$PROM_IMAGE" "$@"
}
amtool() {
  docker run --rm --entrypoint amtool -v "$ROOT/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" "$AM_IMAGE" "$@"
}

echo "== 1. static"
bash -n "$0" && ok "bash -n validate.sh"
if command -v yamllint >/dev/null; then
  check "yamllint -d relaxed" yamllint -d relaxed "$ROOT/prometheus.yml" "$ROOT/alerts.yml" "$ROOT/alertmanager.yml" "$HERE/alerts.test.yml"
else ok "yamllint not installed (skipped)"; fi
if grep -nE "TODO|FIXME|CHANGEME|YOUR_" "$ROOT/prometheus.yml" "$ROOT/alerts.yml" "$ROOT/alertmanager.yml" >/dev/null; then bad "placeholder text found"; else ok "no placeholder text"; fi

echo "== 2. runbook anchors"
mapfile -t used < <(grep -oE 'runbook: "docs/runbooks.md#[a-z0-9-]+"' "$ROOT/alerts.yml" | sed 's/.*#//; s/"//' | sort -u)
mapfile -t listed < <(grep -vE '^#|^$' "$ROOT/runbook-anchors.txt" | cut -f1 | sort -u)
if [[ "${used[*]}" == "${listed[*]}" && ${#used[@]} -gt 0 ]]; then ok "alerts.yml uses exactly the ${#used[@]} anchors of runbook-anchors.txt"; else
  bad "alerts.yml and runbook-anchors.txt disagree"
  diff <(printf '%s\n' "${used[@]}") <(printf '%s\n' "${listed[@]}") >&2 || true
fi
if ! awk -F'\t' '!/^#/ && NF>0 && NF!=3 {exit 1}' "$ROOT/runbook-anchors.txt"; then bad "runbook-anchors.txt lines must have 3 tab-separated fields"; else ok "runbook-anchors.txt format"; fi
if [[ -f "$STACK/docs/runbooks.md" ]]; then
  missing=()
  for a in "${used[@]}"; do
    # GitHub slug: lower-case, drop punctuation, spaces -> hyphens
    grep -E '^#{1,6} ' "$STACK/docs/runbooks.md" | sed -E 's/^#+ +//' | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9 _-]//g; s/ /-/g' | grep -qx "$a" || missing+=("$a")
  done
  if ((${#missing[@]} == 0)); then ok "docs/runbooks.md defines every anchor"; elif $STRICT_DOCS; then bad "docs/runbooks.md misses: ${missing[*]}"; else echo "  WARN  docs/runbooks.md misses ${#missing[@]} anchors: ${missing[*]}"; fi
else
  if $STRICT_DOCS; then bad "docs/runbooks.md does not exist"; else echo "  WARN  docs/runbooks.md does not exist yet (anchors are listed in prometheus/runbook-anchors.txt)"; fi
fi

echo "== 3. promtool / amtool (pinned images)"
check "promtool check config prometheus.yml (+ referenced files)" promtool check config /etc/prometheus/prometheus.yml
check "promtool check rules alerts.yml" promtool check rules /etc/prometheus/alerts.yml
check "promtool test rules (alerts.test.yml)" promtool test rules /etc/prometheus/tests/alerts.test.yml
check "amtool check-config alertmanager.yml" amtool check-config /etc/alertmanager/alertmanager.yml
route_to() { # route_to <expected receiver> <label=value...>
  local want=$1 got
  shift
  got=$(amtool config routes test --config.file=/etc/alertmanager/alertmanager.yml "$@" 2>&1 | tail -1) || true
  [[ $got == "$want" ]]
}
route_case() { # route_case <description> <expected receiver> <label=value...>
  local desc=$1
  if route_to "${@:2}"; then ok "$desc"; else bad "$desc"; fi
}
route_case "route severity=critical -> ops-critical" ops-critical severity=critical alertname=LlmAuditChainBroken
route_case "route severity=warning -> ops-warning" ops-warning severity=warning alertname=FluentdOutputRetrying
route_case "route severity=info -> ops-info" ops-info severity=info alertname=LlmNoInferenceTraffic
route_case "route without severity -> default ops-warning" ops-warning alertname=Unlabelled

if $BOOT; then
  echo "== 4. boot Prometheus + Alertmanager"
  docker network create "$NET" >/dev/null
  docker run -d --name "vs-am-$RUN_ID" --network "$NET" --network-alias alertmanager --read-only --tmpfs /alertmanager:uid=65534 --user 65534:65534 \
    -v "$ROOT/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" "$AM_IMAGE" \
    --config.file=/etc/alertmanager/alertmanager.yml --storage.path=/alertmanager >/dev/null
  docker run -d --name "vs-prom-$RUN_ID" --network "$NET" --network-alias prometheus --read-only --tmpfs /prometheus:uid=65534 --user 65534:65534 \
    -v "$ROOT/prometheus.yml:/etc/prometheus/prometheus.yml:ro" -v "$ROOT/alerts.yml:/etc/prometheus/alerts.yml:ro" \
    -v "$SCRATCH/pki:/pki:ro" -v "$SCRATCH/secrets:/run/secrets:ro" "$PROM_IMAGE" \
    --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus --storage.tsdb.retention.time=15d \
    --web.enable-lifecycle --web.listen-address=0.0.0.0:9090 >/dev/null
  pget() { docker exec "vs-prom-$RUN_ID" wget -q -O- "http://127.0.0.1:9090$1"; }
  aget() { docker exec "vs-am-$RUN_ID" wget -q -O- "http://127.0.0.1:9093$1"; }
  prom_has() { pget "$1" | grep -q -- "$2"; }
  if retry 30 2 pget /-/ready >/dev/null 2>&1; then ok "prometheus /-/ready"; else bad "prometheus did not become ready"; docker logs "vs-prom-$RUN_ID" 2>&1 | tail -15 >&2; fi
  if retry 30 2 aget /-/ready >/dev/null 2>&1; then ok "alertmanager /-/ready"; else bad "alertmanager did not become ready"; docker logs "vs-am-$RUN_ID" 2>&1 | tail -15 >&2; fi
  if retry 10 2 pget /-/healthy >/dev/null 2>&1 && aget /-/healthy >/dev/null 2>&1; then ok "wget-based healthchecks work in both images"; else bad "healthcheck probe failed"; fi

  rules=$(pget /api/v1/rules)
  nrules=$(grep -o '"type":"alerting"' <<<"$rules" | wc -l)
  if ((nrules >= 30)); then ok "$nrules alerting rules loaded"; else bad "only $nrules alerting rules loaded"; fi
  if grep -q '"health":"err"' <<<"$rules"; then bad "a rule reports health=err"; else ok "no rule has health=err"; fi
  if retry 20 3 prom_has /api/v1/alertmanagers 'alertmanager:9093/api/v2/alerts'; then ok "prometheus discovered alertmanager:9093"; else bad "alertmanager not discovered"; fi
  if retry 20 3 prom_has '/api/v1/query?query=up%7Bjob%3D%22alertmanager%22%7D' '"1"\]'; then ok "alertmanager target is up"; else bad "alertmanager target is not up"; fi
  ntargets=$(pget /api/v1/targets | grep -o '"scrapePool"' | wc -l)
  if ((ntargets >= 7)); then ok "$ntargets scrape targets registered (prometheus, alertmanager, fluent-bit, fluentd x2, llm-gateway, errow-mcp)"; else bad "only $ntargets targets"; fi
  if docker logs "vs-prom-$RUN_ID" 2>&1 | grep -iE 'level=(error|fatal)|no such file' | grep -v 'dial tcp\|no such host\|lookup' >/dev/null; then
    bad "prometheus logged unexpected errors"
    docker logs "vs-prom-$RUN_ID" 2>&1 | grep -iE 'level=(error|fatal)|no such file' | head -5 >&2
  else ok "prometheus log has no config/file errors (only unreachable-target noise)"; fi
  if retry 3 2 docker exec "vs-prom-$RUN_ID" wget -q -O /dev/null --post-data='' http://127.0.0.1:9090/-/reload; then ok "hot reload (/-/reload) accepted"; else bad "reload failed"; fi
fi

echo "RESULT: $PASS passed, $FAIL failed"
((FAIL == 0))
