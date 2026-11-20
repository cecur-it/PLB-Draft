#!/usr/bin/env bash
# Traces: PROMPT §4 Phase 4 (validation), §5 Observability; CONTRACT §1 (pinned grafana/prometheus images), §8.11
# Validates grafana/ with the PINNED images:
#   static: yamllint, jq, tests/check_dashboards.py (structure, datasource uids, metric names, OpenSearch fields vs index templates),
#   promtool check rules over every PromQL expression of every dashboard (macros substituted),
#   a real Grafana boot (read-only rootfs, uid 472) with the provisioning tree: health, 9 datasources incl. secureJsonFields read
#   from $__file{}, 4 provisioned dashboards in the "Vendetta Stack" folder, provisioning log free of errors, hot reload, and the
#   exact wget healthcheck documented in prometheus/RUNTIME.md.
# Everything is created under grafana/.scratch and removed on exit.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
STACK="$(dirname "$ROOT")"
RUN_ID="$$"
GRAFANA_IMAGE="${GRAFANA_IMAGE:-grafana/grafana:10.4.19@sha256:a9043254ba16fb10945cc27333963dfd08eccbb43b51f1222d831cc564e3a1f4}"
PROM_IMAGE="${PROMETHEUS_IMAGE:-prom/prometheus:v2.55.1@sha256:2659f4c2ebb718e7695cb9b25ffa7d6be64db013daba13e05c875451cf51b0d3}"
SCRATCH="$ROOT/.scratch/validate-$RUN_ID"
CNAME="vs-grafana-$RUN_ID"
PASS=0
FAIL=0
BOOT=true

usage() {
  cat <<EOF
Usage: validate.sh [--no-boot] [-h|--help]
  Images: GRAFANA_IMAGE=$GRAFANA_IMAGE
          PROMETHEUS_IMAGE=$PROM_IMAGE   (promtool only)
  --no-boot  skip the Grafana container boot (static + promtool checks only)
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h | --help) usage; exit 0 ;;
    --no-boot) BOOT=false ;;
    *) usage >&2; exit 2 ;;
  esac
done

cleanup() {
  local rc=$?
  docker rm -f "$CNAME" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH" 2>/dev/null || true
  rmdir "$ROOT/.scratch" 2>/dev/null || true
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

for tool in docker jq python3; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 3; }
done
mkdir -p "$SCRATCH/secrets"

echo "== 1. static"
bash -n "$0" && ok "bash -n validate.sh"
if command -v yamllint >/dev/null; then
  check "yamllint -d relaxed provisioning" yamllint -d relaxed "$ROOT/provisioning"
else ok "yamllint not installed (skipped)"; fi
for f in "$ROOT"/dashboards/*.json; do check "jq empty $(basename "$f")" jq empty "$f"; done
if grep -rnE 'TODO|FIXME|CHANGEME|YOUR_|\$\{DS_' "$ROOT/provisioning" "$ROOT/dashboards" >/dev/null; then bad "placeholder text found"; else ok "no placeholder text"; fi
if grep -rniE '^[[:space:]-]*(basicAuthPassword|password|token|tlsCACert|tlsClientCert|tlsClientKey|apiKey|secret)[A-Za-z]*:[[:space:]]*[^$[:space:]]' "$ROOT/provisioning" >/dev/null; then bad "literal secret in provisioning"; else ok "provisioning holds no literal secrets"; fi
if grep -qE "type:[[:space:]]*(grafana-opensearch-datasource|grafana-clock-panel|grafana-piechart-panel)" "$ROOT/provisioning/datasources/datasources.yml"; then bad "plugin datasource type used (air-gap unsafe)"; else ok "only built-in datasource types"; fi

echo "== 2. dashboards vs the stack"
if out=$(python3 "$HERE/check_dashboards.py" --rules-out "$SCRATCH/dashboard-exprs.json" 2>&1); then
  sed -n '/ PASS /p;/WARN/p' <<<"$out"
  PASS=$((PASS + $(grep -c ' PASS ' <<<"$out")))
else
  echo "$out" >&2
  FAIL=$((FAIL + $(grep -c 'FAIL' <<<"$out")))
  bad "check_dashboards.py"
fi

echo "== 3. promtool: every dashboard PromQL expression parses"
docker image inspect "$PROM_IMAGE" >/dev/null 2>&1 || retry 3 10 docker pull -q "$PROM_IMAGE" >/dev/null
chmod -R a+rX "$SCRATCH"
check "promtool check rules over dashboard expressions" docker run --rm --entrypoint promtool -v "$SCRATCH:/w:ro" "$PROM_IMAGE" check rules /w/dashboard-exprs.json

if ! $BOOT; then
  echo "RESULT: $PASS passed, $FAIL failed (boot skipped)"
  ((FAIL == 0))
  exit $?
fi

echo "== 4. Grafana boot (pinned image)"
docker image inspect "$GRAFANA_IMAGE" >/dev/null 2>&1 || retry 3 10 docker pull -q "$GRAFANA_IMAGE" >/dev/null
"$STACK/fluent-bit/tests/make-pki.sh" "$SCRATCH/pki" grafana >/dev/null
ADMIN_PW="fixture-grafana-admin-$RUN_ID-0123456789"
printf '%s' "$ADMIN_PW" >"$SCRATCH/secrets/grafana_admin_password"
printf 'fixture-opensearch-admin-0123456789' >"$SCRATCH/secrets/opensearch_admin_password"
chmod -R a+rX "$SCRATCH"

docker run -d --name "$CNAME" --user 472 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /var/lib/grafana:rw,uid=472,gid=0,mode=0770 --tmpfs /tmp:rw,mode=1777 \
  -v "$ROOT/provisioning:/etc/grafana/provisioning:ro" -v "$ROOT/dashboards:/var/lib/grafana/dashboards:ro" \
  -v "$SCRATCH/pki/ca.crt:/pki/ca.crt:ro" -v "$SCRATCH/secrets:/run/secrets:ro" \
  -e GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana_admin_password \
  -e GF_ANALYTICS_REPORTING_ENABLED=false -e GF_ANALYTICS_CHECK_FOR_UPDATES=false -e GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false \
  -e GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false -e GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED=true -e GF_USERS_ALLOW_SIGN_UP=false -e GF_SECURITY_DISABLE_GRAVATAR=true -e GF_LOG_MODE=console \
  "$GRAFANA_IMAGE" >/dev/null

AUTH="Authorization: Basic $(printf 'admin:%s' "$ADMIN_PW" | base64 -w0)"
gf() { docker exec "$CNAME" wget -q -O- --header "$AUTH" "http://localhost:3000$1"; }
gf_post() { docker exec "$CNAME" wget -q -O- --header "$AUTH" --post-data '' "http://localhost:3000$1"; }
HEALTHCHECK='wget -q -O- http://localhost:3000/api/health | grep -q "\"database\": \"ok\""'

if retry 40 3 docker exec "$CNAME" sh -c "$HEALTHCHECK" 2>/dev/null; then ok "documented healthcheck passes (/api/health database ok)"; else
  bad "Grafana did not become healthy"
  docker logs "$CNAME" 2>&1 | tail -30 >&2
fi

jqe() { jq -e "$2" <<<"$1" >/dev/null; } # jqe <json> <filter>
count_is() { [[ "$(jq length <<<"$1")" == "$2" ]]; } # count_is <json> <n>
version_is() { [[ "$(docker exec "$CNAME" wget -q -O- http://localhost:3000/api/health | jq -r .version)" == "$1" ]]; }
container_stable() { [[ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$CNAME")" == "true 0" ]]; }
four_dashboards() { [[ "$(gf '/api/search?type=dash-db' | jq length)" == 4 ]]; }

check "version is 10.4.19" version_is 10.4.19

retry 10 3 four_dashboards || true
SEARCH="$(gf '/api/search?type=dash-db' || true)"
check "4 dashboards provisioned" count_is "$SEARCH" 4
for uid in cs3-pipeline-health cs3-vendetta-overview cs3-errow-offense cs3-llm-slo; do
  check "dashboard $uid in folder 'Vendetta Stack'" jqe "$SEARCH" ".[] | select(.uid==\"$uid\" and .folderTitle==\"Vendetta Stack\")"
  check "dashboard $uid is provisioned (UI edits disabled)" jqe "$(gf "/api/dashboards/uid/$uid" || true)" ".meta.provisioned==true and (.dashboard.panels|length)>0"
done

DS="$(gf /api/datasources || true)"
check "9 datasources provisioned" count_is "$DS" 9
check "Prometheus is the default datasource" jqe "$DS" '.[] | select(.uid=="cs3-prometheus" and .isDefault==true and .type=="prometheus")'
check "Alertmanager datasource (prometheus implementation)" jqe "$DS" '.[] | select(.uid=="cs3-alertmanager" and .type=="alertmanager")'
check "7 OpenSearch datasources use the built-in elasticsearch type" jqe "$DS" '[.[] | select(.type=="elasticsearch")] | length == 7'
for uid in cs3-os-vendetta-alerts cs3-os-errow-findings cs3-os-errow-runs cs3-os-errow-llm cs3-os-errow-mcp cs3-os-ai-inference cs3-os-ai-audit; do
  check "$uid: basic auth, secrets read from files, index pattern" jqe "$(gf "/api/datasources/uid/$uid" || true)" \
    '.basicAuth==true and .secureJsonFields.basicAuthPassword==true and .secureJsonFields.tlsCACert==true and .jsonData.timeField=="@timestamp" and (.jsonData.index|endswith("-*"))'
done

check "hot reload of dashboard provisioning (POST /api/admin/provisioning/dashboards/reload)" gf_post /api/admin/provisioning/dashboards/reload
sleep 2
LOGS="$(docker logs "$CNAME" 2>&1)"
if grep -E "logger=provisioning[^ ]* .*level=(error|warn)" <<<"$LOGS" >/dev/null; then
  bad "provisioning errors/warnings in the Grafana log"
  grep -E "logger=provisioning" <<<"$LOGS" | grep -E "level=(error|warn)" | head -5 >&2
else ok "no provisioning errors or warnings in the Grafana log"; fi
PLUGIN_RE='grafana\.com/api/plugins|installing plugin|downloading plugin|logger=plugin[a-z.]* .*level=(warn|error)'
if grep -qiE "$PLUGIN_RE" <<<"$LOGS"; then
  bad "Grafana tried to download or failed to load a plugin"
  grep -iE "$PLUGIN_RE" <<<"$LOGS" | cut -c1-300 | head -5 >&2
else ok "no plugin downloads attempted (air-gap safe)"; fi
check "container still running and not restarting" container_stable

echo "RESULT: $PASS passed, $FAIL failed"
((FAIL == 0))
