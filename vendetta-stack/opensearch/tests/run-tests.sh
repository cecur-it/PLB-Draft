#!/usr/bin/env bash
# End-to-end test of the opensearch/ assets against a REAL single-node
# OpenSearch 2.17.1 (pinned image, 512 MB heap). Everything it creates
# (container, network, throwaway TLS material, password) is removed on exit.
#
#   tests/run-tests.sh [--keep] [--with-dashboards]
#
#   --keep             leave the node running on 127.0.0.1:${PORT} for debugging
#                      (the work dir and containers are then NOT removed)
#   --with-dashboards  also start the pinned Dashboards image (needs ~1 GB RAM
#                      more) and run dashboards/entrypoint.sh + import.sh against it
#                      (without it, import.sh is tested against a mock saved-objects API)
#
# Steps: lint, apply.sh --dry-run, start node, apply.sh x2 (+--force +drift),
# error exit codes, pipeline _simulate with exact-field assertions, mapping
# acceptance for every index family, upsert-by-id, ISM auto-attach, import.sh,
# and a start-up check of the 3-node opensearch.yml.
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DOCS="${SCRIPT_DIR}/docs"
readonly SCRIPT_DIR OS_DIR DOCS

OS_IMAGE="${OPENSEARCH_IMAGE:-opensearchproject/opensearch:2.17.1@sha256:1193b7c29c5d63028523728243cc4da047ac49f697a8f8105e5aeee2f89bcc4c}"
OSD_IMAGE="${DASHBOARDS_IMAGE:-opensearchproject/opensearch-dashboards:2.17.1@sha256:dc12b6f576aae6024780c01b3cc81abdf611d34340371980ef8edc7738479b8f}"
RUN_ID="vsos-test-$$"
NET="${RUN_ID}-net"
NODE="${RUN_ID}-node"
PORT=$((19200 + $$ % 400))
WORK=""
KEEP=false
WITH_DASHBOARDS=false
PASSED=0
FAILED=0
APPLY_N=0
APPLY_RC=0
APPLY_OUT=""
HTTP_CODE=""
HTTP_BODY=""
declare -a APPLY_ENV=()
declare -a NODES=()
PW=""

for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=true ;;
    --with-dashboards) WITH_DASHBOARDS=true ;;
    -h | --help)
      sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$arg" >&2
      exit 2
      ;;
  esac
done

say() { printf '\n== %s\n' "$*"; }
ok() {
  PASSED=$((PASSED + 1))
  printf '  ok    %s\n' "$1"
}
bad() {
  FAILED=$((FAILED + 1))
  printf '  FAIL  %s\n' "$1"
  shift
  while (($#)); do
    printf '        %s\n' "$1"
    shift
  done
}
check() { # description actual expected
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "expected: $3" "actual:   $2"; fi
}
check_jq() { # description json filter expected-json (numbers and key order normalised)
  local actual expected norm='walk(if type == "number" then . + 0 else . end)'
  actual="$(jq -c "$3" <<<"$2" 2>&1 || true)"
  actual="$(jq -cS "$norm" <<<"$actual" 2>/dev/null || printf '%s' "$actual")"
  expected="$(jq -cS "$norm" <<<"$4")"
  check "$1" "$actual" "$expected"
}
check_contains() { # description haystack needle
  if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "missing: $3" "in: ${2:0:600}"; fi
}

dump_logs() {
  local n
  for n in "${NODES[@]}"; do
    printf -- '--- last log lines of %s\n' "$n" >&2
    docker logs --tail 60 "$n" 2>&1 | cut -c1-300 >&2 || true
  done
}

cleanup() {
  local rc=$? ids
  if [[ "$KEEP" == true && -n "$WORK" ]]; then
    printf '\n--keep: node on https://127.0.0.1:%s, work dir %s, network %s\n' "$PORT" "$WORK" "$NET"
    printf 'remove with: docker ps -aq --filter name=%s | xargs docker rm -f -v; docker network rm %s; rm -rf %s\n' "$RUN_ID" "$NET" "$WORK"
    return
  fi
  if ((rc != 0 && FAILED == 0)); then dump_logs; fi
  ids="$(docker ps -aq --filter "name=${RUN_ID}" 2>/dev/null || true)"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086
    docker rm -f -v $ids >/dev/null 2>&1 || true
  fi
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [[ -n "$WORK" && -d "$WORK" ]]; then rm -rf "$WORK"; fi
  return 0
}
trap cleanup EXIT

need() {
  if ! command -v "$1" >/dev/null; then
    printf 'missing required tool: %s\n' "$1" >&2
    exit 2
  fi
}

# ---------------------------------------------------------------- lint
lint() {
  say "lint: JSON, YAML, shell"
  local f bad_json=0 out
  while IFS= read -r f; do
    if ! jq empty "$f" 2>/dev/null; then
      bad "jq empty $f"
      bad_json=1
    fi
  done < <(find "$OS_DIR" -name '*.json' -not -path '*/.work.*')
  if ((bad_json == 0)); then ok "jq empty: every JSON file parses"; fi
  if [[ -f "${OS_DIR}/dashboards/saved-objects.ndjson" ]]; then
    if jq -c . "${OS_DIR}/dashboards/saved-objects.ndjson" >/dev/null 2>&1; then ok "saved-objects.ndjson: every line parses"; else bad "saved-objects.ndjson is not valid NDJSON"; fi
  fi
  if command -v yamllint >/dev/null; then
    if out="$(yamllint -d '{extends: default, rules: {line-length: {max: 200}, document-start: disable, truthy: disable}}' "$OS_DIR" 2>&1)"; then ok "yamllint: clean"; else bad "yamllint" "$out"; fi
  else
    printf '  skip  yamllint not installed\n'
  fi
  if command -v shellcheck >/dev/null; then
    if out="$(shellcheck -x "${OS_DIR}/apply.sh" "${OS_DIR}/entrypoint.sh" "${SCRIPT_DIR}/run-tests.sh" "${OS_DIR}"/dashboards/*.sh 2>&1)"; then ok "shellcheck: clean"; else bad "shellcheck" "$out"; fi
  else
    printf '  skip  shellcheck not installed\n'
  fi
  if python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "${OS_DIR}/apply-helper.py" 2>/dev/null; then ok "apply-helper.py parses"; else bad "apply-helper.py does not parse"; fi
}

# ------------------------------------------------- throwaway TLS + secret
make_pki() {
  say "throwaway TLS material and admin password"
  mkdir -p "$WORK/ca" "$WORK/pki" "$WORK/secrets"
  chmod 755 "$WORK" "$WORK/pki" "$WORK/secrets"
  (
    cd "$WORK"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=vendetta-test-ca/O=vendetta-stack' \
      -keyout ca/ca.key -out pki/ca.crt 2>/dev/null
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out pki/opensearch.key 2>/dev/null
    openssl req -new -key pki/opensearch.key -subj '/CN=opensearch/O=vendetta-stack' -out ca/node.csr 2>/dev/null
    printf 'subjectAltName=DNS:opensearch,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\n' >ca/node.ext
    openssl x509 -req -in ca/node.csr -CA pki/ca.crt -CAkey ca/ca.key -CAcreateserial -days 2 -extfile ca/node.ext \
      -out pki/opensearch.crt 2>/dev/null
  )
  chmod 644 "$WORK"/pki/*
  PW="Vs-$(openssl rand -hex 12)-Zq9!\"\\x"
  printf '%s\n' "$PW" >"$WORK/secrets/opensearch_admin_password"
  printf '%s\n' "wrong-$(openssl rand -hex 8)-Pw1!" >"$WORK/secrets/wrong_password"
  chmod 644 "$WORK"/secrets/*
  if grep -q 'BEGIN PRIVATE KEY' "$WORK/pki/opensearch.key"; then ok "node key is PKCS#8 (BEGIN PRIVATE KEY)"; else bad "node key is not PKCS#8"; fi
  check "node certificate verifies against the test CA" "$(openssl verify -CAfile "$WORK/pki/ca.crt" "$WORK/pki/opensearch.crt" 2>&1 | tail -n1 | sed 's/^.*: //')" "OK"
}

# ------------------------------------------------------- docker plumbing
node_alive() { [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" == true ]]; }

# Runs apply.sh inside the image (bash+curl+python3, no jq: the real init-job path).
run_apply() {
  local name="${RUN_ID}-apply-$((++APPLY_N))" n alive=true
  docker run -d --name "$name" --network "$NET" "${APPLY_ENV[@]}" \
    -v "$OS_DIR:/opensearch:ro" \
    -v "$WORK/pki/ca.crt:/pki/ca.crt:ro" \
    -v "$WORK/secrets:/run/secrets:ro" \
    --entrypoint /opensearch/apply.sh "$OS_IMAGE" "$@" >/dev/null
  while node_alive "$name"; do
    for n in "${NODES[@]}"; do node_alive "$n" || alive=false; done
    if [[ "$alive" != true ]]; then
      docker rm -f "$name" >/dev/null
      dump_logs
      bad "a node died while apply.sh waited for it"
      exit 1
    fi
    sleep 2
  done
  APPLY_RC="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
  APPLY_OUT="$(docker logs "$name" 2>&1)"
  docker rm -f "$name" >/dev/null
}

cfg_line() { # escape for a curl config file
  local p=${PW//\\/\\\\}
  p=${p//\"/\\\"}
  printf 'user = "admin:%s"\n' "$p"
}

# Host-side API call. Sets HTTP_CODE and HTTP_BODY.
api() { # method path [body-json]
  local method=$1 path=$2 data=${3-} out
  local -a extra=()
  if [[ -n "$data" ]]; then extra=(--data-binary @-); fi
  out="$(printf '%s\n' "$data" | curl -sS --max-time 60 --cacert "$WORK/pki/ca.crt" -K <(cfg_line) -X "$method" \
    -H 'Content-Type: application/json' "${extra[@]}" -w $'\n%{http_code}' "https://127.0.0.1:${PORT}${path}" 2>&1)" || {
    HTTP_CODE=000
    HTTP_BODY=$out
    return 0
  }
  HTTP_CODE=${out##*$'\n'}
  HTTP_BODY=${out%$'\n'*}
}

api_ok() { # description method path [body]
  local d=$1
  shift
  api "$@"
  if [[ "$HTTP_CODE" == 2?? ]]; then ok "$d (HTTP ${HTTP_CODE})"; else bad "$d" "HTTP ${HTTP_CODE}: ${HTTP_BODY:0:500}"; fi
}

simulate() { # pipeline docfile index
  local body
  body="$(jq -n --slurpfile d "$2" --arg i "$3" '{docs:[{_index:$i,_source:$d[0]}]}')"
  api POST "/_ingest/pipeline/$1/_simulate" "$body"
  if [[ "$HTTP_CODE" != 200 ]]; then bad "simulate $1 with $(basename "$2")" "HTTP ${HTTP_CODE}: ${HTTP_BODY:0:800}"; fi
}

# ------------------------------------------------------------ test groups
test_offline() {
  say "apply.sh offline behaviour"
  local out rc=0
  out="$("${OS_DIR}/apply.sh" --dry-run 2>&1)" || rc=$?
  check "dry-run exits 0 without network or credentials" "$rc" "0"
  check_contains "dry-run lists the planned templates" "$out" "vendetta-alerts"
  rc=0
  "${OS_DIR}/apply.sh" --help >/dev/null 2>&1 || rc=$?
  check "--help exits 0" "$rc" "0"
  rc=0
  "${OS_DIR}/apply.sh" --no-such-flag >/dev/null 2>&1 || rc=$?
  check "unknown flag exits 2" "$rc" "2"
  rc=0
  "${OS_DIR}/apply.sh" --insecure-for-bootstrap >/dev/null 2>&1 || rc=$?
  check "--insecure-for-bootstrap refused by default (exit 2)" "$rc" "2"
}

test_node_start() {
  say "start OpenSearch ${OS_IMAGE%%@*} (single node, 512 MB heap)"
  docker network create "$NET" >/dev/null
  NODES+=("$NODE")
  docker run -d --name "$NODE" --network "$NET" --network-alias opensearch -p "127.0.0.1:${PORT}:9200" \
    --ulimit nofile=65536:65536 --ulimit memlock=-1:-1 \
    -e OPENSEARCH_JAVA_OPTS='-Xms512m -Xmx512m' \
    -e cluster.routing.allocation.disk.threshold_enabled=false \
    -e NODE_NAME=opensearch \
    -v "$OS_DIR:/opensearch:ro" \
    -v "${OS_DIR}/opensearch.single-node.yml:/usr/share/opensearch/config/opensearch.yml:ro" \
    -v "$WORK/pki:/usr/share/opensearch/config/certs:ro" \
    -v "$WORK/secrets/opensearch_admin_password:/run/secrets/opensearch_admin_password:ro" \
    --entrypoint /opensearch/entrypoint.sh "$OS_IMAGE" >/dev/null
  ok "container ${NODE} started"
}

test_apply() {
  say "apply.sh against the live node"
  APPLY_ENV=()
  run_apply --wait-timeout 300
  check "first apply exits 0" "$APPLY_RC" "0"
  if [[ "$APPLY_RC" != 0 ]]; then printf '%s\n' "$APPLY_OUT" | tail -n 30; fi
  check_contains "first apply created objects" "$APPLY_OUT" "created pipeline sarif-to-vendetta-alert"
  check_contains "first apply created the bootstrap index" "$APPLY_OUT" "vendetta-alerts-000001"
  run_apply --wait-timeout 60
  check "second apply exits 0" "$APPLY_RC" "0"
  check_contains "second apply changed nothing (idempotent)" "$APPLY_OUT" "done: 0 created, 0 updated,"
  run_apply --force --wait-timeout 60
  check "--force apply exits 0" "$APPLY_RC" "0"
  check_contains "--force rewrites ISM policies with seq_no/primary_term" "$APPLY_OUT" "updated ism rollover-40gb"
  api_ok "tamper with a template to create drift" PUT /_index_template/errow-runs \
    '{"index_patterns":["errow-runs-*"],"priority":200,"template":{"settings":{"index.number_of_shards":1}}}'
  run_apply --wait-timeout 60
  check_contains "drifted template is detected and restored" "$APPLY_OUT" "updated template errow-runs"
  check_contains "only the drifted object changed" "$APPLY_OUT" "done: 0 created, 1 updated,"

  say "apply.sh error exit codes"
  APPLY_ENV=(-e OPENSEARCH_URL=https://127.0.0.1:9)
  run_apply --wait-timeout 4
  check "unreachable cluster exits 3" "$APPLY_RC" "3"
  APPLY_ENV=(-e OPENSEARCH_PASSWORD_FILE=/run/secrets/wrong_password)
  run_apply --wait-timeout 30
  check "wrong password exits 4" "$APPLY_RC" "4"
  APPLY_ENV=(-e OPENSEARCH_CA=/nonexistent/ca.crt)
  run_apply --wait-timeout 5
  check "missing CA exits 4" "$APPLY_RC" "4"
  APPLY_ENV=(-e OPENSEARCH_URL=http://opensearch:9200)
  run_apply --wait-timeout 5
  check "plain-http URL refused (exit 4)" "$APPLY_RC" "4"
  APPLY_ENV=()
}

test_security() {
  say "security plugin and cluster settings"
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$WORK/pki/ca.crt" "https://127.0.0.1:${PORT}/" 2>&1 || true)"
  check "anonymous request rejected (401)" "$code" "401"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:${PORT}/" 2>&1 || true)"
  if [[ "$code" == 200 ]]; then bad "plain http answered with 200"; else ok "plain http is not served"; fi
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://127.0.0.1:${PORT}/" 2>&1 || true)"
  if [[ "$code" == 200 ]]; then bad "TLS accepted without the CA"; else ok "TLS verification fails without the stack CA"; fi
  api GET /_plugins/_security/authinfo
  check_jq "admin authenticates (basic auth over TLS)" "$HTTP_BODY" '.user_name' '"admin"'
  api GET '/_cluster/settings?flat_settings=true'
  check_jq "auto_create_index restricted to known prefixes" "$HTTP_BODY" '.persistent["action.auto_create_index"]' '"+vendetta-alerts-*,+errow-*,+cfgaudit-*,+cs3-ai-*,+security-auditlog-*,+.*,-*"'
  api PUT /stray-index-xyz/_doc/1 '{"a":1}'
  check "auto-creating an unknown index is rejected (404)" "$HTTP_CODE" "404"
  api GET /_cluster/health
  check_jq "cluster is not red" "$HTTP_BODY" '.status != "red"' 'true'
  api GET '/_nodes/settings?filter_path=nodes.*.settings.node.attr'
  check_jq "node attribute box_type=hot" "$HTTP_BODY" '[.nodes[].settings.node.attr.box_type][0]' '"hot"'
  api GET '/_snapshot/vendetta-snapshots'
  check_jq "snapshot repository vendetta-snapshots is an fs repo" "$HTTP_BODY" '.["vendetta-snapshots"].type' '"fs"'
  api GET /_alias/vendetta-alerts
  check_jq "write alias vendetta-alerts -> vendetta-alerts-000001" "$HTTP_BODY" '.["vendetta-alerts-000001"].aliases["vendetta-alerts"].is_write_index' 'true'
  api GET /_index_template
  check_jq "all 10 index templates present" "$HTTP_BODY" '[.index_templates[].name] | sort' '["cfgaudit-findings","cfgaudit-runs","cs3-ai-audit","cs3-ai-inference","errow-findings","errow-generic","errow-runs","errow-threat-models","errow-transcripts","vendetta-alerts"]'
  api GET '/_ingest/pipeline/aiincident-to-vendetta-alert,sarif-to-vendetta-alert,errow-finding-enrichment,vendetta-alerts-router'
  check_jq "all 4 ingest pipelines present" "$HTTP_BODY" 'keys' '["aiincident-to-vendetta-alert","errow-finding-enrichment","sarif-to-vendetta-alert","vendetta-alerts-router"]'
  api GET '/vendetta-alerts-000001/_settings/index.default_pipeline'
  check_jq "bootstrap index uses the router as default_pipeline" "$HTTP_BODY" '.["vendetta-alerts-000001"].settings.index.default_pipeline' '"vendetta-alerts-router"'
  api GET '/_plugins/_ism/policies'
  check_jq "all 6 ISM policies present" "$HTTP_BODY" '[.policies[].policy.policy_id] | sort' '["cfgaudit-findings-retention","cfgaudit-runs-retention","cs3-ai-audit-retention","errow-findings-retention","hot-warm-cold","rollover-40gb"]'
}

test_template_composition() {
  say "template priorities (specific templates win)"
  api POST '/_index_template/_simulate_index/errow-sarif-2026.11.12' ''
  check_jq "errow-sarif-* gets the findings mapping (SARIF ruleId field)" "$HTTP_BODY" '.template.mappings.properties | has("ruleId")' 'true'
  api POST '/_index_template/_simulate_index/errow-findings-2026.11.12' ''
  check_jq "errow-findings-* gets the findings mapping" "$HTTP_BODY" '.template.mappings.properties | has("ruleId")' 'true'
  api POST '/_index_template/_simulate_index/errow-mcp-2026.11.12' ''
  check_jq "errow-mcp-* is served by the generic template (event_type, no SARIF ruleId)" "$HTTP_BODY" '.template.mappings.properties | [has("event_type"), has("ruleId")]' '[true,false]'
  api POST '/_index_template/_simulate_index/errow-runs-2026.11.12' ''
  check_jq "errow-runs-* gets the runs mapping" "$HTTP_BODY" '.template.mappings.properties | has("run_id")' 'true'
  api POST '/_index_template/_simulate_index/vendetta-alerts-000002' ''
  check_jq "vendetta-alerts-* sets the rollover alias" "$HTTP_BODY" '.template.settings.index.plugins.index_state_management.rollover_alias' '"vendetta-alerts"'
  api POST '/_index_template/_simulate_index/cs3-ai-audit-2026.11.12' ''
  check_jq "cs3-ai-audit-* is dynamic:false" "$HTTP_BODY" '.template.mappings.dynamic' '"false"'
  api POST '/_index_template/_simulate_index/cfgaudit-findings-2026.11.12' ''
  check_jq "cfgaudit-findings-* has dedicated identity, hashes and nested framework mappings" "$HTTP_BODY" \
    '.template.mappings | [.dynamic, .properties.asset.properties.id.type, .properties.config.properties.sha256.type, .properties.control.properties.frameworks.type]' \
    '["false","keyword","keyword","nested"]'
  api POST '/_index_template/_simulate_index/cfgaudit-runs-2026.11.12' ''
  check_jq "cfgaudit-runs-* has run timestamps, per-asset outcomes and dynamic:false" "$HTTP_BODY" \
    '.template.mappings | [.dynamic, .properties.run.properties.started_at.type, .properties.assets.properties.config_sha256.type, (.properties | has("ruleId"))]' \
    '["false","date","keyword",false]'
}

test_pipelines() {
  say "ingest pipelines: _simulate with realistic documents"
  local out src
  src='.docs[0].doc._source'
  simulate errow-finding-enrichment "$DOCS/finding-sqli-high.json" errow-findings-2026.11.12
  out=$HTTP_BODY
  check_jq "enrichment: owasp A03:2021-Injection" "$out" "${src}.owasp" '"A03:2021-Injection"'
  check_jq "enrichment: cwe normalised" "$out" "${src}.cwe" '"CWE-89"'
  check_jq "enrichment: severity high" "$out" "${src}.severity" '"high"'
  check_jq "enrichment: ATT&CK id T1190" "$out" "${src}.mitre.id" '["T1190"]'
  check_jq "enrichment: ATT&CK technique name" "$out" "${src}.mitre.technique" '["Exploit Public-Facing Application"]'
  check_jq "enrichment: ATT&CK tactic" "$out" "${src}.mitre.tactic" '["Initial Access"]'
  check_jq "enrichment keeps the raw SARIF fields" "$out" "${src}.ruleId" '"CWE-89"'
  check_jq "enrichment adds no ingest_error" "$out" "${src}.ingest_error" 'null'
  simulate errow-finding-enrichment "$DOCS/finding-xss-medium.json" errow-findings-2026.11.12
  check_jq "enrichment XSS: owasp A03" "$HTTP_BODY" "${src}.owasp" '"A03:2021-Injection"'
  check_jq "enrichment XSS: severity medium" "$HTTP_BODY" "${src}.severity" '"medium"'
  check_jq "enrichment XSS: ATT&CK ids include T1059.007" "$HTTP_BODY" "${src}.mitre.id | index(\"T1059.007\") != null" 'true'

  simulate sarif-to-vendetta-alert "$DOCS/finding-sqli-high.json" vendetta-alerts-000001
  out=$HTTP_BODY
  check_jq "sarif->alert: _id = doc_id" "$out" '.docs[0].doc._id' '"7c1f0e5b3a94d2886e0b5f1c9a4d7e3320b8c6a15f94e7d2b3a0c8e1f6d95a42"'
  check_jq "sarif->alert: id = doc_id" "$out" "${src}.id" '"7c1f0e5b3a94d2886e0b5f1c9a4d7e3320b8c6a15f94e7d2b3a0c8e1f6d95a42"'
  check_jq "sarif->alert: @timestamp kept from the shipper" "$out" "${src}[\"@timestamp\"]" '"2026-11-12T09:14:31.482Z"'
  check_jq "sarif->alert: source" "$out" "${src}.source" '{"system":"errow","stream":"errow.findings"}'
  check_jq "sarif->alert: rule.id" "$out" "${src}.rule.id" '"CWE-89"'
  check_jq "sarif->alert: rule.level (high = 11)" "$out" "${src}.rule.level" '11'
  check_jq "sarif->alert: rule.groups" "$out" "${src}.rule.groups" '["errow","sarif","CWE-89"]'
  check_jq "sarif->alert: rule.description = message.text" "$out" "${src}.rule.description | startswith(\"SQL Injection in product search (q parameter)\")" 'true'
  check_jq "sarif->alert: severity" "$out" "${src}.severity" '"high"'
  check_jq "sarif->alert: mitre.id" "$out" "${src}.mitre.id" '["T1190"]'
  check_jq "sarif->alert: mitre.tactic" "$out" "${src}.mitre.tactic" '["Initial Access"]'
  check_jq "sarif->alert: mitre.technique" "$out" "${src}.mitre.technique" '["Exploit Public-Facing Application"]'
  check_jq "sarif->alert: agent.name = target host" "$out" "${src}.agent.name" '"scan-target.vendetta.lab"'
  check_jq "sarif->alert: location = endpoint (synthetic SECURITY.md location skipped)" "$out" "${src}.location" '"/rest/products/search"'
  check_jq "sarif->alert: errow.* block" "$out" "${src}.errow | {run,finding_id,cwe,owasp,cvss,confidence,target,endpoint,sarif_rule_id}" \
    '{"run":"scan-target-vendetta-lab-8080_3f9a","finding_id":"vuln-0001","cwe":"CWE-89","owasp":"A03:2021-Injection","cvss":8.6,"confidence":"high","target":"http://scan-target.vendetta.lab:8080","endpoint":"/rest/products/search","sarif_rule_id":"CWE-89"}'
  check_jq "sarif->alert: errow.fingerprint is the SARIF primaryLocationLineHash" "$out" "${src}.errow.fingerprint" '"29086aa0756bcc40406def84d8e48c8d99d6eecfe57aedd74acaacd79b863866"'
  check_jq "sarif->alert: full_log is a concise summary without PoC bodies" "$out" "${src}.full_log | (length < 1000) and (contains(\"UNION SELECT id,email\") | not)" 'true'
  check_jq "sarif->alert: raw SARIF keys are gone" "$out" "${src} | [has(\"ruleId\"), has(\"properties\"), has(\"locations\"), has(\"message\"), has(\"partialFingerprints\"), has(\"doc_id\")] | any" 'false'
  check_jq "sarif->alert: no ai/root_cause fields invented" "$out" "${src} | [has(\"ai\"), has(\"root_cause\"), has(\"recommended_action\")] | any" 'false'
  check_jq "sarif->alert: no ingest_error" "$out" "${src}.ingest_error" 'null'

  simulate sarif-to-vendetta-alert "$DOCS/finding-xss-medium.json" vendetta-alerts-000001
  out=$HTTP_BODY
  check_jq "xss->alert: rule.level (medium = 8)" "$out" "${src}.rule.level" '8'
  check_jq "xss->alert: severity medium" "$out" "${src}.severity" '"medium"'
  check_jq "xss->alert: location = code file:line" "$out" "${src}.location" '"frontend/src/app/search-result/search-result.component.ts:42"'
  check_jq "xss->alert: errow.owasp" "$out" "${src}.errow.owasp" '"A03:2021-Injection"'
  check_jq "xss->alert: errow.cvss" "$out" "${src}.errow.cvss" '5.4'
  check_jq "xss->alert: rule.groups carries the CWE" "$out" "${src}.rule.groups" '["errow","sarif","CWE-79"]'

  simulate sarif-to-vendetta-alert "$DOCS/finding-malformed.json" vendetta-alerts-000001
  out=$HTTP_BODY
  check_jq "malformed finding is tolerated (no ingest_error)" "$out" "${src}.ingest_error" 'null'
  check_jq "malformed finding: a bare-string message becomes rule.description" "$out" "${src}.rule.description" '"a bare string instead of the SARIF message object"'
  check_jq "malformed finding: id = doc_id, source normalised to an object" "$out" "${src} | [.id, .source.system]" '["d0a7c3e91b5f4826a0c8e2b4d6f81a3c5e7092b4d6f8a1c3e5079b2d4f6a8c01","errow"]'
  simulate sarif-to-vendetta-alert "$DOCS/finding-no-docid.json" vendetta-alerts-000001
  check_jq "no doc_id: id is a 64-hex SHA-256 fingerprint" "$HTTP_BODY" "${src}.id | test(\"^[0-9a-f]{64}\$\")" 'true'
  check_jq "no doc_id: _id equals id" "$HTTP_BODY" '.docs[0].doc._id == .docs[0].doc._source.id' 'true'
  local p body
  for p in errow-finding-enrichment sarif-to-vendetta-alert aiincident-to-vendetta-alert; do
    body="$(jq -n --slurpfile pl "${OS_DIR}/ingest-pipelines/${p}.json" --slurpfile d "$DOCS/finding-malformed.json" \
      '{pipeline: ($pl[0] | .processors = [{fail: {message: "injected failure"}}] + .processors), docs: [{_index: "x", _source: $d[0]}]}')"
    api POST /_ingest/pipeline/_simulate "$body"
    check_jq "${p}: on_failure keeps the document and records ingest_error" "$HTTP_BODY" \
      '.docs[0].doc._source | (.ingest_error | contains("injected failure")) and (.ruleId == "CWE-22")' 'true'
  done

  simulate aiincident-to-vendetta-alert "$DOCS/ai-inference-nemotron.json" vendetta-alerts-000001
  out=$HTTP_BODY
  check_jq "ai (nemotron, enrichment): id = alert_id" "$out" "${src}.id" '"1794474721.4872013"'
  check_jq "ai (nemotron): severity lower-case" "$out" "${src}.severity" '"high"'
  check_jq "ai (nemotron): rule.level 11" "$out" "${src}.rule.level" '11'
  check_jq "ai (nemotron): mitre.tactic[]" "$out" "${src}.mitre.tactic" '["Credential Access"]'
  check_jq "ai (nemotron): mitre.technique[]" "$out" "${src}.mitre.technique" '["T1110 Brute Force"]'
  check_jq "ai (nemotron): mitre.id[]" "$out" "${src}.mitre.id" '["T1110"]'
  check_jq "ai (nemotron): root_cause" "$out" "${src}.root_cause | startswith(\"Internet-exposed sshd\")" 'true'
  check_jq "ai (nemotron): recommended_action" "$out" "${src}.recommended_action | startswith(\"Block 203.0.113.50\")" 'true'
  check_jq "ai (nemotron): ai.engine" "$out" "${src}.ai.engine" '"nemotron-3-nano:30b"'
  check_jq "ai (nemotron): ai.role triage" "$out" "${src}.ai.role" '"triage"'
  check_jq "ai (nemotron): ai.confidence" "$out" "${src}.ai.confidence" '87'
  check_jq "ai (nemotron): ai.fallback false" "$out" "${src}.ai.fallback" 'false'
  check_jq "ai (nemotron): ai.verdict" "$out" "${src}.ai.verdict" '"escalate"'
  check_jq "ai (nemotron): ai.cost.gpu_seconds" "$out" "${src}.ai.cost.gpu_seconds" '6.42'
  check_jq "ai (nemotron): enrichment leaves @timestamp/source/description to the alert" "$out" "${src} | [has(\"@timestamp\"), has(\"source\"), (.rule | has(\"description\"))] | any" 'false'
  check_jq "ai (nemotron): analysis/chain fields dropped" "$out" "${src} | [has(\"analysis\"), has(\"hash\"), has(\"alert_id\")] | any" 'false'

  simulate aiincident-to-vendetta-alert "$DOCS/ai-inference-heuristic.json" vendetta-alerts-000001
  out=$HTTP_BODY
  check_jq "ai (heuristic, standalone): _id = request_id" "$out" '.docs[0].doc._id' '"a91d3e07-52c8-4b6f-8e14-0d7c2f9b6a35"'
  check_jq "ai (heuristic): ai.role heuristic" "$out" "${src}.ai.role" '"heuristic"'
  check_jq "ai (heuristic): ai.engine Cecur Heuristics" "$out" "${src}.ai.engine" '"Cecur Heuristics"'
  check_jq "ai (heuristic): ai.fallback true" "$out" "${src}.ai.fallback" 'true'
  check_jq "ai (heuristic): ai.fallback_reason" "$out" "${src}.ai.fallback_reason" '"backend_unavailable"'
  check_jq "ai (heuristic): severity medium / level 8" "$out" "${src} | [.severity, .rule.level]" '["medium",8]'
  check_jq "ai (heuristic): sub-technique id T1562.001" "$out" "${src}.mitre.id" '["T1562.001"]'
  check_jq "ai (heuristic): gpu_seconds 0" "$out" "${src}.ai.cost.gpu_seconds" '0'
  check_jq "ai (heuristic): standalone alert source" "$out" "${src}.source" '{"system":"cs3-ai","stream":"cs3.ai.inference"}'
  check_jq "ai (heuristic): standalone alert has @timestamp" "$out" "${src} | has(\"@timestamp\")" 'true'

  simulate aiincident-to-vendetta-alert "$DOCS/ai-incident-bare.json" vendetta-alerts-000001
  out=$HTTP_BODY
  check_jq "bare AIIncidentAnalysis: severity critical / level 14" "$out" "${src} | [.severity, .rule.level]" '["critical",14]'
  check_jq "bare AIIncidentAnalysis: ai.role forensic (gemma)" "$out" "${src}.ai.role" '"forensic"'
  check_jq "bare AIIncidentAnalysis: fractional confidence kept" "$out" "${src}.ai.confidence" '92.5'
  check_jq "bare AIIncidentAnalysis: mitre.id T1110.001" "$out" "${src}.mitre.id" '["T1110.001"]'
  check_jq "bare AIIncidentAnalysis: gpu seconds" "$out" "${src}.ai.cost.gpu_seconds" '11.8'

  simulate aiincident-to-vendetta-alert "$DOCS/ai-invalid-severity.json" vendetta-alerts-000001
  out=$HTTP_BODY
  check_jq "invalid severity: document kept with ingest_error" "$out" "${src}.ingest_error | contains(\"severityAssessment\")" 'true'

  simulate vendetta-alerts-router "$DOCS/finding-sqli-high.json" vendetta-alerts-000001
  check_jq "router: raw SARIF result becomes an alert" "$HTTP_BODY" "${src} | [.rule.level, .source.system, has(\"ruleId\")]" '[11,"errow",false]'
  simulate vendetta-alerts-router "$DOCS/ai-inference-nemotron.json" vendetta-alerts-000001
  check_jq "router: cs3.ai.inference becomes an AI enrichment" "$HTTP_BODY" "${src} | [.ai.role, .rule.level, has(\"analysis\")]" '["triage",11,false]'
  simulate vendetta-alerts-router "$DOCS/ai-incident-bare.json" vendetta-alerts-000001
  check_jq "router: bare AIIncidentAnalysis becomes an alert" "$HTTP_BODY" "${src} | [.severity, .ai.role]" '["critical","forensic"]'
  jq '.["vendetta-alerts"]' "$DOCS/family-docs.json" >"$WORK/native.json"
  simulate vendetta-alerts-router "$WORK/native.json" vendetta-alerts-000001
  check "router: a native Vendetta alert passes through unchanged" "$(jq -cS "$src" <<<"$HTTP_BODY")" "$(jq -cS . "$WORK/native.json")"
}

index_doc() { # description index id file [pipeline]
  local path="/$2/_doc/$3?refresh=true"
  if [[ -n "${5-}" ]]; then path+="&pipeline=$5"; fi
  api PUT "$path" "$(jq -c . "$4")"
  if [[ "$HTTP_CODE" == 2?? && "$(jq -r '.result' <<<"$HTTP_BODY")" == created ]]; then ok "$1"; else bad "$1" "HTTP ${HTTP_CODE}: ${HTTP_BODY:0:600}"; fi
}

test_indexing() {
  say "mapping acceptance: index realistic documents into every family"
  local fam tmp="$WORK/fam.json" cfg_finding_id cfg_run_id
  cfg_finding_id="$(jq -r .doc_id "$DOCS/cfgaudit-finding.json")"
  cfg_run_id="$(jq -r .doc_id "$DOCS/cfgaudit-run.json")"
  index_doc "cfgaudit-findings accepts the dedicated finding contract" cfgaudit-findings-2026.11.12 "$cfg_finding_id" "$DOCS/cfgaudit-finding.json"
  index_doc "cfgaudit-runs accepts the dedicated run contract" cfgaudit-runs-2026.11.12 "$cfg_run_id" "$DOCS/cfgaudit-run.json"
  index_doc "errow-findings accepts the SARIF finding via errow-finding-enrichment" errow-findings-2026.11.12 sqli "$DOCS/finding-sqli-high.json" errow-finding-enrichment
  index_doc "errow-findings accepts the XSS finding" errow-findings-2026.11.12 xss "$DOCS/finding-xss-medium.json" errow-finding-enrichment
  index_doc "errow-sarif accepts the raw SARIF finding" errow-sarif-2026.11.12 sqli "$DOCS/finding-sqli-high.json"
  index_doc "cs3-ai-inference accepts the inference event" cs3-ai-inference-2026.11.12 inf0 "$DOCS/ai-inference-nemotron.json"
  index_doc "cs3-ai-audit accepts the nemotron inference event" cs3-ai-audit-2026.11.12 chain-41 "$DOCS/ai-inference-nemotron.json"
  for fam in errow-runs errow-transcripts errow-threat-models errow-llm-logs errow-mcp errow-report-artifacts errow-runtime cs3-ai-inference cs3-ai-audit vendetta-alerts; do
    jq --arg f "$fam" '.[$f]' "$DOCS/family-docs.json" >"$tmp"
    index_doc "${fam}-2026.11.12 accepts its record shape" "${fam}-2026.11.12" fam1 "$tmp"
  done
  api GET '/cfgaudit-findings-2026.11.12/_mapping'
  check_jq "Cfgaudit finding mapping: dynamic:false, nested frameworks and keyword hashes" "$HTTP_BODY" \
    '.["cfgaudit-findings-2026.11.12"].mappings | [.dynamic, .properties.control.properties.frameworks.type, .properties.evidence.properties.sha256.type]' \
    '["false","nested","keyword"]'
  api GET '/cfgaudit-runs-2026.11.12/_mapping'
  check_jq "Cfgaudit run mapping: dynamic:false and date run timestamps" "$HTTP_BODY" \
    '.["cfgaudit-runs-2026.11.12"].mappings | [.dynamic, .properties.run.properties.completed_at.type, .properties.summary.properties.findings_total.type]' \
    '["false","date","integer"]'
  api GET "/cfgaudit-findings-2026.11.12/_search?q=finding.id:${cfg_finding_id}"
  check_jq "Cfgaudit deterministic finding id is searchable" "$HTTP_BODY" '[.hits.total.value, .hits.hits[0]._id]' "[1,\"${cfg_finding_id}\"]"
  api GET '/errow-findings-2026.11.12/_mapping'
  check_jq "findings mapping: properties.security-severity is float" "$HTTP_BODY" '.["errow-findings-2026.11.12"].mappings.properties.properties.properties["security-severity"].type' '"float"'
  api GET '/errow-findings-2026.11.12/_search?size=0&q=owasp:%22A03:2021-Injection%22'
  check_jq "findings: enrichment fields searchable (owasp)" "$HTTP_BODY" '.hits.total.value' '2'
  api GET '/cs3-ai-audit-2026.11.12/_mapping'
  check_jq "audit mapping: hash is keyword" "$HTTP_BODY" '.["cs3-ai-audit-2026.11.12"].mappings.properties.hash.type' '"keyword"'
  check_jq "audit mapping: dynamic=false (no field explosion)" "$HTTP_BODY" '.["cs3-ai-audit-2026.11.12"].mappings.dynamic' '"false"'
  api GET '/cs3-ai-audit-2026.11.12/_settings'
  check_jq "audit index is NOT write-blocked by the template" "$HTTP_BODY" '.["cs3-ai-audit-2026.11.12"].settings.index.blocks.write // "none"' '"none"'
  api GET '/vendetta-alerts-2026.11.12/_mapping'
  check_jq "alerts mapping: rule.level is integer" "$HTTP_BODY" '.["vendetta-alerts-2026.11.12"].mappings.properties.rule.properties.level.type' '"integer"'
  check_jq "alerts mapping: errow.cvss is float" "$HTTP_BODY" '.["vendetta-alerts-2026.11.12"].mappings.properties.errow.properties.cvss.type' '"float"'
  check_jq "alerts mapping: ai.confidence is float" "$HTTP_BODY" '.["vendetta-alerts-2026.11.12"].mappings.properties.ai.properties.confidence.type' '"float"'
}

bulk_upsert() { # description id file (the transform comes from the index default pipeline)
  local line body
  line="$(jq -nc --arg id "$2" '{update:{_index:"vendetta-alerts",_id:$id}}')"
  body="$(jq -c '{doc:., doc_as_upsert:true}' "$3")"
  api POST "/_bulk?refresh=true" "$(printf '%s\n%s\n' "$line" "$body")"
  if [[ "$HTTP_CODE" == 200 && "$(jq -r '.errors' <<<"$HTTP_BODY")" == false ]]; then ok "$1"; else bad "$1" "HTTP ${HTTP_CODE}: ${HTTP_BODY:0:900}"; fi
}

test_upserts() {
  say "vendetta-alerts upsert by id (write alias, default router pipeline on update+doc_as_upsert)"
  local sqli_id=7c1f0e5b3a94d2886e0b5f1c9a4d7e3320b8c6a15f94e7d2b3a0c8e1f6d95a42 native=1794474721.4872013 doc
  bulk_upsert "finding upsert #1 (update+doc_as_upsert, router -> sarif-to-vendetta-alert)" "$sqli_id" "$DOCS/finding-sqli-high.json"
  bulk_upsert "finding upsert #2 (same id)" "$sqli_id" "$DOCS/finding-sqli-high.json"
  api GET "/vendetta-alerts/_search?q=id:${sqli_id}&size=5"
  check_jq "exactly one alert for the finding after two upserts" "$HTTP_BODY" '.hits.total.value' '1'
  check_jq "alert is stored in the write index vendetta-alerts-000001" "$HTTP_BODY" '.hits.hits[0]._index' '"vendetta-alerts-000001"'
  doc="$(jq -c '.hits.hits[0]._source' <<<"$HTTP_BODY")"
  check_jq "stored alert: rule.level 11, severity high" "$doc" '[.rule.level, .severity]' '[11,"high"]'
  check_jq "stored alert: source.system errow" "$doc" '.source.system' '"errow"'

  jq '.["vendetta-alerts"]' "$DOCS/family-docs.json" >"$WORK/native.json"
  api PUT "/vendetta-alerts/_doc/${native}?refresh=true" "$(jq -c . "$WORK/native.json")"
  check "native Vendetta alert written through the alias" "$(jq -r '.result' <<<"$HTTP_BODY")" "created"
  bulk_upsert "AI enrichment upsert (alert_id; router -> aiincident-to-vendetta-alert)" "$native" "$DOCS/ai-inference-nemotron.json"
  api GET "/vendetta-alerts/_doc/${native}"
  doc="$(jq -c '._source' <<<"$HTTP_BODY")"
  check_jq "merged alert keeps the original rule.description" "$doc" '.rule.description | startswith("sshd")' 'true'
  check_jq "merged alert keeps the original @timestamp" "$doc" '.["@timestamp"] | type' '"string"'
  check_jq "merged alert gains the AI fields" "$doc" '[.ai.engine, .ai.role, .ai.confidence, .root_cause != null, .recommended_action != null]' '["nemotron-3-nano:30b","triage",87,true,true]'
  check_jq "merged alert: severity/level from the AI verdict" "$doc" '[.severity, .rule.level]' '["high",11]'
  check_jq "merged alert: mitre replaced by the AI mapping" "$doc" '.mitre.technique' '["T1110 Brute Force"]'
  api GET "/vendetta-alerts/_count?q=id:${native}"
  check_jq "merged alert is still a single document" "$HTTP_BODY" '.count' '1'

  api POST "/vendetta-alerts/_doc?pipeline=aiincident-to-vendetta-alert&refresh=true" "$(jq -c . "$DOCS/ai-inference-heuristic.json")"
  check "standalone heuristic alert gets _id = request_id" "$(jq -r '._id' <<<"$HTTP_BODY")" "a91d3e07-52c8-4b6f-8e14-0d7c2f9b6a35"
  api GET '/vendetta-alerts/_search?q=ai.role:heuristic'
  check_jq "heuristic alert searchable by ai.role and carries ai.fallback" "$HTTP_BODY" '[.hits.total.value, .hits.hits[0]._source.ai.fallback]' '[1,true]'

  api POST '/vendetta-alerts/_doc?pipeline=sarif-to-vendetta-alert' "$(jq -c . "$DOCS/finding-malformed.json")"
  if [[ "$HTTP_CODE" == 2?? ]]; then ok "malformed finding is still indexed (ingest_error recorded, nothing dropped)"; else bad "malformed finding rejected" "HTTP ${HTTP_CODE}: ${HTTP_BODY:0:400}"; fi
}

test_ism() {
  say "ISM auto-attach (ism_template) on freshly created indices"
  local idx pol got entry
  local -a want=(
    "cfgaudit-findings-2026.11.12|cfgaudit-findings-retention"
    "cfgaudit-runs-2026.11.12|cfgaudit-runs-retention"
    "vendetta-alerts-000001|rollover-40gb"
    "vendetta-alerts-2026.11.12|hot-warm-cold"
    "errow-findings-2026.11.12|errow-findings-retention"
    "errow-sarif-2026.11.12|errow-findings-retention"
    "errow-runs-2026.11.12|hot-warm-cold"
    "errow-mcp-2026.11.12|hot-warm-cold"
    "cs3-ai-inference-2026.11.12|hot-warm-cold"
    "cs3-ai-audit-2026.11.12|cs3-ai-audit-retention"
  )
  for entry in "${want[@]}"; do
    idx=${entry%%|*}
    pol=${entry##*|}
    got=""
    for _ in $(seq 1 30); do
      api GET "/_plugins/_ism/explain/${idx}"
      got="$(jq -r --arg i "$idx" '.[$i]["index.plugins.index_state_management.policy_id"] // .[$i]["index.opendistro.index_state_management.policy_id"] // ""' <<<"$HTTP_BODY" 2>/dev/null || true)"
      if [[ -n "$got" ]]; then break; fi
      sleep 2
    done
    check "${idx} -> policy ${pol}" "$got" "$pol"
  done
  api GET /_plugins/_ism/policies/cs3-ai-audit-retention
  check_jq "audit policy: snapshot action present" "$HTTP_BODY" '[.policy.states[] | select(.actions | map(keys[]) | index("snapshot"))] | length >= 1' 'true'
  check_jq "audit policy: a transition fires at min_index_age 1d" "$HTTP_BODY" '[.policy.states[].transitions[]? | select(.conditions.min_index_age == "1d")] | length >= 1' 'true'
}

run_import() { # container-name args... ; runs import.sh in the OpenSearch image, prints its output, returns its exit code
  local name=$1 rc
  shift
  docker run -d --name "$name" --network "$NET" \
    -v "$OS_DIR:/opensearch:ro" \
    -v "$WORK/secrets/opensearch_admin_password:/run/secrets/opensearch_admin_password:ro" \
    --entrypoint /opensearch/dashboards/import.sh "$OS_IMAGE" "$@" >/dev/null
  while node_alive "$name"; do sleep 1; done
  docker logs "$name" 2>&1
  rc="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
  docker rm -f "$name" >/dev/null
  return "$rc"
}

# Exercises import.sh against a stand-in for the Dashboards saved-objects API
# (xsrf header + basic auth enforced) so the HTTP flow is covered without the
# ~1 GB Dashboards image; --with-dashboards repeats it against the real one.
test_import_mock() {
  say "dashboards/import.sh against a mock saved-objects API"
  local mock="${RUN_ID}-mock" out rc
  NODES+=("$mock")
  MOCK_USER_PASS="admin:${PW}" docker run -d --name "$mock" --network "$NET" --network-alias mock-dashboards \
    -e MOCK_USER_PASS -v "$SCRIPT_DIR:/mock:ro" --entrypoint python3 "$OS_IMAGE" /mock/mock_dashboards.py >/dev/null
  sleep 2
  if ! node_alive "$mock"; then
    dump_logs
    bad "mock dashboards API did not start"
    return 0
  fi
  rc=0
  out="$(run_import "${RUN_ID}-imp1" --url http://mock-dashboards:5601 --wait-timeout 30)" || rc=$?
  check "import.sh exits 0" "$rc" "0"
  check_contains "imported 47 saved objects" "$out" "imported 47 saved objects"
  check_contains "verified 20 index patterns and 3 dashboards" "$out" "verified: 20 index patterns, 3 dashboards"
  rc=0
  out="$(run_import "${RUN_ID}-imp2" --url http://mock-dashboards:5601 --wait-timeout 30)" || rc=$?
  check "import.sh is idempotent (second run exits 0)" "$rc" "0"
  rc=0
  out="$(run_import "${RUN_ID}-imp3" --url http://mock-dashboards:5601 --wait-timeout 30 --file /opensearch/dashboards/opensearch_dashboards.yml)" || rc=$?
  check "import.sh rejects a non-NDJSON file (exit 4)" "$rc" "4"
  docker rm -f "$mock" >/dev/null
}

test_dashboards() {
  say "Dashboards: keystore wrapper, saved objects import"
  local osd="${RUN_ID}-osd" imp="${RUN_ID}-import" code="" out rc
  NODES+=("$osd")
  docker run -d --name "$osd" --network "$NET" --network-alias opensearch-dashboards -p "127.0.0.1:$((PORT + 1)):5601" \
    -v "$OS_DIR:/opensearch:ro" \
    -v "$WORK/pki/ca.crt:/pki/ca.crt:ro" \
    -v "$WORK/secrets/opensearch_admin_password:/run/secrets/opensearch_admin_password:ro" \
    --entrypoint /opensearch/dashboards/entrypoint.sh "$OSD_IMAGE" >/dev/null
  for _ in $(seq 1 90); do
    if ! node_alive "$osd"; then
      dump_logs
      bad "dashboards container died"
      return 0
    fi
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -K <(cfg_line) "http://127.0.0.1:$((PORT + 1))/api/status" 2>/dev/null || true)"
    if [[ "$code" == 200 ]]; then break; fi
    sleep 3
  done
  check "dashboards /api/status is up" "$code" "200"
  rc=0
  out="$(run_import "$imp" --url http://opensearch-dashboards:5601)" || rc=$?
  check "import.sh exits 0 against real Dashboards" "$rc" "0"
  check_contains "import.sh verified the saved objects" "$out" "verified"
}

# The 3-node file needs three nodes to elect a cluster manager, so only the
# configuration itself is validated: a node must parse every setting and start.
test_prod_config() {
  say "3-node opensearch.yml: every setting parses and the node starts (no quorum expected)"
  local n="${RUN_ID}-prod" log="" state
  docker rm -f -v "$NODE" >/dev/null
  NODES=("$n")
  docker run -d --name "$n" --network "$NET" --network-alias opensearch-0 \
    --ulimit nofile=65536:65536 --ulimit memlock=-1:-1 \
    -e OPENSEARCH_JAVA_OPTS='-Xms384m -Xmx384m' \
    -e cluster.routing.allocation.disk.threshold_enabled=false \
    -e node.store.allow_mmap=false \
    -e NODE_NAME=opensearch-0 -e NODE_BOX_TYPE=warm \
    -v "$OS_DIR:/opensearch:ro" \
    -v "${OS_DIR}/opensearch.yml:/usr/share/opensearch/config/opensearch.yml:ro" \
    -v "$WORK/pki:/usr/share/opensearch/config/certs:ro" \
    -v "$WORK/secrets/opensearch_admin_password:/run/secrets/opensearch_admin_password:ro" \
    --entrypoint /opensearch/entrypoint.sh "$OS_IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    log="$(docker logs "$n" 2>&1 || true)"
    if ! node_alive "$n" || [[ "$log" == *"] started"* ]]; then break; fi
    sleep 3
  done
  state=down
  if node_alive "$n"; then state=up; fi
  check "node with opensearch.yml is running" "$state" "up"
  check_contains "node started" "$log" "] started"
  check_contains "node has the cluster_manager, data and ingest roles" "$log" "cluster_manager"
  if [[ "$log" == *"unknown setting"* || "$log" == *"IllegalArgumentException"* || "$log" == *"bootstrap checks failed"* ]]; then
    bad "opensearch.yml was rejected" "$(grep -m3 -E 'unknown setting|IllegalArgumentException|bootstrap checks failed' <<<"$log" | cut -c1-300)"
  else
    ok "no rejected settings in the start-up log"
  fi
}

# ---------------------------------------------------------------------- main
main() {
  need docker
  need openssl
  need curl
  need jq
  need python3
  WORK="$(mktemp -d "${SCRIPT_DIR}/.work.XXXXXX")"
  lint
  test_offline
  make_pki
  test_node_start
  test_apply
  test_security
  test_template_composition
  test_pipelines
  test_indexing
  test_upserts
  test_ism
  test_import_mock
  if [[ "$WITH_DASHBOARDS" == true ]]; then test_dashboards; fi
  test_prod_config
  say "result: ${PASSED} passed, ${FAILED} failed"
  if ((FAILED != 0)); then exit 1; fi
}

main
