#!/usr/bin/env bash
# vendetta-stack OpenSearch bootstrap (idempotent). Loads, in this order:
#   cluster settings -> ingest pipelines -> index templates -> ISM policies
#   -> snapshot repository -> vendetta-alerts-000001 + write alias -> default
#   pipeline on every vendetta-alerts-* index -> verify.
# Needs: bash >= 4, curl, python3 (stdlib only; all present in the pinned
# OpenSearch image, so the compose `opensearch-init` job can run it in-image).
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly HELPER="${SCRIPT_DIR}/apply-helper.py"
readonly ALIAS_NAME="vendetta-alerts"
readonly FIRST_INDEX="vendetta-alerts-000001"
readonly REPO_NAME="vendetta-snapshots"
readonly ROUTER_PIPELINE="vendetta-alerts-router"

EX_FAIL=1 EX_USAGE=2 EX_NOT_READY=3 EX_AUTH=4
readonly EX_FAIL EX_USAGE EX_NOT_READY EX_AUTH

OS_URL="${OPENSEARCH_URL:-https://opensearch:9200}"
OS_URL="${OS_URL%/}"
OS_USER="${OPENSEARCH_USER:-admin}"
PASSWORD_FILE="${OPENSEARCH_PASSWORD_FILE:-/run/secrets/opensearch_admin_password}"
CA_FILE="${OPENSEARCH_CA:-/pki/ca.crt}"
EXPECTED_NODES="${OPENSEARCH_EXPECTED_NODES:-}"
WAIT_TIMEOUT="${OPENSEARCH_WAIT_TIMEOUT:-300}"
REPLICAS="${OPENSEARCH_APPLY_REPLICAS:-auto}"
HTTP_TIMEOUT=60
DRY_RUN=false
FORCE=false
INSECURE=false

PASSWORD=""
DATA_NODES=1
HTTP_CODE=""
HTTP_BODY=""
CURL_RC=0
CREATED=0
UPDATED=0
UNCHANGED=0
declare -A WANT=()
declare -a PIPELINE_FILES=() TEMPLATE_FILES=() POLICY_FILES=()
SNAPSHOT_PATH=""

usage() {
  cat <<'EOF'
Usage: apply.sh [options]

Idempotently applies the vendetta-stack OpenSearch objects: persistent cluster
settings, ingest pipelines, composable index templates, ISM policies, the
`vendetta-snapshots` fs repository (only when path.repo is configured) and the
bootstrap index vendetta-alerts-000001 behind the write alias vendetta-alerts
(existing vendetta-alerts-* indices also get index.default_pipeline=
vendetta-alerts-router, which the templates only apply to new indices).
Every object carries a content hash; unchanged objects are skipped. Finally
each object is read back (GET) and verified.

Options:
  --dry-run              validate the local files and print the plan; no
                         network access, no credentials needed
  --force                rewrite every object even when its hash is unchanged
  --wait-timeout SECS    cluster readiness budget with exponential backoff
                         (default 300, env OPENSEARCH_WAIT_TIMEOUT)
  --replicas auto|keep|N auto (default): 0 replicas when the cluster has a
                         single data node, files as written otherwise; keep:
                         files as written; N: cap/set replicas to N
  --insecure-for-bootstrap  skip TLS verification; refused unless
                         OPENSEARCH_ALLOW_INSECURE_BOOTSTRAP=true
  -h, --help             show this help

Environment:
  OPENSEARCH_URL            default https://opensearch:9200 (https only)
  OPENSEARCH_USER           default admin
  OPENSEARCH_PASSWORD_FILE  default /run/secrets/opensearch_admin_password
  OPENSEARCH_CA             default /pki/ca.crt
  OPENSEARCH_EXPECTED_NODES wait until at least this many nodes joined
  OPENSEARCH_WAIT_TIMEOUT   same as --wait-timeout
  OPENSEARCH_APPLY_REPLICAS same as --replicas

Exit codes:
  0  everything applied and verified (or --dry-run files are valid)
  1  an apply/verify step failed, or a local file is invalid
  2  usage error
  3  cluster not ready within the wait timeout
  4  authentication, TLS or credential-file problem
EOF
}

log() { printf 'apply.sh: %s\n' "$*"; }
warn() { printf 'apply.sh: WARNING: %s\n' "$*" >&2; }
die() {
  local code=$1
  shift
  printf 'apply.sh: ERROR: %s\n' "$*" >&2
  exit "$code"
}
on_err() { printf 'apply.sh: ERROR: unexpected failure (exit %s) at line %s\n' "$1" "$2" >&2; exit "$EX_FAIL"; }
trap 'on_err $? $LINENO' ERR

helper() { python3 "$HELPER" "$@"; }

parse_args() {
  while (($#)); do
    case "$1" in
      --dry-run) DRY_RUN=true ;;
      --force) FORCE=true ;;
      --wait-timeout)
        [[ $# -ge 2 ]] || die "$EX_USAGE" "--wait-timeout needs a value"
        WAIT_TIMEOUT=$2
        shift
        ;;
      --replicas)
        [[ $# -ge 2 ]] || die "$EX_USAGE" "--replicas needs a value"
        REPLICAS=$2
        shift
        ;;
      --insecure-for-bootstrap) INSECURE=true ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage >&2
        die "$EX_USAGE" "unknown option: $1"
        ;;
    esac
    shift
  done
  [[ "$WAIT_TIMEOUT" =~ ^[0-9]+$ ]] || die "$EX_USAGE" "--wait-timeout must be a number of seconds"
  [[ "$REPLICAS" =~ ^(auto|keep|[0-9]+)$ ]] || die "$EX_USAGE" "--replicas must be auto, keep or a number"
  if [[ "$INSECURE" == true && "${OPENSEARCH_ALLOW_INSECURE_BOOTSTRAP:-}" != true ]]; then
    die "$EX_USAGE" "--insecure-for-bootstrap is refused unless OPENSEARCH_ALLOW_INSECURE_BOOTSTRAP=true"
  fi
}

collect_files() {
  local f
  PIPELINE_FILES=("${SCRIPT_DIR}/ingest-pipelines/errow-finding-enrichment.json")
  for f in "${SCRIPT_DIR}"/ingest-pipelines/*.json; do
    [[ "$f" == */errow-finding-enrichment.json ]] || PIPELINE_FILES+=("$f")
  done
  TEMPLATE_FILES=("${SCRIPT_DIR}"/index-templates/*.json)
  POLICY_FILES=("${SCRIPT_DIR}"/ism-policies/*.json)
  for f in "${PIPELINE_FILES[@]}" "${TEMPLATE_FILES[@]}" "${POLICY_FILES[@]}" "${SCRIPT_DIR}/cluster-settings.json"; do
    [[ -f "$f" ]] || die "$EX_FAIL" "missing input file: $f"
  done
}

object_name() {
  local name
  name="$(basename "$1" .json)"
  printf '%s' "${name%-template}"
}

dry_run() {
  local f info
  log "dry-run: validating local files, no cluster contact"
  helper get persistent <"${SCRIPT_DIR}/cluster-settings.json" >/dev/null || die "$EX_FAIL" "cluster-settings.json is not valid JSON"
  log "plan: PUT _cluster/settings (persistent) from cluster-settings.json"
  for f in "${PIPELINE_FILES[@]}"; do
    info="$(helper validate pipeline "$f")" || die "$EX_FAIL" "invalid pipeline $f"
    log "plan: PUT _ingest/pipeline/$(object_name "$f")  [${info}]"
  done
  for f in "${TEMPLATE_FILES[@]}"; do
    info="$(helper validate template "$f")" || die "$EX_FAIL" "invalid template $f"
    log "plan: PUT _index_template/$(object_name "$f")  [${info}]"
  done
  for f in "${POLICY_FILES[@]}"; do
    info="$(helper validate ism "$f")" || die "$EX_FAIL" "invalid ISM policy $f"
    log "plan: PUT _plugins/_ism/policies/$(object_name "$f")  [${info}]"
  done
  log "plan: PUT _snapshot/${REPO_NAME} (fs, <path.repo>/${REPO_NAME}) when path.repo is configured"
  log "plan: PUT ${FIRST_INDEX} with write alias ${ALIAS_NAME} when the alias is absent"
  log "plan: verify every object with GET (replicas: ${REPLICAS})"
  log "dry-run OK"
}

load_credentials() {
  [[ "$OS_URL" == https://* ]] || die "$EX_AUTH" "OPENSEARCH_URL must be https:// (credentials are never sent in clear text)"
  [[ -r "$PASSWORD_FILE" ]] || die "$EX_AUTH" "password file not readable: ${PASSWORD_FILE}"
  PASSWORD="$(tr -d '\r\n' <"$PASSWORD_FILE")"
  [[ -n "$PASSWORD" ]] || die "$EX_AUTH" "password file is empty: ${PASSWORD_FILE}"
  if [[ "$INSECURE" == true ]]; then
    warn "TLS verification disabled for bootstrap"
  else
    [[ -r "$CA_FILE" ]] || die "$EX_AUTH" "CA file not readable: ${CA_FILE}"
  fi
}

auth_config() {
  local user=${OS_USER//\\/\\\\} pw=${PASSWORD//\\/\\\\}
  user=${user//\"/\\\"}
  pw=${pw//\"/\\\"}
  printf 'user = "%s:%s"\n' "$user" "$pw"
}

# Single HTTP call. Sets HTTP_CODE (000 on transport failure), HTTP_BODY, CURL_RC.
os_once() {
  local method=$1 path=$2 data=${3-} out rc=0
  local -a tls=(--cacert "$CA_FILE") extra=()
  [[ "$INSECURE" == true ]] && tls=(--insecure)
  [[ -n "$data" ]] && extra=(--data-binary @-)
  out="$(printf '%s' "$data" | curl --silent --show-error --max-time "$HTTP_TIMEOUT" "${tls[@]}" \
    -K <(auth_config) -X "$method" -H 'Content-Type: application/json' "${extra[@]}" \
    -w $'\n%{http_code}' "${OS_URL}${path}" 2>&1)" || rc=$?
  CURL_RC=$rc
  if ((rc != 0)); then
    HTTP_CODE=000
    HTTP_BODY=$out
    return 0
  fi
  HTTP_CODE=${out##*$'\n'}
  HTTP_BODY=${out%$'\n'*}
}

# HTTP call with bounded retries on transient transport/server errors.
os_call() {
  local attempt=0 delay=1
  while :; do
    os_once "$@"
    case "$HTTP_CODE" in
      429 | 502 | 503 | 504) ;;
      000)
        case "$CURL_RC" in
          58 | 60 | 77) die "$EX_AUTH" "TLS verification failed against ${OS_URL} with CA ${CA_FILE}: ${HTTP_BODY}" ;;
          *) ;;
        esac
        ;;
      *) return 0 ;;
    esac
    attempt=$((attempt + 1))
    if ((attempt >= 6)); then return 0; fi
    sleep "$delay"
    delay=$((delay * 2))
  done
}

require_2xx() {
  case "$HTTP_CODE" in
    2??) return 0 ;;
    401 | 403) die "$EX_AUTH" "$1: HTTP ${HTTP_CODE} - credentials rejected or role lacks permission: ${HTTP_BODY:0:400}" ;;
    *) die "$EX_FAIL" "$1: HTTP ${HTTP_CODE}: ${HTTP_BODY:0:800}" ;;
  esac
}

wait_ready() {
  local deadline=$((SECONDS + WAIT_TIMEOUT)) delay=2 auth_failures=0 status="" query
  query='/_cluster/health?wait_for_status=yellow&timeout=5s'
  [[ -n "$EXPECTED_NODES" ]] && query+="&wait_for_nodes=ge(${EXPECTED_NODES})"
  log "waiting for ${OS_URL} (timeout ${WAIT_TIMEOUT}s)"
  while :; do
    os_once GET "$query"
    case "$HTTP_CODE" in
      200)
        status="$(helper get status <<<"$HTTP_BODY")"
        if [[ "$status" == green || "$status" == yellow ]]; then
          DATA_NODES="$(helper get number_of_data_nodes <<<"$HTTP_BODY")"
          log "cluster ${status}, ${DATA_NODES} data node(s)"
          return 0
        fi
        ;;
      401 | 403)
        auth_failures=$((auth_failures + 1))
        ((auth_failures >= 3)) && die "$EX_AUTH" "credentials rejected by ${OS_URL} (HTTP ${HTTP_CODE})"
        ;;
      000)
        case "$CURL_RC" in
          58 | 60 | 77) die "$EX_AUTH" "TLS verification failed against ${OS_URL} with CA ${CA_FILE}: ${HTTP_BODY}" ;;
          *) ;;
        esac
        ;;
      *) ;;
    esac
    if ((SECONDS >= deadline)); then
      die "$EX_NOT_READY" "cluster not ready after ${WAIT_TIMEOUT}s (last: HTTP ${HTTP_CODE}, status '${status}')"
    fi
    log "not ready yet (HTTP ${HTTP_CODE}); retry in ${delay}s"
    sleep "$delay"
    delay=$((delay * 2 > 15 ? 15 : delay * 2))
  done
}

resolve_replicas() {
  if [[ "$REPLICAS" == auto ]]; then
    if [[ "${DATA_NODES:-1}" == 1 ]]; then REPLICAS=0; else REPLICAS=keep; fi
  fi
  log "replicas policy: ${REPLICAS}"
}

note() { # created|updated|unchanged kind name
  case "$1" in
    created) CREATED=$((CREATED + 1)) ;;
    updated) UPDATED=$((UPDATED + 1)) ;;
    *) UNCHANGED=$((UNCHANGED + 1)) ;;
  esac
  log "$1 $2 $3"
}

apply_cluster_settings() {
  local body
  os_call GET '/_cluster/settings?flat_settings=true'
  require_2xx "GET _cluster/settings"
  if helper settings-match "${SCRIPT_DIR}/cluster-settings.json" <<<"$HTTP_BODY" && [[ "$FORCE" != true ]]; then
    note unchanged settings cluster
    return 0
  fi
  body="$(helper get '' <"${SCRIPT_DIR}/cluster-settings.json")"
  os_call PUT /_cluster/settings "$body"
  require_2xx "PUT _cluster/settings"
  note updated settings cluster
}

# Create-or-update for objects whose PUT is itself idempotent (templates, pipelines).
apply_put_object() { # kind name path
  local kind=$1 name=$2 path=$3 file body want have action=created
  file=$4
  body="$(helper body "$kind" "$file" "$REPLICAS")"
  want="$(helper marker "$kind" <<<"$body")"
  WANT["${kind}:${name}"]=$want
  os_call GET "$path"
  case "$HTTP_CODE" in
    200)
      have="$(helper marker "$kind" <<<"$HTTP_BODY")"
      if [[ "$have" == "$want" && "$FORCE" != true ]]; then
        note unchanged "$kind" "$name"
        return 0
      fi
      action=updated
      ;;
    404) ;;
    *) require_2xx "GET ${path}" ;;
  esac
  os_call PUT "$path" "$body"
  require_2xx "PUT ${path}"
  note "$action" "$kind" "$name"
}

apply_ism_policy() {
  local file=$1 name body want have seq term action=created attempt
  name="$(object_name "$file")"
  body="$(helper body ism "$file" "$REPLICAS")"
  want="$(helper marker ism <<<"$body")"
  WANT["ism:${name}"]=$want
  for attempt in 1 2 3 4 5; do
    os_call GET "/_plugins/_ism/policies/${name}"
    case "$HTTP_CODE" in
      200)
        have="$(helper marker ism <<<"$HTTP_BODY")"
        if [[ "$have" == "$want" && "$FORCE" != true ]]; then
          note unchanged ism "$name"
          return 0
        fi
        seq="$(helper get _seq_no <<<"$HTTP_BODY")"
        term="$(helper get _primary_term <<<"$HTTP_BODY")"
        os_call PUT "/_plugins/_ism/policies/${name}?if_seq_no=${seq}&if_primary_term=${term}" "$body"
        action=updated
        ;;
      404) os_call PUT "/_plugins/_ism/policies/${name}" "$body" ;;
      *) require_2xx "GET ism policy ${name}" ;;
    esac
    if [[ "$HTTP_CODE" == 409 ]]; then
      log "ISM policy ${name}: concurrent change (attempt ${attempt}), retrying"
      sleep "$attempt"
      continue
    fi
    require_2xx "PUT ism policy ${name}"
    note "$action" ism "$name"
    return 0
  done
  die "$EX_FAIL" "ISM policy ${name}: still conflicting after 5 attempts"
}

apply_snapshot_repo() {
  local location want_loc have_loc body
  os_call GET '/_nodes/settings?filter_path=nodes.*.settings.path.repo'
  require_2xx "GET _nodes/settings"
  SNAPSHOT_PATH="$(helper repo-path <<<"$HTTP_BODY")"
  if [[ -z "$SNAPSHOT_PATH" ]]; then
    warn "path.repo is not configured: snapshot repository ${REPO_NAME} skipped (ISM snapshot actions will retry until it exists)"
    return 0
  fi
  location="${SNAPSHOT_PATH%/}/${REPO_NAME}"
  want_loc=$location
  os_call GET "/_snapshot/${REPO_NAME}"
  case "$HTTP_CODE" in
    200)
      have_loc="$(helper get "${REPO_NAME}/settings/location" <<<"$HTTP_BODY")"
      if [[ "$have_loc" == "$want_loc" && "$FORCE" != true ]]; then
        note unchanged repository "$REPO_NAME"
        return 0
      fi
      ;;
    404) ;;
    *) require_2xx "GET _snapshot/${REPO_NAME}" ;;
  esac
  body="$(helper repo-body "$location")"
  os_call PUT "/_snapshot/${REPO_NAME}" "$body"
  require_2xx "PUT _snapshot/${REPO_NAME} (every node needs the shared path.repo volume)"
  note created repository "$REPO_NAME"
}

bootstrap_alias() {
  os_call GET "/_alias/${ALIAS_NAME}"
  case "$HTTP_CODE" in
    200)
      if [[ "$(helper write-indices <<<"$HTTP_BODY")" != 1 ]]; then
        die "$EX_FAIL" "alias ${ALIAS_NAME} exists but has no single write index: fix with POST _aliases"
      fi
      note unchanged alias "$ALIAS_NAME"
      return 0
      ;;
    404) ;;
    *) require_2xx "GET _alias/${ALIAS_NAME}" ;;
  esac
  os_call GET "/${ALIAS_NAME}/_settings?filter_path=*.settings.index.uuid"
  if [[ "$HTTP_CODE" == 200 ]]; then
    die "$EX_FAIL" "a concrete index named ${ALIAS_NAME} exists; the rollover write alias cannot be created (reindex and delete it)"
  fi
  os_call GET "/${FIRST_INDEX}/_settings?filter_path=*.settings.index.uuid"
  if [[ "$HTTP_CODE" == 200 ]]; then
    os_call POST /_aliases "{\"actions\":[{\"add\":{\"index\":\"${FIRST_INDEX}\",\"alias\":\"${ALIAS_NAME}\",\"is_write_index\":true}}]}"
    require_2xx "POST _aliases"
    note updated alias "$ALIAS_NAME"
    return 0
  fi
  os_call PUT "/${FIRST_INDEX}" "{\"aliases\":{\"${ALIAS_NAME}\":{\"is_write_index\":true}}}"
  require_2xx "PUT ${FIRST_INDEX}"
  note created index "${FIRST_INDEX} (write alias ${ALIAS_NAME})"
}

ensure_default_pipeline() {
  local missing
  os_call GET "/${ALIAS_NAME}-*/_settings?flat_settings=true"
  require_2xx "GET ${ALIAS_NAME}-*/_settings"
  missing="$(helper setting-missing index.default_pipeline "$ROUTER_PIPELINE" <<<"$HTTP_BODY")"
  if ((missing == 0)); then
    note unchanged settings "${ALIAS_NAME}-* default_pipeline"
    return 0
  fi
  os_call PUT "/${ALIAS_NAME}-*/_settings" "{\"index.default_pipeline\":\"${ROUTER_PIPELINE}\"}"
  require_2xx "PUT ${ALIAS_NAME}-*/_settings default_pipeline"
  note updated settings "${ALIAS_NAME}-* default_pipeline=${ROUTER_PIPELINE} (${missing} index(es))"
}

verify_all() {
  local failures=0 f name have want
  log "verifying every object with GET"
  os_call GET '/_cluster/settings?flat_settings=true'
  if ! helper settings-match "${SCRIPT_DIR}/cluster-settings.json" <<<"$HTTP_BODY"; then
    warn "verify: cluster settings differ from cluster-settings.json"
    failures=$((failures + 1))
  fi
  for f in "${PIPELINE_FILES[@]}"; do
    name="$(object_name "$f")"
    os_call GET "/_ingest/pipeline/${name}"
    have="$(helper marker pipeline <<<"$HTTP_BODY" 2>/dev/null || true)"
    want=${WANT["pipeline:${name}"]}
    if [[ "$HTTP_CODE" != 200 || "$have" != "$want" ]]; then
      warn "verify: pipeline ${name} missing or stale (HTTP ${HTTP_CODE})"
      failures=$((failures + 1))
    fi
  done
  for f in "${TEMPLATE_FILES[@]}"; do
    name="$(object_name "$f")"
    os_call GET "/_index_template/${name}"
    have="$(helper marker template <<<"$HTTP_BODY" 2>/dev/null || true)"
    want=${WANT["template:${name}"]}
    if [[ "$HTTP_CODE" != 200 || "$have" != "$want" ]]; then
      warn "verify: index template ${name} missing or stale (HTTP ${HTTP_CODE})"
      failures=$((failures + 1))
    elif [[ "$(helper get index_templates/0/index_template/index_patterns <<<"$HTTP_BODY")" != "$(helper get index_patterns <"$f")" ]]; then
      warn "verify: index template ${name} has different index_patterns"
      failures=$((failures + 1))
    fi
  done
  for f in "${POLICY_FILES[@]}"; do
    name="$(object_name "$f")"
    os_call GET "/_plugins/_ism/policies/${name}"
    have="$(helper marker ism <<<"$HTTP_BODY" 2>/dev/null || true)"
    want=${WANT["ism:${name}"]}
    if [[ "$HTTP_CODE" != 200 || "$have" != "$want" ]]; then
      warn "verify: ISM policy ${name} missing or stale (HTTP ${HTTP_CODE})"
      failures=$((failures + 1))
    elif [[ "$(helper ism-sig <<<"$HTTP_BODY")" != "$(helper ism-sig <"$f")" ]]; then
      warn "verify: ISM policy ${name} has a different ism_template"
      failures=$((failures + 1))
    fi
  done
  os_call GET "/_alias/${ALIAS_NAME}"
  if [[ "$HTTP_CODE" != 200 || "$(helper write-indices <<<"$HTTP_BODY")" != 1 ]]; then
    warn "verify: alias ${ALIAS_NAME} missing or without a single write index"
    failures=$((failures + 1))
  fi
  if [[ -n "$SNAPSHOT_PATH" ]]; then
    os_call POST "/_snapshot/${REPO_NAME}/_verify"
    if [[ "$HTTP_CODE" != 200 ]]; then
      warn "verify: snapshot repository ${REPO_NAME} failed _verify (HTTP ${HTTP_CODE}): ${HTTP_BODY:0:300}"
      failures=$((failures + 1))
    fi
  fi
  ((failures == 0)) || die "$EX_FAIL" "verification failed (${failures} problem(s))"
  log "verification OK"
}

main() {
  local f
  parse_args "$@"
  command -v python3 >/dev/null || die "$EX_FAIL" "python3 is required"
  collect_files
  if [[ "$DRY_RUN" == true ]]; then
    dry_run
    exit 0
  fi
  command -v curl >/dev/null || die "$EX_FAIL" "curl is required"
  load_credentials
  wait_ready
  resolve_replicas
  apply_cluster_settings
  for f in "${PIPELINE_FILES[@]}"; do apply_put_object pipeline "$(object_name "$f")" "/_ingest/pipeline/$(object_name "$f")" "$f"; done
  for f in "${TEMPLATE_FILES[@]}"; do apply_put_object template "$(object_name "$f")" "/_index_template/$(object_name "$f")" "$f"; done
  for f in "${POLICY_FILES[@]}"; do apply_ism_policy "$f"; done
  apply_snapshot_repo
  bootstrap_alias
  ensure_default_pipeline
  verify_all
  log "done: ${CREATED} created, ${UPDATED} updated, ${UNCHANGED} unchanged"
}

main "$@"
