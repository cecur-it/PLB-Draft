#!/usr/bin/env bash
# Import dashboards/saved-objects.ndjson into OpenSearch Dashboards (idempotent:
# overwrite=true, stable object ids) and verify the result through the API.
#
# Usage: dashboards/import.sh [--url URL] [--file FILE] [--wait-timeout SECONDS] [--dry-run] [--help]
#
# Environment:
#   DASHBOARDS_URL            default http://opensearch-dashboards:5601
#   DASHBOARDS_CA             CA bundle, only needed when DASHBOARDS_URL is https
#   OPENSEARCH_USER           default admin
#   OPENSEARCH_PASSWORD_FILE  default /run/secrets/opensearch_admin_password
#   DASHBOARDS_WAIT_TIMEOUT   seconds to wait for Dashboards (default 300)
#
# Needs bash, curl and python3 only (all present in the OpenSearch image).
# Exit codes: 0 imported and verified; 1 import or verification failed; 2 usage;
#             3 Dashboards not ready in time; 4 password/file problem.
set -Eeuo pipefail
IFS=$'\n\t'
trap 'printf "import.sh: FAILED at line %s\n" "$LINENO" >&2' ERR
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
URL="${DASHBOARDS_URL:-http://opensearch-dashboards:5601}"
FILE="${HERE}/saved-objects.ndjson"
USER_NAME="${OPENSEARCH_USER:-admin}"
PW_FILE="${OPENSEARCH_PASSWORD_FILE:-/run/secrets/opensearch_admin_password}"
WAIT_TIMEOUT="${DASHBOARDS_WAIT_TIMEOUT:-300}"
DEFAULT_INDEX="vs-ip-vendetta-alerts"
DRY_RUN=false
PW=""

log() { printf 'import.sh: %s\n' "$*"; }
die() { # code message
  local code=$1
  shift
  printf 'import.sh: ERROR: %s\n' "$*" >&2
  exit "$code"
}

usage() {
  sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while (($#)); do
  case "$1" in
    --url)
      [[ $# -ge 2 ]] || die 2 "--url needs a value"
      URL=$2
      shift
      ;;
    --file)
      [[ $# -ge 2 ]] || die 2 "--file needs a value"
      FILE=$2
      shift
      ;;
    --wait-timeout)
      [[ $# -ge 2 ]] || die 2 "--wait-timeout needs a value"
      WAIT_TIMEOUT=$2
      shift
      ;;
    --dry-run) DRY_RUN=true ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die 2 "unknown option: $1 (see --help)" ;;
  esac
  shift
done
[[ "$WAIT_TIMEOUT" =~ ^[0-9]+$ ]] || die 2 "--wait-timeout must be a whole number of seconds"
URL="${URL%/}"

command -v python3 >/dev/null || die 4 "python3 is required"
command -v curl >/dev/null || die 4 "curl is required"
[[ -r "$FILE" ]] || die 4 "saved objects file ${FILE} is missing or unreadable"

# Validates every line, the id/type pairs and cross references; prints "<objects> <index-patterns> <dashboards>".
SUMMARY="$(python3 - "$FILE" <<'PY'
import json, sys
objs, seen = [], set()
with open(sys.argv[1], encoding="utf-8") as fh:
    for number, line in enumerate(fh, 1):
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except ValueError as exc:
            sys.exit("line %d is not JSON: %s" % (number, exc))
        if "exportedCount" in doc:
            continue
        if not all(k in doc for k in ("id", "type", "attributes")):
            sys.exit("line %d lacks id/type/attributes" % number)
        key = (doc["type"], doc["id"])
        if key in seen:
            sys.exit("duplicate object %s/%s" % key)
        seen.add(key)
        objs.append(doc)
for doc in objs:
    for ref in doc.get("references", []):
        if (ref["type"], ref["id"]) not in seen:
            sys.exit("%s/%s references missing %s/%s" % (doc["type"], doc["id"], ref["type"], ref["id"]))
print(len(objs), sum(d["type"] == "index-pattern" for d in objs), sum(d["type"] == "dashboard" for d in objs))
PY
)" || die 4 "invalid saved objects file ${FILE}: ${SUMMARY:-see message above}"
IFS=' ' read -r N_OBJECTS N_PATTERNS N_DASHBOARDS <<<"$SUMMARY"
log "${FILE}: ${N_OBJECTS} objects (${N_PATTERNS} index patterns, ${N_DASHBOARDS} dashboards)"

if [[ "$DRY_RUN" == true ]]; then
  log "dry-run: would POST ${URL}/api/saved_objects/_import?overwrite=true as ${USER_NAME}"
  log "dry-run: would set defaultIndex=${DEFAULT_INDEX} and verify via ${URL}/api/saved_objects/_find"
  exit 0
fi

[[ -r "$PW_FILE" ]] || die 4 "password file ${PW_FILE} is missing or unreadable"
PW="$(<"$PW_FILE")"
PW="${PW%$'\r'}"
[[ -n "$PW" ]] || die 4 "password file ${PW_FILE} is empty"

auth_config() {
  local p=${PW//\\/\\\\}
  p=${p//\"/\\\"}
  printf 'user = "%s:%s"\n' "$USER_NAME" "$p"
}

HTTP_CODE=""
HTTP_BODY=""
req() { # method path [extra curl args...]
  local method=$1 path=$2 out
  shift 2
  local -a tls=()
  if [[ -n "${DASHBOARDS_CA:-}" ]]; then tls=(--cacert "$DASHBOARDS_CA"); fi
  if out="$(curl -sS --max-time 120 "${tls[@]}" -K <(auth_config) -X "$method" -H 'osd-xsrf: true' \
    -w $'\n%{http_code}' "$@" "${URL}${path}" 2>&1)"; then
    HTTP_CODE=${out##*$'\n'}
    HTTP_BODY=${out%$'\n'*}
  else
    HTTP_CODE=000
    HTTP_BODY=$out
  fi
}

json_get() { # json-text python-expression-on-d
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2" <<<"$1" 2>/dev/null || true
}

wait_ready() {
  local deadline=$((SECONDS + WAIT_TIMEOUT)) delay=2 state
  log "waiting for ${URL} (timeout ${WAIT_TIMEOUT}s)"
  while :; do
    req GET /api/status
    if [[ "$HTTP_CODE" == 200 ]]; then
      state="$(json_get "$HTTP_BODY" "d['status']['overall']['state']")"
      if [[ "$state" == green || "$state" == yellow ]]; then
        log "Dashboards is ${state}"
        return 0
      fi
    elif [[ "$HTTP_CODE" == 401 || "$HTTP_CODE" == 403 ]]; then
      die 4 "Dashboards rejected the credentials for ${USER_NAME} (HTTP ${HTTP_CODE})"
    fi
    if ((SECONDS >= deadline)); then
      die 3 "Dashboards not ready after ${WAIT_TIMEOUT}s (last HTTP ${HTTP_CODE})"
    fi
    log "not ready yet (HTTP ${HTTP_CODE}); retry in ${delay}s"
    sleep "$delay"
    delay=$((delay < 15 ? delay * 2 : 15))
  done
}

wait_ready

req POST '/api/saved_objects/_import?overwrite=true' -F "file=@${FILE}"
[[ "$HTTP_CODE" == 200 ]] || die 1 "import failed: HTTP ${HTTP_CODE}: ${HTTP_BODY:0:600}"
[[ "$(json_get "$HTTP_BODY" "d.get('success')")" == True ]] || die 1 "import reported errors: ${HTTP_BODY:0:900}"
COUNT="$(json_get "$HTTP_BODY" "d.get('successCount')")"
[[ "$COUNT" == "$N_OBJECTS" ]] || die 1 "imported ${COUNT} of ${N_OBJECTS} objects"
log "imported ${COUNT} saved objects (overwrite=true)"

req POST /api/opensearch-dashboards/settings -H 'Content-Type: application/json' \
  --data "{\"changes\":{\"defaultIndex\":\"${DEFAULT_INDEX}\"}}"
[[ "$HTTP_CODE" == 200 ]] || die 1 "setting defaultIndex failed: HTTP ${HTTP_CODE}: ${HTTP_BODY:0:400}"

check_type() { # type expected
  req GET "/api/saved_objects/_find?type=$1&per_page=200&fields=title"
  [[ "$HTTP_CODE" == 200 ]] || die 1 "verification of $1 failed: HTTP ${HTTP_CODE}: ${HTTP_BODY:0:400}"
  local got
  got="$(json_get "$HTTP_BODY" "d.get('total')")"
  [[ "$got" == "$2" ]] || die 1 "expected $2 $1 objects, found ${got}"
}
check_type index-pattern "$N_PATTERNS"
check_type dashboard "$N_DASHBOARDS"
log "verified: ${N_PATTERNS} index patterns, ${N_DASHBOARDS} dashboards, defaultIndex=${DEFAULT_INDEX}"
