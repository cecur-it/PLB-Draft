#!/usr/bin/env bash
# Fail-closed C3 telemetry verification.
#
# The ingest route can return HTTP 201 and success:true with indexed:false when
# OpenSearch fails. Fluent Bit therefore considers delivery successful and need
# not retry; its filesystem buffer is not a durable C3 store. This script requires
# an explicit durable acknowledgement and independent OpenSearch evidence.
#
# A synthetic event verifies the relay/API path only. Supply --expectations and
# --since to require evidence for every real device. --restart-console queries
# all evidence before and after a Compose console restart.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
URL="${CS3_URL:-}"
INGEST_KEY=""
AGENT_ID=""
BEARER_TOKEN="${CS3_TOKEN:-}"
EXPECTATIONS=""
EXPECT_COUNT=""
SINCE=""
QUERY_ONLY="false"
RESTART_CONSOLE="false"
ATTEMPTS=30
QUERY_DELAY=2

usage() {
  cat <<'EOF'
Usage:
  verify-real-telemetry.sh --url <console-url> --ingest-key <key> --agent-id <relay-id>
    [--token <bearer>] [--expectations <json> --expect-count 18 --since <ISO-8601>]
    [--restart-console]
  verify-real-telemetry.sh --query-only --expectations <json> --since <ISO-8601>
    [--expect-count 18] [--url <console-url> --restart-console]

Environment:
  CS3_TOKEN                         Console bearer token (or use --token).
  CECUR_INDEXER_URL                Host-reachable OpenSearch base URL (required).
  CECUR_INDEXER_VERIFY_URL         Optional host-side override for the above.
  CECUR_INDEXER_USERNAME/PASSWORD  OpenSearch credentials.
  CECUR_INDEXER_CA_FILE            Optional CA bundle for host-side TLS verification.
  CECUR_INDEXER_TLS_INSECURE=true  Lab-only: disable indexer TLS verification.
  CS3_COMPOSE_DIR                  Compose project for --restart-console
                                   (default: repository deployment/docker).

Expectations JSON is an array of:
  {"device":"HOST", "message":"unique text", "agentName":"HOST", "sourceIp":"optional sender IP"}
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --ingest-key) INGEST_KEY="$2"; shift 2 ;;
    --agent-id) AGENT_ID="$2"; shift 2 ;;
    --token) BEARER_TOKEN="$2"; shift 2 ;;
    --expectations) EXPECTATIONS="$2"; shift 2 ;;
    --expect-count) EXPECT_COUNT="$2"; shift 2 ;;
    --since) SINCE="$2"; shift 2 ;;
    --query-only) QUERY_ONLY="true"; shift ;;
    --restart-console) RESTART_CONSOLE="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"

INDEXER_URL="${CECUR_INDEXER_VERIFY_URL:-${CECUR_INDEXER_URL:-}}"
[ -n "$INDEXER_URL" ] || fail "set host-reachable CECUR_INDEXER_URL or CECUR_INDEXER_VERIFY_URL"
CONSOLE_URL="${URL%/}"
INGEST_URL="${CONSOLE_URL}/api/cecur/logs/ingest"
if [[ "$CONSOLE_URL" == */api/cecur/logs/ingest ]]; then
  INGEST_URL="$CONSOLE_URL"
  CONSOLE_URL="${CONSOLE_URL%/api/cecur/logs/ingest}"
fi

if [ "$QUERY_ONLY" = "true" ]; then
  [ -n "$EXPECTATIONS" ] || fail "--query-only requires --expectations"
else
  [ -n "$URL" ] || fail "--url is required"
  [ -n "$INGEST_KEY" ] || fail "--ingest-key is required"
  [ -n "$AGENT_ID" ] || fail "--agent-id must identify the relay enrolled by the supplied key"
  [ -n "$BEARER_TOKEN" ] || fail "--token or CS3_TOKEN is required; hot-cache verification cannot be skipped"
fi
if [ "$RESTART_CONSOLE" = "true" ]; then
  [ -n "$URL" ] || fail "--restart-console requires --url for the post-restart health check"
  command -v docker >/dev/null 2>&1 || fail "docker is required for --restart-console"
fi
if [ -z "$EXPECTATIONS" ] && [ -n "$EXPECT_COUNT" ]; then
  fail "--expect-count requires --expectations"
fi
if [ -n "$EXPECTATIONS" ]; then
  [ -f "$EXPECTATIONS" ] || fail "expectations file not found: $EXPECTATIONS"
  [ -n "$SINCE" ] || fail "--since is required with --expectations so historical events cannot satisfy the gate"
  jq -e 'type == "array" and length > 0 and all(.[];
    (.device | type == "string" and length > 0) and
    (.message | type == "string" and length > 0) and
    (.agentName | type == "string" and length > 0) and
    ((.sourceIp // "") | type == "string"))' "$EXPECTATIONS" >/dev/null \
    || fail "expectations must be a non-empty array with device, message, agentName, and optional sourceIp strings"
  [ "$(jq '[.[].device] | unique | length' "$EXPECTATIONS")" = "$(jq 'length' "$EXPECTATIONS")" ] \
    || fail "expectations device names must be unique"
  if [ -n "$EXPECT_COUNT" ]; then
    [[ "$EXPECT_COUNT" =~ ^[1-9][0-9]*$ ]] || fail "--expect-count must be a positive integer"
    actual_count="$(jq 'length' "$EXPECTATIONS")"
    [ "$actual_count" = "$EXPECT_COUNT" ] || fail "expectations contain $actual_count devices; required: $EXPECT_COUNT"
  fi
elif [ "$QUERY_ONLY" = "true" ]; then
  fail "--query-only has no work without --expectations"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
AUTH_ARGS=()
[ -n "${CECUR_INDEXER_USERNAME:-}" ] && AUTH_ARGS=(-u "${CECUR_INDEXER_USERNAME}:${CECUR_INDEXER_PASSWORD:-}")
TLS_ARGS=()
if [ "${CECUR_INDEXER_TLS_INSECURE:-false}" = "true" ]; then
  TLS_ARGS=(-k)
  echo "WARNING: indexer TLS verification is disabled; this is a lab-only check."
elif [ -n "${CECUR_INDEXER_CA_FILE:-}" ]; then
  [ -f "$CECUR_INDEXER_CA_FILE" ] || fail "CECUR_INDEXER_CA_FILE not found: $CECUR_INDEXER_CA_FILE"
  TLS_ARGS=(--cacert "$CECUR_INDEXER_CA_FILE")
fi

QUERY_LABELS=()
QUERY_FILES=()
QUERY_COUNT=0
MARKER=""
LOG_ID=""

if [ "$QUERY_ONLY" = "false" ]; then
  SINCE="${SINCE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  MARKER="onprem-verify-$(date +%s)-$$"
  echo "== Ingest synthetic relay marker =="
  jq -n --arg agentId "$AGENT_ID" --arg marker "$MARKER" \
    '{agentId:$agentId,agentName:$agentId,source:"syslog",severity:"info",message:$marker}' > "$TMP/ingest-request.json"
  if ! curl -fsS -m 10 -X POST "$INGEST_URL" \
      -H "Content-Type: application/json" -H "X-API-Key: ${INGEST_KEY}" \
      --data-binary @"$TMP/ingest-request.json" > "$TMP/ingest-response.json"; then
    cat "$TMP/ingest-response.json" >&2
    fail "ingest request failed"
  fi
  jq -e '.success == true' "$TMP/ingest-response.json" >/dev/null \
    || { cat "$TMP/ingest-response.json" >&2; fail "ingest did not report success:true"; }
  if ! jq -e '.indexed == true' "$TMP/ingest-response.json" >/dev/null; then
    cat "$TMP/ingest-response.json" >&2
    fail "ingest did not confirm durable indexing. HTTP 201/success:true with indexed:false is a C3 failure; Fluent Bit need not retry and its filesystem buffer is not durable C3 storage"
  fi
  LOG_ID="$(jq -r '.logId // .logIds[0] // empty' "$TMP/ingest-response.json")"
  [ -n "$LOG_ID" ] || fail "ingest response did not contain a log ID"
  echo "  [PASS] ingest returned success:true and indexed:true (log $LOG_ID)"

  echo "== Verify authenticated hot-cache visibility =="
  HOT_FOUND="false"
  for ((attempt=1; attempt<=ATTEMPTS; attempt++)); do
    if curl -fsS -m 10 --get "$CONSOLE_URL/api/cecur/logs" \
        --data-urlencode "search=$MARKER" --data-urlencode "limit=5" \
        -H "Authorization: Bearer ${BEARER_TOKEN}" > "$TMP/hot-cache.json" \
      && jq -e --arg marker "$MARKER" --arg agentId "$AGENT_ID" \
        'any(.logs[]?; .message == $marker and .agentId == $agentId)' "$TMP/hot-cache.json" >/dev/null; then
      HOT_FOUND="true"
      break
    fi
    sleep "$QUERY_DELAY"
  done
  [ "$HOT_FOUND" = "true" ] || { cat "$TMP/hot-cache.json" >&2; fail "synthetic marker not found in hot cache for the enrolled relay agent ID"; }
  echo "  [PASS] marker is visible in the hot cache with the pinned relay agent ID"

  jq -n --arg id "$LOG_ID" '{size:1,query:{ids:{values:[$id]}}}' > "$TMP/query-0.json"
  QUERY_LABELS+=("synthetic relay marker")
  QUERY_FILES+=("$TMP/query-0.json")
  QUERY_COUNT=1
fi

if [ -n "$EXPECTATIONS" ]; then
  while IFS= read -r expectation; do
    device="$(jq -r '.device' <<< "$expectation")"
    message="$(jq -r '.message' <<< "$expectation")"
    agent_name="$(jq -r '.agentName' <<< "$expectation")"
    source_ip="$(jq -r '.sourceIp // ""' <<< "$expectation")"
    query_file="$TMP/query-$QUERY_COUNT.json"
    jq -n --arg message "$message" --arg agentName "$agent_name" --arg sourceIp "$source_ip" --arg since "$SINCE" \
      '{size:5,query:{bool:{must:([{match_phrase:{message:$message}},{match_phrase:{agentName:$agentName}}]
        + (if $sourceIp == "" then [] else [{match_phrase:{"fields.source_ip":$sourceIp}}] end)),
        filter:[{range:{timestamp:{gte:$since}}}]}}}' > "$query_file"
    QUERY_LABELS+=("$device")
    QUERY_FILES+=("$query_file")
    QUERY_COUNT=$((QUERY_COUNT + 1))
  done < <(jq -c '.[]' "$EXPECTATIONS")
fi

run_queries() {
  local phase="$1" i attempt found response label
  echo "== Direct OpenSearch verification ($phase) =="
  for ((i=0; i<QUERY_COUNT; i++)); do
    label="${QUERY_LABELS[$i]}"
    response="$TMP/search-$phase-$i.json"
    found="false"
    for ((attempt=1; attempt<=ATTEMPTS; attempt++)); do
      if curl -fsS -m 15 ${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"} ${TLS_ARGS[@]+"${TLS_ARGS[@]}"} \
          -X POST "${INDEXER_URL%/}/cs3-logs/_search" -H "Content-Type: application/json" \
          --data-binary @"${QUERY_FILES[$i]}" > "$response" \
        && jq -e '(.error | not) and ((.hits.hits | length) > 0)' "$response" >/dev/null; then
        found="true"
        break
      fi
      sleep "$QUERY_DELAY"
    done
    if [ "$found" != "true" ]; then
      jq -c '{error:(.error // "no matching document"),hits:(.hits.total // 0)}' "$response" >&2 2>/dev/null || true
      fail "no post-$SINCE OpenSearch evidence for $label ($phase)"
    fi
    jq -r --arg evidence_label "$label" '.hits.hits[0] | "  [PASS] \($evidence_label): index=\(._index) id=\(._id) timestamp=\(._source.timestamp) agent=\(._source.agentName) sourceIp=\(._source.fields.source_ip // "unrecorded")"' "$response"
  done
}

run_queries "before-restart"

if [ "$RESTART_CONSOLE" = "true" ]; then
  COMPOSE_DIR="${CS3_COMPOSE_DIR:-$REPO_ROOT/deployment/docker}"
  [ -f "$COMPOSE_DIR/docker-compose.yml" ] || fail "Compose project not found: $COMPOSE_DIR"
  echo "== Restart console and verify post-restart health =="
  docker compose --project-directory "$COMPOSE_DIR" restart console
  HEALTHY="false"
  for ((attempt=1; attempt<=ATTEMPTS; attempt++)); do
    if curl -fsS -m 10 "$CONSOLE_URL/api/health" > "$TMP/health.json"; then
      HEALTHY="true"
      break
    fi
    sleep "$QUERY_DELAY"
  done
  [ "$HEALTHY" = "true" ] || fail "console did not return a healthy /api/health response after restart"
  echo "  [PASS] console is healthy; the hot cache was not used for durability evidence"
  run_queries "after-restart"
fi

if [ "$RESTART_CONSOLE" = "true" ] && [ -n "$EXPECTATIONS" ]; then
  echo "C3 verification PASSED for $QUERY_COUNT evidence item(s). Device matches prove arrival/attribution fields, not authenticated device identity."
elif [ "$RESTART_CONSOLE" = "true" ]; then
  echo "Relay restart durability check PASSED for the synthetic marker only; this is not per-device C3 acceptance."
else
  echo "Evidence verification PASSED for $QUERY_COUNT evidence item(s); no console restart was performed, so this is not C3 restart-durability acceptance."
fi
