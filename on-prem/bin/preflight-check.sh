#!/usr/bin/env bash
# on-prem/bin/preflight-check.sh
#
# Fail-closed go/no-go gate for on-prem CS3 installs. Exits non-zero (and prints
# remediation text) the moment any invariant required for a real, on-prem, non-mock
# deployment is violated. Intended to be run:
#   - manually before go-live (see ../checklists/go-live-checklist.md)
#   - at the end of bootstrap-onprem.sh
#   - in CI/ops automation as a final gate
#
# Checks performed:
#   1. CS3_DEMO_MODE must be unset or "false"           (server/profile.ts#isDemoMode)
#   2. CS3_PROFILE must be "onprem" or "airgap"          (server/profile.ts#getDeploymentProfile)
#   3. CS3_INGEST_REQUIRE_KEY must be "true"             (server/fleet/enrollment.ts requireIngestKey)
#   4. GEMINI_API_KEY / DEEPSEEK_API_KEY must be blank   (hosted-model keys are rejected on-prem)
#  5. On-prem C3 installs require durable indexing and a reachable indexer.
#      CECUR_INDEXER_VERIFY_URL may override CECUR_INDEXER_URL when the latter
#      is a Compose-internal address (server/integrations/opensearchSink.ts).
#
# This script only reads environment variables already present in its own process
# environment -- source your deployment's .env file before running it, e.g.:
#   set -a; source .env; set +a; on-prem/bin/preflight-check.sh
set -uo pipefail

FAILED=0
pass() { printf '  [PASS] %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1"; printf '         %s\n' "$2"; FAILED=1; }

echo "CS3 on-prem preflight check"
echo "============================"

# 1. Demo mode must be off.
if [ "${CS3_DEMO_MODE:-false}" = "true" ]; then
  fail "CS3_DEMO_MODE=true" \
       "Unset CS3_DEMO_MODE or set it to 'false'. Demo mode seeds mock data and runs a simulated tick loop (server/db.ts, server.ts) -- never valid for an on-prem install of real endpoints."
else
  pass "CS3_DEMO_MODE is unset/false"
fi

# 2. Deployment profile must be onprem or airgap.
PROFILE="${CS3_PROFILE:-cloud}"
case "$PROFILE" in
  onprem|airgap)
    pass "CS3_PROFILE=${PROFILE}"
    ;;
  *)
    fail "CS3_PROFILE=${PROFILE}" \
         "Set CS3_PROFILE=onprem (or airgap) before launching the console. See demo/demo-100226/server/profile.ts."
    ;;
esac

# 3. Ingest key enforcement must be on, or no real fleet can be trusted.
if [ "${CS3_INGEST_REQUIRE_KEY:-false}" = "true" ]; then
  pass "CS3_INGEST_REQUIRE_KEY=true"
else
  fail "CS3_INGEST_REQUIRE_KEY=${CS3_INGEST_REQUIRE_KEY:-<unset>}" \
       "Set CS3_INGEST_REQUIRE_KEY=true. Without it, /api/cecur/logs/ingest accepts events from any caller without a per-agent key (server/fleet/enrollment.ts#requireIngestKey)."
fi

# 4. Hosted model keys must be blank on-prem/airgap.
for key in GEMINI_API_KEY DEEPSEEK_API_KEY; do
  val="${!key:-}"
  if [ -n "$val" ]; then
    fail "${key} is set" \
         "Blank ${key}. On-prem/airgap profiles must route LLM calls to a local Ollama instance only (root README.md Path B); hosted-model keys indicate an unintended cloud dependency."
  else
    pass "${key} is blank"
  fi
done

# 5. PLB/on-prem C3 requires durable indexing. Airgap remains an explicit
# architecture decision, but an enabled indexer is always checked fail-closed.
if [ "$PROFILE" = "onprem" ] && [ "${CS3_INDEXER_ENABLED:-false}" != "true" ]; then
  fail "CS3_INDEXER_ENABLED=${CS3_INDEXER_ENABLED:-<unset>}" \
       "Set CS3_INDEXER_ENABLED=true and run the siem profile. A filesystem relay buffer and the 300-row hot cache do not provide durable C3 storage."
elif [ "${CS3_INDEXER_ENABLED:-false}" = "true" ]; then
  INDEXER_VERIFY_URL="${CECUR_INDEXER_VERIFY_URL:-${CECUR_INDEXER_URL:-}}"
  if [ -z "$INDEXER_VERIFY_URL" ]; then
    fail "CS3_INDEXER_ENABLED=true but the indexer URL is empty" \
         "Set CECUR_INDEXER_URL, or CECUR_INDEXER_VERIFY_URL for host-side verification of a Compose-internal endpoint."
  elif ! command -v curl >/dev/null 2>&1; then
    fail "curl is not installed" \
         "Install curl; indexer reachability cannot be skipped when durable indexing is enabled."
  else
    AUTH_ARGS=()
    if [ -n "${CECUR_INDEXER_USERNAME:-}" ]; then
      AUTH_ARGS=(-u "${CECUR_INDEXER_USERNAME}:${CECUR_INDEXER_PASSWORD:-}")
    fi
    TLS_ARGS=()
    if [ "${CECUR_INDEXER_TLS_INSECURE:-false}" = "true" ]; then
      TLS_ARGS=(-k)
    elif [ -n "${CECUR_INDEXER_CA_FILE:-}" ]; then
      TLS_ARGS=(--cacert "$CECUR_INDEXER_CA_FILE")
    fi
    if curl -fsS -m 5 ${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"} ${TLS_ARGS[@]+"${TLS_ARGS[@]}"} "${INDEXER_VERIFY_URL%/}/_cluster/health" >/dev/null 2>&1; then
      pass "Indexer ($INDEXER_VERIFY_URL) is reachable"
    else
      fail "Indexer ($INDEXER_VERIFY_URL) is not reachable" \
           "Confirm the siem profile, credentials, host-reachable verification URL, and CA trust. Do not disable production TLS verification to bypass this failure."
    fi
  fi
else
  echo "  [INFO] CS3_INDEXER_ENABLED is not 'true'; durable indexing is off for this airgap profile."
fi

echo "============================"
if [ "$FAILED" -ne 0 ]; then
  echo "Preflight FAILED. Fix the items above before going live."
  exit 1
fi
echo "Preflight PASSED."
exit 0
