#!/usr/bin/env bash
#
# entrypoint.sh — container entrypoint of the CS3 Ollama worker image (Dockerfile.ollama).
#   serve (default)  start `ollama serve` (bound to 127.0.0.1:11434 by the image ENV), wait until it
#                    answers, then provision the approved models with pull-models.sh:
#                      cloud/onprem/edge  pull (OLLAMA_PRELOAD_MODELS, default primary + fallback + security + deep)
#                      airgap             NEVER pulls: loads + verifies the bundle in
#                                         OLLAMA_AIRGAP_BUNDLE_DIR, or just serves what is already stored
#   --healthcheck    exit 0 only if the server answers `ollama list` AND every model that would be
#                    preloaded is present (used by the image HEALTHCHECK)
#   anything else    passed through to the ollama CLI (docker exec / run ... list, show, ps)
#
# Traces: PROMPT §1 Tier 4 (sovereign Ollama), PROMPT §3 (air-gap: no registry access),
#         CONTRACT §8.1/§8.2 (worker binds loopback only; models preloaded per profile).
#
# Environment: CS3_PROFILE (onprem), OLLAMA_PRELOAD_MODELS, OLLAMA_AIRGAP_BUNDLE_DIR,
#   OLLAMA_PRELOAD_STRICT (true: exit if provisioning fails; false: keep serving),
#   OLLAMA_READY_TIMEOUT (120 s), OLLAMA_BIN, PULL_MODELS_BIN (/usr/local/bin/pull-models.sh).
# Exit codes: 0 clean stop, 1 start/provisioning failure, 2 usage, 3 integrity (digest/policy),
#             otherwise the exit code of `ollama serve`.
set -euo pipefail
set -o errtrace
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

OLLAMA_BIN="${OLLAMA_BIN:-ollama}"
PULL_MODELS_BIN="${PULL_MODELS_BIN:-/usr/local/bin/pull-models.sh}"
PROFILE="${CS3_PROFILE:-onprem}"
STRICT="${OLLAMA_PRELOAD_STRICT:-true}"
READY_TIMEOUT="${OLLAMA_READY_TIMEOUT:-120}"

log()  { printf '[entrypoint] %s\n' "$1" >&2; }
die()  { local code="$1"; shift; printf '[entrypoint][FAIL] %s\n' "$*" >&2; exit "$code"; }

case "$PROFILE" in cloud|onprem|airgap|edge) ;; *) die 2 "CS3_PROFILE must be cloud, onprem, airgap or edge (got '$PROFILE')" ;; esac
[[ "$READY_TIMEOUT" =~ ^[0-9]+$ ]] || die 2 "OLLAMA_READY_TIMEOUT must be an integer"
case "$STRICT" in true|false) ;; *) die 2 "OLLAMA_PRELOAD_STRICT must be true or false" ;; esac

healthcheck() {
  local present want id
  present="$("$OLLAMA_BIN" list 2>/dev/null)" || exit 1
  want="$("$PULL_MODELS_BIN" --print-models 2>/dev/null)" || exit 1
  for id in $want; do
    printf '%s\n' "$present" | awk 'NR > 1 {print $1}' | grep -qxF "$id" || exit 1
  done
}

provision() {
  local args=(--from-models-json --profile "$PROFILE")
  if [[ "$PROFILE" == "airgap" ]]; then
    if [[ -z "${OLLAMA_AIRGAP_BUNDLE_DIR:-}" || ! -d "${OLLAMA_AIRGAP_BUNDLE_DIR:-}" ]]; then
      log "profile airgap: no OLLAMA_AIRGAP_BUNDLE_DIR mounted — serving the models already in the store, never pulling."
      return 0
    fi
    args+=(--release)
  fi
  "$PULL_MODELS_BIN" "${args[@]}"
}

serve() {
  local server_pid="" worker_pid="" waited=0 rc=0
  stop_children() {
    [[ -z "$worker_pid" ]] || kill -TERM "$worker_pid" 2>/dev/null || true
    [[ -z "$server_pid" ]] || kill -TERM "$server_pid" 2>/dev/null || true
  }
  trap 'stop_children; wait 2>/dev/null || true; exit 143' TERM INT

  log "starting ollama serve (OLLAMA_HOST=${OLLAMA_HOST:-unset}, profile=$PROFILE)"
  "$OLLAMA_BIN" serve "$@" &
  server_pid=$!

  until "$OLLAMA_BIN" list >/dev/null 2>&1; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
      wait "$server_pid" || rc=$?
      [[ "$rc" -ne 0 ]] || rc=1
      die "$rc" "ollama serve exited before becoming ready"
    fi
    (( waited < READY_TIMEOUT )) || { stop_children; die 1 "ollama did not answer within ${READY_TIMEOUT}s"; }
    sleep 1
    waited=$(( waited + 1 ))
  done
  log "ollama is answering after ${waited}s"

  provision &
  worker_pid=$!
  wait "$worker_pid" || rc=$?
  worker_pid=""
  if [[ "$rc" -ne 0 ]]; then
    if [[ "$STRICT" == "true" || "$rc" -eq 3 ]]; then
      stop_children
      die "$rc" "model provisioning failed (exit $rc)"
    fi
    log "model provisioning failed (exit $rc); OLLAMA_PRELOAD_STRICT=false so the server keeps running."
  fi

  rc=0
  wait "$server_pid" || rc=$?
  exit "$rc"
}

case "${1:-serve}" in
  --healthcheck) healthcheck ;;
  serve)         shift || true; serve "$@" ;;
  *)             exec "$OLLAMA_BIN" "$@" ;;
esac
