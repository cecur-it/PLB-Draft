#!/usr/bin/env bash
# test_entrypoint.sh - plain-bash tests for errow/entrypoint.sh (no Docker daemon, no real Errow).
# Traces: CONTRACT §2 (secrets via files, gateway env), §4.4 (gateway-only LLM egress), §8 (Errow addenda: one-shot CLI, viewer on 8765),
#         §11 (healthchecks). Uses a fake `errow` CLI, a fake dind-ready interpreter and throwaway TCP listeners;
#         scratch files live in .work.<pid>/ next to this script and are removed on exit.
# The fake CLI below is generated from single-quoted strings on purpose: its $-expansions must happen when the fake runs.
# shellcheck disable=SC2016
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

if [[ ${1-} == -h || ${1-} == --help ]]; then
  echo "Usage: test_entrypoint.sh   (needs bash, jq, python3, coreutils; exits non-zero on the first failed assertion)"
  exit 0
fi

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
EP=$(cd -- "${HERE}/.." && pwd)/entrypoint.sh
WORK="${HERE}/.work.$$"
BG_PIDS=()

cleanup() {
  local p
  for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  rm -rf -- "$WORK"
}
trap cleanup EXIT

PASS=0
pass() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() {
  printf '  FAIL %s\n' "$1" >&2
  if [[ -n ${2-} ]]; then printf '%s\n' "$2" | sed 's/^/       | /' >&2; fi
  exit 1
}
contains() { [[ $1 == *"$2"* ]] || fail "$3" "expected to contain: $2"$'\n'"got: $1"; pass "$3"; }
lacks() { [[ $1 != *"$2"* ]] || fail "$3" "must not contain: $2"$'\n'"got: $1"; pass "$3"; }
equals() { [[ $1 == "$2" ]] || fail "$3" "expected '$2' got '$1'"; pass "$3"; }
# GNU vs BSD userland: the suite runs on Linux containers and on macOS developer hosts alike.
ago() { touch -t "$(date -v-1H +%Y%m%d%H%M.%S 2>/dev/null || date -d '1 hour ago' +%Y%m%d%H%M.%S)" "$1"; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

mkdir -p "${WORK}/secrets" "${WORK}/bin" "${WORK}/ws" "${WORK}/home"
GW_TOKEN='gw-token-0123456789abcdef'
printf '%s\n' "$GW_TOKEN" >"${WORK}/secrets/llm_gateway_token"
printf 'cloud-provider-key-do-not-leak\n' >"${WORK}/secrets/provider_key"

printf '%s\n' '#!/usr/bin/env bash' 'printf "ARGS:%s\n" "$*" >>"$FAKE_LOG"' 'case ${1-} in' \
  '  view)' \
  '    echo "Serving ${2} (live) at:"' \
  '    echo "  http://127.0.0.1:8765/?token=SeCrEt-Tok_123"' \
  "    trap 'exit 0' TERM" \
  '    while :; do sleep 0.2; done ;;' \
  '  *)' \
  '    echo "ENV LLM_API_BASE=${LLM_API_BASE-} STREAM=${LLM_DISABLE_STREAMING-} MODEL=${errow_LLM-} TELEMETRY=${errow_TELEMETRY-} APP=${errow_APP_URL-} KEYLEN=${#LLM_API_KEY} HDR=${LLM_EXTRA_HEADERS-} IMG=${errow_IMAGE-} DOCKER=${DOCKER_HOST-}"' \
  '    echo "token=XYZ should be redacted"' \
  '    exit "${FAKE_EXIT:-0}" ;;' \
  'esac' >"${WORK}/bin/errow"
printf '%s\n' '#!/usr/bin/env bash' 'case ${2-} in ping | has-image | load) exit 0 ;; esac' 'exit 1' >"${WORK}/bin/fake-python"
chmod +x "${WORK}/bin/errow" "${WORK}/bin/fake-python"

BASE_ENV=(
  "PATH=${PATH}" "HOME=${WORK}/home" "LLM_GATEWAY_TOKEN_FILE=${WORK}/secrets/llm_gateway_token" "ERROW_WORKDIR=${WORK}/ws"
  "ERROW_LOG_DIR=${WORK}/log" "ERROW_CLI=${WORK}/bin/errow" "ERROW_PYTHON=${WORK}/bin/fake-python" "ERROW_PKI_CA=${WORK}/none.crt"
  "ERROW_STATE_DIR=${WORK}/state" "FAKE_LOG=${WORK}/fake.log"
)
OUT='' ERR='' RC=0
# ep [VAR=value ...] -- <entrypoint args>
ep() {
  local -a extra=()
  while [[ $1 != -- ]]; do extra+=("$1"); shift; done
  shift
  RC=0
  OUT=$(env -i ${BASE_ENV[@]+"${BASE_ENV[@]}"} ${extra[@]+"${extra[@]}"} bash "$EP" "$@" 2>"${WORK}/stderr") || RC=$?
  ERR=$(<"${WORK}/stderr")
}

echo "== usage and argument handling"
ep -- --help
equals "$RC" 0 "--help exits 0"
contains "$OUT" "--mode scan|view|idle" "--help documents modes"
ep -- --version
contains "$OUT" "errow-entrypoint 1.0.0" "--version"
ep -- --mode bogus
equals "$RC" 64 "unknown mode is a usage error (64)"
ep ERROW_MODE=weird -- --dry-run
equals "$RC" 64 "invalid ERROW_MODE is a usage error (64)"
ep CS3_PROFILE=moon -- --dry-run
equals "$RC" 78 "invalid profile is a configuration error (78)"

echo "== dry-run: gateway wiring and secrets hygiene"
ep ERROW_TARGET=scan-target.vendetta.lab -- --dry-run --mode scan
equals "$RC" 0 "scan dry-run exits 0"
contains "$OUT" "LLM_API_BASE         https://llm-gateway:9101/v1" "LLM_API_BASE points at the gateway"
contains "$OUT" "errow_LLM            openai/nemotron-3-nano:30b" "errow_LLM defaults to openai/<security model>"
contains "$OUT" "LLM_DISABLE_STREAMING true" "streaming disabled"
contains "$OUT" "errow_TELEMETRY      false" "telemetry off by default"
contains "$OUT" "errow_APP_URL        http://127.0.0.1:9" "Errow cloud URL blackholed by default"
contains "$OUT" "errow_IMAGE          vendetta-stack/errow-sandbox:1.0.0" "sandbox image default"
contains "$OUT" "DOCKER_HOST          tcp://errow-dind:2375" "DOCKER_HOST defaults to the DinD sidecar (no certs mounted)"
contains "$OUT" "command              ${WORK}/bin/errow --non-interactive --target scan-target.vendetta.lab --scan-mode quick" "scan command is assembled from env"
lacks "$OUT$ERR" "$GW_TOKEN" "the bearer token is never printed"
ep OLLAMA_SECURITY_MODEL=gemma4:26b ERROW_TENANT_ID=acme ERROW_INCIDENT_ID=inc-7 STACK_VERSION=2.0.0 -- --dry-run --mode idle
contains "$OUT" "openai/gemma4:26b" "OLLAMA_SECURITY_MODEL selects the default model"
contains "$OUT" '{"X-Tenant-Id":"acme","X-Incident-Id":"inc-7"}' "tenant/incident headers go through LLM_EXTRA_HEADERS"
contains "$OUT" "vendetta-stack/errow-sandbox:2.0.0" "STACK_VERSION selects the sandbox tag"
printf 'approval-tok-123\n' >"${WORK}/secrets/approval"
ep ERROW_TENANT_ID=acme CS3_APPROVAL_TOKEN_FILE="${WORK}/secrets/approval" -- --dry-run --mode idle
contains "$OUT" '{"X-Tenant-Id":"acme","X-CS3-Approval":"approval-tok-123"}' "the approval token file becomes the X-CS3-Approval header"
contains "$OUT" "approval token       from file ${WORK}/secrets/approval" "dry-run names the approval token source"
ep LLM_EXTRA_HEADERS='{"X-Custom":"1"}' CS3_APPROVAL_TOKEN=inline-approval -- --dry-run --mode idle
contains "$OUT" '{"X-Custom":"1","X-CS3-Approval":"inline-approval"}' "an existing LLM_EXTRA_HEADERS object is merged, not replaced"
ep LLM_EXTRA_HEADERS='not-json' CS3_APPROVAL_TOKEN=inline-approval -- --dry-run --mode idle
equals "$RC" 78 "a non-object LLM_EXTRA_HEADERS is refused when a token must be merged"
ep CS3_APPROVAL_TOKEN_FILE="${WORK}/secrets/missing" -- --dry-run --mode idle
equals "$RC" 66 "an unreadable approval token file is refused"
ep errow_LLM=openai/gemma4:31b -- --dry-run --mode idle
contains "$OUT" "openai/gemma4:31b" "an explicit errow_LLM wins over the security model"
ep errow_LLM=gemini/gemini-2.5-pro -- --dry-run --mode idle
equals "$RC" 78 "a non-openai errow_LLM is refused on the gateway route"
ep ERROW_MODE=view -- --dry-run
contains "$OUT" "view [<newest run>] --host 0.0.0.0 --port 8765 --no-open" "view dry-run shows the pinned viewer port"
ep ERROW_TARGET=x -- --dry-run --mode scan view
contains "$OUT" "${WORK}/bin/errow view" "errow subcommands pass through unchanged"
ep -- --dry-run --mode scan
equals "$RC" 64 "scan without a target is a usage error"
ep "LLM_GATEWAY_TOKEN_FILE=${WORK}/secrets/absent" -- --dry-run --mode idle
equals "$RC" 0 "dry-run tolerates a missing token file"
contains "$OUT" "(missing)" "dry-run reports the missing token file"
ep "LLM_GATEWAY_TOKEN_FILE=${WORK}/secrets/absent" -- --mode idle
equals "$RC" 66 "a real start without the token file fails (66)"

echo "== telemetry / cloud opt-in"
ep ERROW_TELEMETRY=true -- --dry-run --mode idle
contains "$OUT" "errow_TELEMETRY      true" "telemetry opt-in honoured (onprem)"
ep ERROW_TELEMETRY=true CS3_PROFILE=airgap -- --dry-run --mode idle
contains "$OUT" "errow_TELEMETRY      false" "airgap never sends telemetry"
ep ERROW_CLOUD_ENABLED=true -- --dry-run --mode idle
contains "$OUT" "errow_APP_URL        https://app.errow.ai" "ERROW_CLOUD_ENABLED restores the cloud URL"

echo "== fail-closed (CONTRACT §4.4)"
for bad in GEMINI_API_KEY DEEPSEEK_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY_FILE AWS_SECRET_ACCESS_KEY PERPLEXITY_API_KEY EXA_API_KEY; do
  ep "${bad}=sk-live-should-not-leak" -- --dry-run --mode idle
  equals "$RC" 78 "onprem + ${bad} => exit 78"
  contains "$ERR" "FailClosedError" "${bad}: FailClosedError reported"
  lacks "$ERR$OUT" "sk-live-should-not-leak" "${bad}: value never echoed"
done
ep CS3_PROFILE=airgap GEMINI_API_KEY=x -- --dry-run --mode idle
equals "$RC" 78 "airgap + cloud key => exit 78"
ep LLM_API_KEY=some-other-key -- --dry-run --mode idle
equals "$RC" 78 "non-gateway LLM_API_KEY => exit 78"
ep LLM_API_KEY="$GW_TOKEN" -- --dry-run --mode idle
equals "$RC" 0 "LLM_API_KEY equal to the gateway token is accepted"
ep LLM_API_BASE=https://api.openai.com/v1 -- --dry-run --mode idle
equals "$RC" 78 "non-gateway LLM_API_BASE => exit 78"
ep errow_LLM=gemini/gemini-2.5-pro -- --dry-run --mode idle
equals "$RC" 78 "non-openai/ model prefix => exit 78"
ep ERROW_LLM_ROUTE=direct -- --dry-run --mode idle
equals "$RC" 78 "direct route outside profile cloud => exit 78"
ep CS3_PROFILE=airgap ERROW_CLOUD_ENABLED=true -- --dry-run --mode idle
equals "$RC" 78 "airgap + ERROW_CLOUD_ENABLED => exit 78"
mkdir -p "${WORK}/home/.errow"
printf '{"env":{"GEMINI_API_KEY":"stale-secret","LLM_MODEL":"x"}}\n' >"${WORK}/home/.errow/cli-config.json"
ep -- --dry-run --mode idle
equals "$RC" 78 "stale cloud key persisted in ~/.errow/cli-config.json => exit 78"
contains "$ERR" "GEMINI_API_KEY (in " "stale key is named with its location"
lacks "$ERR" "stale-secret" "stale value not echoed"
rm -f "${WORK}/home/.errow/cli-config.json"
ep CS3_PROFILE=cloud GEMINI_API_KEY=cloud-only -- --dry-run --mode idle
equals "$RC" 0 "profile cloud may hold provider keys"
ep CS3_PROFILE=cloud ERROW_LLM_ROUTE=direct "LLM_API_KEY_FILE=${WORK}/secrets/provider_key" errow_LLM=gemini/gemini-2.5-pro -- --dry-run --mode idle
equals "$RC" 0 "cloud profile + direct route + key file accepted"
lacks "$OUT$ERR" "cloud-provider-key-do-not-leak" "direct-route key never printed"
ep CS3_PROFILE=cloud ERROW_LLM_ROUTE=direct -- --dry-run --mode idle
equals "$RC" 78 "direct route requires LLM_API_KEY_FILE"

echo "== target allow-list"
ep ERROW_ALLOWED_TARGETS='*.vendetta.lab,10.0.0.5' -- --dry-run --mode scan --target https://scan-target.vendetta.lab:8443/app
equals "$RC" 0 "target matching a glob is accepted"
ep ERROW_ALLOWED_TARGETS='*.vendetta.lab' -- --dry-run --mode scan --target https://evil.example.com
equals "$RC" 77 "target outside the allow-list => 77"

echo "== errow-config.yaml defaults and llm-providers.yaml policy"
CFG_DIR=$(cd -- "${HERE}/../config" && pwd)
HELPER=$(cd -- "${HERE}/.." && pwd)/stack-config.py
if python3 -c 'import yaml' 2>/dev/null; then
  PYBIN=$(command -v python3)
  CFG_ENV=("ERROW_PYTHON=${PYBIN}" "ERROW_CONFIG_HELPER=${HELPER}")
  printf '%s\n' 'version: 1' 'env:' '  ERROW_SCAN_MODE: standard' '  errow_MAX_CONTEXT_IMAGES: 2' 'profiles:' '  airgap:' '    env:' '      ERROW_SCAN_MODE: deep' >"${WORK}/cfg.yaml"
  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${WORK}/cfg.yaml" ERROW_TARGET=scan-target.vendetta.lab -- --dry-run --mode scan
  contains "$OUT" "--scan-mode standard" "config file supplies the default scan mode"
  contains "$OUT" "config file          loaded" "dry-run reports the loaded config file"
  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${WORK}/cfg.yaml" ERROW_SCAN_MODE=quick ERROW_TARGET=scan-target.vendetta.lab -- --dry-run --mode scan
  contains "$OUT" "--scan-mode quick" "the environment wins over the config file"
  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${WORK}/cfg.yaml" CS3_PROFILE=airgap ERROW_TARGET=scan-target.vendetta.lab -- --dry-run --mode scan
  contains "$OUT" "--scan-mode deep" "profile overlay applies"
  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${WORK}/absent.yaml" -- --dry-run --mode idle
  contains "$OUT" "config file          absent" "a missing config file is not an error"
  printf '%s\n' 'version: 1' 'env:' '  LLM_API_KEY: sk-not-allowed-here' >"${WORK}/bad.yaml"
  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${WORK}/bad.yaml" -- --dry-run --mode idle
  equals "$RC" 78 "a secret-like name in the config file => exit 78"
  lacks "$OUT$ERR" "sk-not-allowed-here" "rejected config value never echoed"
  printf '%s\n' 'version: 1' 'env: [' >"${WORK}/broken.yaml"
  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${WORK}/broken.yaml" -- --dry-run --mode idle
  equals "$RC" 78 "invalid YAML => exit 78"

  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${CFG_DIR}/errow-config.yaml" -- --dry-run --mode scan --target https://scan-target.vendetta.lab
  equals "$RC" 0 "the shipped errow-config.yaml loads"
  contains "$OUT" "--scan-mode quick" "shipped default scan mode is quick"
  ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${CFG_DIR}/errow-config.yaml" -- --dry-run --mode scan --target https://evil.example.com
  equals "$RC" 77 "the shipped config restricts targets to the lab domain"
  for prof in cloud onprem airgap edge; do
    ep ${CFG_ENV[@]+"${CFG_ENV[@]}"} "ERROW_CONFIG_FILE=${CFG_DIR}/errow-config.yaml" "CS3_PROFILE=${prof}" -- --dry-run --mode idle
    equals "$RC" 0 "the shipped errow-config.yaml is valid for profile ${prof}"
  done

  POLICY=("${CFG_ENV[@]}" "ERROW_LLM_PROVIDERS_FILE=${CFG_DIR}/llm-providers.yaml")
  ep ${POLICY[@]+"${POLICY[@]}"} -- --dry-run --mode idle
  equals "$RC" 0 "the security model passes the shipped llm-providers.yaml policy"
  ep ${POLICY[@]+"${POLICY[@]}"} OLLAMA_PRIMARY_MODEL=gemma4:31b -- --dry-run --mode idle
  equals "$RC" 0 "gemma4:31b is approved"
  ep ${POLICY[@]+"${POLICY[@]}"} OLLAMA_SECURITY_MODEL=llama3:8b -- --dry-run --mode idle
  equals "$RC" 0 "an unapproved security model degrades instead of refusing to start"
  contains "$ERR" "is not approved for profile 'onprem'" "the degraded warning names the model and profile"
  contains "$OUT" "openai/nemotron-3-nano:30b" "the degraded run falls back to the primary model"
  contains "$OUT" "DEGRADED" "the dry-run flags the degraded run"
  ep ${POLICY[@]+"${POLICY[@]}"} OLLAMA_SECURITY_MODEL=llama3:8b ERROW_MODEL_DEGRADED=true -- --dry-run --mode idle
  equals "$RC" 0 "an operator-declared degraded run still starts"
  ep ${POLICY[@]+"${POLICY[@]}"} errow_LLM=openai/llama3:8b -- --dry-run --mode idle
  equals "$RC" 78 "an explicitly unapproved model => exit 78"
  contains "$ERR" "is not approved for profile 'onprem'" "the policy violation names the model and profile"
  ep ${POLICY[@]+"${POLICY[@]}"} CS3_PROFILE=cloud OLLAMA_SECURITY_MODEL=llama3:8b ERROW_MODEL_DEGRADED=false -- --dry-run --mode idle
  equals "$RC" 0 "cloud degrades identically"
  ep ${POLICY[@]+"${POLICY[@]}"} CS3_PROFILE=cloud errow_LLM=openai/llama3:8b -- --dry-run --mode idle
  equals "$RC" 78 "the allow-list also applies to the gateway route of profile cloud"
else
  echo "  skip python3 without PyYAML: config/policy tests not run"
fi
ep -- --dry-run --mode idle
contains "$OUT" "errow_API_TYPE       chat_completions" "chat completions API forced (the gateway has no Responses API)"

echo "== scan mode: env passthrough, logging, exit code"
ep ERROW_TARGET=scan-target.vendetta.lab ERROW_SCAN_MODE=standard FAKE_EXIT=2 ERROW_TENANT_ID=acme -- --mode scan
equals "$RC" 2 "Errow's exit code is propagated"
contains "$OUT" "LLM_API_BASE=https://llm-gateway:9101/v1 STREAM=true MODEL=openai/nemotron-3-nano:30b TELEMETRY=false APP=http://127.0.0.1:9 KEYLEN=${#GW_TOKEN}" "Errow sees the gateway environment"
contains "$OUT" 'HDR={"X-Tenant-Id":"acme"}' "tenant header exported"
contains "$OUT" "token=REDACTED" "token= is redacted in the stream"
lacks "$OUT" "XYZ" "redacted value is gone from stdout"
LOG=$(<"${WORK}/log/cli.log")
contains "$LOG" "token=REDACTED" "cli.log carries the redacted stream"
lacks "$LOG" "$GW_TOKEN" "cli.log has no bearer token"
contains "$(<"${WORK}/fake.log")" "ARGS:--non-interactive --target scan-target.vendetta.lab --scan-mode standard" "flags filled from env"
ep -- --target a.vendetta.lab --scan-mode deep --fail-on high
contains "$(<"${WORK}/fake.log")" "ARGS:--non-interactive --target a.vendetta.lab --scan-mode deep --fail-on high" "explicit flags win over env"
ep ERROW_INSTRUCTION_FILE="${WORK}/missing.md" ERROW_TARGET=x -- --mode scan
equals "$RC" 66 "unreadable instruction file => 66"
ep ERROW_WORKDIR="${WORK}/nowhere/deeper" ERROW_TARGET=x -- --mode scan
equals "$RC" 0 "missing workdir is created (idempotent bring-up)"
if [[ -d ${WORK}/nowhere/deeper/errow_runs ]]; then pass "errow_runs created"; else fail "errow_runs created"; fi

echo "== TCP helpers for health checks"
PORT_PY='import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(8)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    c.close()'
python3 -c "$PORT_PY" >"${WORK}/port" &
BG_PIDS+=("$!")
for _ in $(seq 1 50); do if [[ -s ${WORK}/port ]]; then break; fi; sleep 0.1; done
PORT=$(<"${WORK}/port")
ep "LLM_GATEWAY_URL=http://127.0.0.1:${PORT}" -- --healthcheck
equals "$RC" 0 "idle healthcheck passes with DinD up and the gateway reachable"
ep "LLM_GATEWAY_URL=http://127.0.0.1:1" -- --healthcheck
equals "$RC" 1 "idle healthcheck fails when the gateway is unreachable"
ep "LLM_GATEWAY_URL=http://127.0.0.1:${PORT}" GEMINI_API_KEY=x -- --healthcheck
equals "$RC" 1 "healthcheck fails closed on a cloud key"
ep ERROW_MODE=view -- --healthcheck
equals "$RC" 1 "view healthcheck fails before the viewer reports a state"

echo "== view mode: wait, serve, redact, follow, stop"
ep -- --print-viewer-link
equals "$RC" 66 "no viewer link before the viewer has served"
env -i "${BASE_ENV[@]}" "ERROW_VIEWER_PORT=${PORT}" ERROW_VIEWER_POLL=1 ERROW_VIEWER_MIN_RESTART=0 bash "$EP" --mode view >"${WORK}/view.out" 2>"${WORK}/view.err" &
VIEW_PID=$!
BG_PIDS+=("$VIEW_PID")
for _ in $(seq 1 50); do if grep -q waiting "${WORK}/state/viewer.state" 2>/dev/null; then break; fi; sleep 0.1; done
ep ERROW_MODE=view "ERROW_VIEWER_PORT=${PORT}" -- --healthcheck
equals "$RC" 0 "view healthcheck is green while waiting for the first run"
mkdir -p "${WORK}/ws/errow_runs/run-one"
printf '{"run_name":"run-one"}\n' >"${WORK}/ws/errow_runs/run-one/run.json"
ago "${WORK}/ws/errow_runs/run-one/run.json"
for _ in $(seq 1 100); do if [[ -s ${WORK}/state/viewer-link ]]; then break; fi; sleep 0.1; done
ep -- --print-viewer-link
equals "$OUT" "http://127.0.0.1:8765/?token=SeCrEt-Tok_123" "--print-viewer-link returns the authorised link"
equals "$(mode_of "${WORK}/state/viewer-link")" 600 "viewer link file is 0600"
ep ERROW_MODE=view "ERROW_VIEWER_PORT=${PORT}" -- --healthcheck
equals "$RC" 0 "view healthcheck passes while serving"
contains "$(<"${WORK}/fake.log")" "ARGS:view run-one --host 0.0.0.0 --port ${PORT} --no-open" "viewer started on the newest run"
mkdir -p "${WORK}/ws/errow_runs/run-two"
printf '{"run_name":"run-two"}\n' >"${WORK}/ws/errow_runs/run-two/run.json"
for _ in $(seq 1 100); do if grep -q 'ARGS:view run-two' "${WORK}/fake.log"; then break; fi; sleep 0.1; done
contains "$(<"${WORK}/fake.log")" "ARGS:view run-two" "viewer follows the newest run"
kill -TERM "$VIEW_PID"
VIEW_RC=0
wait "$VIEW_PID" || VIEW_RC=$?
equals "$VIEW_RC" 0 "SIGTERM stops the viewer cleanly (exit 0)"
lacks "$(<"${WORK}/view.out")" "SeCrEt-Tok_123" "container stdout never shows the session token"
lacks "$(<"${WORK}/log/cli.log")" "SeCrEt-Tok_123" "cli.log never shows the session token"
contains "$(<"${WORK}/log/cli.log")" "token=REDACTED" "cli.log shows the redacted link"
if compgen -G "${WORK}/state/cli.*.fifo" >/dev/null; then fail "fifo cleaned up"; else pass "fifo cleaned up"; fi

echo "== idle mode stops on SIGTERM"
env -i "${BASE_ENV[@]}" bash "$EP" --mode idle >/dev/null 2>"${WORK}/idle.err" &
IDLE_PID=$!
BG_PIDS+=("$IDLE_PID")
for _ in $(seq 1 50); do if grep -q 'ready (profile' "${WORK}/idle.err" 2>/dev/null; then break; fi; sleep 0.1; done
kill -TERM "$IDLE_PID"
IDLE_RC=0
wait "$IDLE_PID" || IDLE_RC=$?
equals "$IDLE_RC" 0 "idle exits 0 on SIGTERM"

printf '\n%d assertions passed\n' "$PASS"
