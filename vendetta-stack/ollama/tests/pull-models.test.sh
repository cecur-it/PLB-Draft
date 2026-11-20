#!/usr/bin/env bash
#
# pull-models.test.sh — behavioural tests for ollama/pull-models.sh and ollama/entrypoint.sh.
# A stub `ollama` CLI (state kept in a throw-away directory) records every call, so the tests can
# assert what was — and, above all, what was NOT — executed: the airgap profile must never pull.
#
# Traces: PROMPT §1 Tier 4 (approved models only), PROMPT §3 (air-gap, digest verification),
#         CONTRACT §8.2 (preload per profile), CONTRACT §10 (sentinel refused in --release).
# Usage: ollama/tests/pull-models.test.sh [--help]
# shellcheck disable=SC2015  # `cond && ok || bad` is intentional: ok/bad always return 0
set -euo pipefail
set -o errtrace
IFS=$'\n\t'
trap 'echo "TEST HARNESS ERROR at line $LINENO" >&2' ERR

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' -e '/^#$/s/^#//'
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OLLAMA_DIR="$(cd "$HERE/.." && pwd)"
PULL="$OLLAMA_DIR/pull-models.sh"
ENTRY="$OLLAMA_DIR/entrypoint.sh"
for dep in jq sha256sum; do
  command -v "$dep" >/dev/null 2>&1 || { echo "missing dependency: $dep" >&2; exit 2; }
done

mkdir -p "${TMPDIR:-/var/tmp}"
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cs3-pull-test.XXXXXX")"
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

PASS=0
FAIL=0
OUT=""
RC=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
run_cmd() { OUT="$("$@" 2>&1)" && RC=0 || RC=$?; }
expect_rc() {
  local name="$1" want="$2"; shift 2
  run_cmd "$@"
  if [[ "$RC" -eq "$want" ]]; then ok "$name (rc=$RC)"; else bad "$name (wanted rc=$want, got $RC)"; printf '%s\n' "$OUT" | sed 's/^/       | /'; fi
}
out_has() { if grep -qF -- "$2" <<<"$OUT"; then ok "$1"; else bad "$1 (output lacks: $2)"; printf '%s\n' "$OUT" | sed 's/^/       | /'; fi; }
out_lacks() { if grep -qF -- "$2" <<<"$OUT"; then bad "$1 (output has: $2)"; else ok "$1"; fi; }
calls_has() { if grep -qxF -- "$2" "$STATE/calls" 2>/dev/null; then ok "$1"; else bad "$1 (no call: $2)"; sed 's/^/       | /' "$STATE/calls" 2>/dev/null || true; fi; }
calls_lack() { if grep -qE -- "$2" "$STATE/calls" 2>/dev/null; then bad "$1 (unexpected call matching: $2)"; else ok "$1"; fi; }

# --- stub ollama -----------------------------------------------------------------------------
cat >"$T/ollama" <<'STUB'
#!/usr/bin/env bash
# Stub of the ollama CLI. STUB_STATE holds: calls (log), models/<safe> (digest per stored model), serving.
set -euo pipefail
S="${STUB_STATE:?}"
mkdir -p "$S/models"
safe() { printf '%s' "${1//:/_}"; }
echo "$*" >>"$S/calls"
case "${1:-}" in
  serve)
    touch "$S/serving"
    echo "$$" >"$S/serve.pid"
    trap 'rm -f "$S/serving"; exit 0' TERM INT
    while true; do sleep 0.1; done ;;
  list)
    [[ "${STUB_NEEDS_SERVE:-0}" != "1" || -e "$S/serving" ]] || exit 1
    printf 'NAME ID SIZE MODIFIED\n'
    for f in "$S"/models/*; do
      [[ -e "$f" ]] || continue
      printf '%s abc 1GB now\n' "$(basename "$f" | sed 's/_/:/')"
    done ;;
  pull)
    [[ "${STUB_PULL_FAIL:-0}" != "1" ]] || { echo "pull failed" >&2; exit 1; }
    printf '%s' "${STUB_PULL_DIGEST:?}" >"$S/models/$(safe "$2")" ;;
  create)
    from="$(sed -n 's/^FROM //p' "$4" | head -n1)"
    cp "$4" "$S/created-$(safe "$2").Modelfile"
    printf '%s' "${STUB_CREATE_DIGEST:-$(sha256sum "$from" | awk '{print $1}')}" >"$S/models/$(safe "$2")" ;;
  show)
    [[ -e "$S/models/$(safe "$3")" ]] || exit 1
    printf 'FROM /var/lib/cs3-ollama/.ollama/models/blobs/sha256-%s\nPARAMETER num_ctx 16384\n' "$(cat "$S/models/$(safe "$3")")" ;;
  *) echo "stub: unsupported $*" >&2; exit 1 ;;
esac
STUB
chmod +x "$T/ollama"

new_state() { STATE="$T/state-$1"; rm -rf "$STATE"; mkdir -p "$STATE"; export STUB_STATE="$STATE"; : >"$STATE/calls"; }
unset OLLAMA_PRELOAD_MODELS OLLAMA_AIRGAP_BUNDLE_DIR CS3_RELEASE CS3_PROFILE OLLAMA_PRIMARY_MODEL OLLAMA_FALLBACK_MODEL OLLAMA_SECURITY_MODEL INFERENCE_MODEL_REASONING_DEEP
export OLLAMA_BIN="$T/ollama" OLLAMA_PULL_RETRIES=2 STUB_PULL_DIGEST="" STUB_NEEDS_SERVE=0
STATE=""

# --- fixtures --------------------------------------------------------------------------------
mkdir -p "$T/bundle"
printf 'fake gemma4 26b weights\n' >"$T/bundle/gemma4_26b.gguf"
printf 'fake nemotron weights\n' >"$T/bundle/nemotron-3-nano_30b.gguf"
G26="$(sha256sum "$T/bundle/gemma4_26b.gguf" | awk '{print $1}')"
NEM="$(sha256sum "$T/bundle/nemotron-3-nano_30b.gguf" | awk '{print $1}')"
G31="$(printf 'g31' | sha256sum | awk '{print $1}')"
jq --arg a "$G26" --arg b "$NEM" --arg c "$G31" \
  '(.models[] | select(.id == "gemma4:26b")).sha256 = $a | (.models[] | select(.id == "nemotron-3-nano:30b")).sha256 = $b | (.models[] | select(.id == "gemma4:31b")).sha256 = $c' \
  "$OLLAMA_DIR/models.json" >"$T/models.pinned.json"
jq '(.models[] | select(.id == "gemma4:26b")).sha256 = "<pinned-per-release>"' \
  "$OLLAMA_DIR/models.json" >"$T/models.sentinel.json"
PINNED=(--models-json "$T/models.pinned.json")
SENTINEL=(--models-json "$T/models.sentinel.json")

echo "== resolution =="
run_cmd "$PULL" --print-models "${PINNED[@]}"
[[ "$OUT" == $'nemotron-3-nano:30b\ngemma4:26b\ngemma4:31b' ]] && ok "default = primary, fallback, security, then deep fallback (deduped)" || { bad "default resolution"; echo "$OUT"; }
run_cmd "$PULL" --print-models --profile edge "${PINNED[@]}"
[[ "$OUT" == $'gemma4:26b\nnemotron-3-nano:30b\ngemma4:31b' ]] && ok "edge profile = fallback, security, then deep fallback" || bad "edge resolution: $OUT"
run_cmd "$PULL" --print-models --models all "${PINNED[@]}"
[[ "$(wc -l <<<"$OUT")" -eq 4 ]] && ok "'all' = the 4 approved models" || bad "all resolution: $OUT"
run_cmd "$PULL" --print-models --models none "${PINNED[@]}"
[[ -z "$OUT" ]] && ok "'none' = nothing" || bad "none resolution: $OUT"
run_cmd "$PULL" --print-models --models 'gemma4:31b, gemma4:31b' "${PINNED[@]}"
[[ "$OUT" == "gemma4:31b" ]] && ok "CSV is trimmed and de-duplicated" || bad "csv resolution: $OUT"
OLLAMA_PRELOAD_MODELS=gemma4:31b run_cmd "$PULL" --print-models "${PINNED[@]}"
[[ "$OUT" == "gemma4:31b" ]] && ok "OLLAMA_PRELOAD_MODELS honoured" || bad "env resolution: $OUT"

echo "== policy: approved tags only =="
expect_rc "unapproved tag is refused" 3 "$PULL" --print-models --models 'llama3:8b' "${PINNED[@]}"
out_has "refusal names the tag" "'llama3:8b' is not an approved model tag"
expect_rc "unknown profile" 2 "$PULL" --profile lab --print-models "${PINNED[@]}"
expect_rc "unknown flag" 2 "$PULL" --frobnicate
expect_rc "missing models.json" 2 "$PULL" --print-models --models-json "$T/nope.json"
expect_rc "--help" 0 "$PULL" --help
out_has "help lists --bundle-dir" "--bundle-dir"

echo "== connected profile: pull =="
new_state pull
export STUB_PULL_DIGEST="$G26"
expect_rc "pull gemma4:26b (pinned, digest ok)" 0 "$PULL" --profile onprem --models gemma4:26b "${PINNED[@]}"
calls_has "ollama pull issued" "pull gemma4:26b"
expect_rc "second run is idempotent" 0 "$PULL" --profile onprem --models gemma4:26b "${PINNED[@]}"
out_has "already-present message" "already present"
[[ "$(grep -c '^pull ' "$STATE/calls")" -eq 1 ]] && ok "no second pull" || bad "pull repeated"

EVIL_SHA="$(printf 'evil' | sha256sum | awk '{print $1}')"
OTHER_SHA="$(printf 'other' | sha256sum | awk '{print $1}')"
new_state mismatch
export STUB_PULL_DIGEST="$EVIL_SHA"
expect_rc "pulled weights with the wrong digest" 3 "$PULL" --profile cloud --models gemma4:26b "${PINNED[@]}"
out_has "mismatch explained" "do not match the pinned SHA-256"

new_state sentinel-dev
export STUB_PULL_DIGEST="anything"
expect_rc "sentinel is tolerated in development" 0 "$PULL" --profile onprem --models gemma4:26b "${SENTINEL[@]}"
out_has "unpinned warning" "NOT integrity-checked"
new_state sentinel-rel
expect_rc "sentinel + --release is refused" 3 "$PULL" --profile onprem --release --models gemma4:26b "${SENTINEL[@]}"
out_has "sentinel named" "<pinned-per-release>"
calls_lack "nothing pulled under refusal" '^pull '
CS3_RELEASE=true expect_rc "CS3_RELEASE=true also refuses the sentinel" 3 "$PULL" --profile cloud --models gemma4:26b "${SENTINEL[@]}"

new_state retry
export STUB_PULL_FAIL=1
expect_rc "pull failure gives rc 1 after retries" 1 env OLLAMA_PULL_RETRIES=1 "$PULL" --profile onprem --models gemma4:26b "${PINNED[@]}"
unset STUB_PULL_FAIL

new_state dry
expect_rc "dry-run" 0 "$PULL" --profile onprem --dry-run --models gemma4:26b "${PINNED[@]}"
out_has "dry-run announces the pull" "[dry-run]"
calls_lack "dry-run pulls nothing" '^pull '

echo "== airgap profile: load, verify, never pull =="
new_state airgap
expect_rc "airgap load of two models" 0 "$PULL" --profile airgap --bundle-dir "$T/bundle" --models gemma4:26b,nemotron-3-nano:30b "${PINNED[@]}"
grep -q '^create gemma4:26b -f .*gemma4_26b.Modelfile$' "$STATE/calls" && ok "gemma4:26b registered with ollama create" || bad "ollama create missing"
calls_lack "airgap never pulls" '^pull '
head -n1 "$STATE/created-gemma4_26b.Modelfile" | grep -qxF "FROM $T/bundle/gemma4_26b.gguf" && ok "Modelfile starts with FROM <verified gguf>" || bad "Modelfile FROM line"
grep -qx 'PARAMETER num_ctx 16384' "$STATE/created-gemma4_26b.Modelfile" && ok "packaged parameters appended" || bad "packaged parameters missing"
[[ "$(grep -c '^FROM ' "$STATE/created-gemma4_26b.Modelfile")" -eq 1 ]] && ok "exactly one FROM line" || bad "FROM count"
expect_rc "airgap re-run is idempotent" 0 "$PULL" --profile airgap --bundle-dir "$T/bundle" --models gemma4:26b "${PINNED[@]}"
out_has "skip message" "already loaded with the pinned weights"
[[ "$(grep -c '^create ' "$STATE/calls")" -eq 2 ]] && ok "no re-create" || bad "create repeated"

new_state airgap-env
OLLAMA_AIRGAP_BUNDLE_DIR="$T/bundle" CS3_PROFILE=airgap expect_rc "bundle dir and profile from the environment" 0 "$PULL" --models gemma4:26b "${PINNED[@]}"

new_state airgap-sentinel
expect_rc "airgap + sentinel digest is refused" 3 "$PULL" --profile airgap --bundle-dir "$T/bundle" --models gemma4:26b "${SENTINEL[@]}"
calls_lack "nothing created or pulled" '^(create|pull) '

new_state airgap-tamper
mkdir -p "$T/bundle-bad"
printf 'tampered weights\n' >"$T/bundle-bad/gemma4_26b.gguf"
expect_rc "tampered GGUF (sha256 mismatch)" 3 "$PULL" --profile airgap --bundle-dir "$T/bundle-bad" --models gemma4:26b "${PINNED[@]}"
out_has "mismatch shows expected and actual" "SHA-256 mismatch"
calls_lack "tampered blob is never registered" '^create '

new_state airgap-missing
expect_rc "bundle lacks the model" 1 "$PULL" --profile airgap --bundle-dir "$T/bundle" --models gemma4:31b "${PINNED[@]}"
out_has "missing GGUF named" "no GGUF in"
expect_rc "airgap without bundle dir" 1 "$PULL" --profile airgap --models gemma4:26b "${PINNED[@]}"
out_has "bundle dir required" "OLLAMA_AIRGAP_BUNDLE_DIR"

new_state airgap-blob
mkdir -p "$T/bundle-blob/blobs"
cp "$T/bundle/gemma4_26b.gguf" "$T/bundle-blob/blobs/sha256-$G26"
expect_rc "content-addressed blobs/sha256-<digest> layout" 0 "$PULL" --profile airgap --bundle-dir "$T/bundle-blob" --models gemma4:26b "${PINNED[@]}"

new_state airgap-modelfile
mkdir -p "$T/bundle-mf"
cp "$T/bundle/gemma4_26b.gguf" "$T/bundle-mf/"
printf 'FROM ./ignored.gguf\nPARAMETER num_ctx 4096\nSYSTEM "bundle"\n' >"$T/bundle-mf/gemma4_26b.Modelfile"
expect_rc "bundle Modelfile overrides the packaged one" 0 "$PULL" --profile airgap --bundle-dir "$T/bundle-mf" --models gemma4:26b "${PINNED[@]}"
grep -qx 'PARAMETER num_ctx 4096' "$STATE/created-gemma4_26b.Modelfile" && ok "bundle parameters used" || bad "bundle parameters missing"
grep -q 'ignored.gguf' "$STATE/created-gemma4_26b.Modelfile" && bad "bundle FROM line must be dropped" || ok "bundle FROM line dropped"

new_state airgap-badregister
export STUB_CREATE_DIGEST="$OTHER_SHA"
expect_rc "registered model not referencing the verified blob" 3 "$PULL" --profile airgap --bundle-dir "$T/bundle" --models gemma4:26b "${PINNED[@]}"
unset STUB_CREATE_DIGEST

new_state airgap-dry
expect_rc "airgap dry-run verifies but registers nothing" 0 "$PULL" --profile airgap --bundle-dir "$T/bundle" --dry-run --models gemma4:26b "${PINNED[@]}"
calls_lack "dry-run creates nothing" '^(create|pull) '

echo "== entrypoint =="
export STUB_NEEDS_SERVE=1 PULL_MODELS_BIN="$PULL" OLLAMA_MODELS_JSON="$T/models.pinned.json" OLLAMA_MODELFILES_DIR="$OLLAMA_DIR/modelfiles" OLLAMA_READY_TIMEOUT=20
new_state ep-pass
expect_rc "non-serve arguments are passed to the CLI (stub: unknown model -> 1)" 1 "$ENTRY" show --modelfile nothing-here-yet
calls_has "CLI got the arguments verbatim" "show --modelfile nothing-here-yet"
expect_rc "unknown profile rejected" 2 env CS3_PROFILE=lab "$ENTRY" serve

new_state ep-health
expect_rc "healthcheck fails while the server is down" 1 env OLLAMA_PRELOAD_MODELS=gemma4:26b "$ENTRY" --healthcheck
touch "$STATE/serving"
expect_rc "healthcheck fails while the model is missing" 1 env OLLAMA_PRELOAD_MODELS=gemma4:26b "$ENTRY" --healthcheck
printf '%s' "$G26" >"$STATE/models/gemma4_26b"
expect_rc "healthcheck passes with server up and model present" 0 env OLLAMA_PRELOAD_MODELS=gemma4:26b "$ENTRY" --healthcheck

new_state ep-serve
export STUB_PULL_DIGEST="$G26"
( OLLAMA_PRELOAD_MODELS=gemma4:26b CS3_PROFILE=onprem "$ENTRY" serve >"$T/ep-serve.log" 2>&1; echo "$?" >"$T/ep-serve.rc" ) &
EP_PID=$!
for _ in $(seq 1 100); do [[ -e "$STATE/models/gemma4_26b" ]] && break; sleep 0.1; done
if [[ -e "$STATE/models/gemma4_26b" ]]; then ok "serve provisions the preload model after the server is ready"; else bad "serve never pulled"; sed 's/^/       | /' "$T/ep-serve.log"; fi
calls_has "serve started" "serve"
stop_stub_server() { [[ ! -e "$STATE/serve.pid" ]] || kill -TERM "$(cat "$STATE/serve.pid")" 2>/dev/null || true; }
stop_stub_server
for _ in $(seq 1 100); do [[ -e "$T/ep-serve.rc" ]] && break; sleep 0.1; done
[[ -e "$T/ep-serve.rc" ]] && ok "entrypoint exits when ollama serve stops (rc=$(cat "$T/ep-serve.rc"))" || { bad "entrypoint did not exit"; kill -TERM "$EP_PID" 2>/dev/null || true; }
wait "$EP_PID" 2>/dev/null || true

new_state ep-airgap
export STUB_PULL_DIGEST="must-never-be-used"
( OLLAMA_PRELOAD_MODELS=gemma4:26b CS3_PROFILE=airgap OLLAMA_AIRGAP_BUNDLE_DIR="$T/bundle" "$ENTRY" serve >"$T/ep-air.log" 2>&1; echo "$?" >"$T/ep-air.rc" ) &
EP_PID=$!
for _ in $(seq 1 100); do [[ -e "$STATE/models/gemma4_26b" ]] && break; sleep 0.1; done
[[ -e "$STATE/models/gemma4_26b" ]] && ok "airgap serve loads the bundle model" || { bad "airgap serve never created the model"; sed 's/^/       | /' "$T/ep-air.log"; }
calls_lack "airgap serve never pulls" '^pull '
grep -q '^create gemma4:26b ' "$STATE/calls" && ok "airgap serve ran ollama create" || bad "airgap serve skipped ollama create"
stop_stub_server
for _ in $(seq 1 100); do [[ -e "$T/ep-air.rc" ]] && break; sleep 0.1; done
wait "$EP_PID" 2>/dev/null || true

new_state ep-airgap-nobundle
export STUB_PULL_DIGEST="must-never-be-used"
( OLLAMA_PRELOAD_MODELS=gemma4:26b CS3_PROFILE=airgap "$ENTRY" serve >"$T/ep-nb.log" 2>&1; echo "$?" >"$T/ep-nb.rc" ) &
EP_PID=$!
for _ in $(seq 1 100); do grep -q 'never pulling' "$T/ep-nb.log" 2>/dev/null && break; sleep 0.1; done
grep -q 'never pulling' "$T/ep-nb.log" && ok "airgap without a bundle only serves what is stored" || bad "airgap no-bundle message missing"
calls_lack "no pull and no create without a bundle" '^(pull|create) '
stop_stub_server
for _ in $(seq 1 100); do [[ -e "$T/ep-nb.rc" ]] && break; sleep 0.1; done
wait "$EP_PID" 2>/dev/null || true

new_state ep-integrity
export STUB_PULL_DIGEST="$EVIL_SHA"
expect_rc "integrity failure is fatal even when not strict" 3 env OLLAMA_PRELOAD_MODELS=gemma4:26b OLLAMA_PRELOAD_STRICT=false "$ENTRY" serve
sleep 0.3
[[ ! -e "$STATE/serving" ]] && ok "server stopped after the fatal integrity failure" || bad "ollama serve left running"

new_state ep-nonstrict
export STUB_PULL_FAIL=1 OLLAMA_PULL_RETRIES=1
( OLLAMA_PRELOAD_MODELS=gemma4:26b OLLAMA_PRELOAD_STRICT=false "$ENTRY" serve >"$T/ep-ns.log" 2>&1; echo "$?" >"$T/ep-ns.rc" ) &
EP_PID=$!
for _ in $(seq 1 100); do grep -q 'keeps running' "$T/ep-ns.log" 2>/dev/null && break; sleep 0.1; done
grep -q 'keeps running' "$T/ep-ns.log" && ok "non-strict mode keeps serving after a failed pull" || { bad "non-strict message missing"; sed 's/^/       | /' "$T/ep-ns.log"; }
[[ -e "$STATE/serving" ]] && ok "server still up" || bad "server not up"
stop_stub_server
for _ in $(seq 1 100); do [[ -e "$T/ep-ns.rc" ]] && break; sleep 0.1; done
wait "$EP_PID" 2>/dev/null || true
unset STUB_PULL_FAIL

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
