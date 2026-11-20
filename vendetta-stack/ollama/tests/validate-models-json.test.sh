#!/usr/bin/env bash
#
# validate-models-json.test.sh — exercises scripts/validate-models-json.sh against
# temp copies of ollama/models.json, including every negative path and exit code.
#
# Traces: CONTRACT §0 / §10 (models.json rules enforced in CI).
# Usage:  ollama/tests/validate-models-json.test.sh        (TMPDIR is honoured)
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$(cd "${HERE}/../.." && pwd)"
VALIDATOR="${STACK}/scripts/validate-models-json.sh"
SOURCE_JSON="${STACK}/ollama/models.json"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0
FAILED=0
HEX64="$(printf 'a%.0s' {1..64})"

# expect <exit-code> <description> <jq-mutation> [validator flags...]
expect() {
  local want="$1" desc="$2" mutation="$3"
  shift 3
  local file="${WORK}/case.json"
  jq "$mutation" "$SOURCE_JSON" >"$file"
  local got=0
  "$VALIDATOR" --file "$file" "$@" >/dev/null 2>&1 || got=$?
  if [[ "$got" -eq "$want" ]]; then
    PASS=$((PASS + 1)); printf 'ok   - %s\n' "$desc"
  else
    FAILED=$((FAILED + 1)); printf 'FAIL - %s (want exit %s, got %s)\n' "$desc" "$want" "$got"
  fi
}

expect_raw() {
  local want="$1" desc="$2"
  shift 2
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  if [[ "$got" -eq "$want" ]]; then
    PASS=$((PASS + 1)); printf 'ok   - %s\n' "$desc"
  else
    FAILED=$((FAILED + 1)); printf 'FAIL - %s (want exit %s, got %s)\n' "$desc" "$want" "$got"
  fi
}

PIN_ALL=".models |= map(.sha256 = \"${HEX64}\")"

expect_raw 0 "shipped models.json passes in default mode" "$VALIDATOR"
expect_raw 0 "shipped models.json is fully pinned and passes --release" "$VALIDATOR" --release
expect 0 "all sha256 pinned passes under --release" "$PIN_ALL" --release
expect 0 "sentinel is allowed outside --release" '.' 
expect 0 "uppercase hex digest is accepted" ".models[0].sha256 = \"${HEX64^^}\""
expect 8 "a single remaining sentinel fails --release" "${PIN_ALL} | .models[1].sha256 = \"<pinned-per-release>\"" --release

for key in id family variant activeParams minVramGb functionCalling multimodal sha256; do
  expect 4 "missing mandatory key ${key}" "del(.models[1].${key})"
done
expect 4 "minVramGb as string" '.models[0].minVramGb = "16"'
expect 4 "minVramGb as float" '.models[0].minVramGb = 16.5'
expect 4 "minVramGb zero" '.models[0].minVramGb = 0'
expect 4 "functionCalling as string" '.models[0].functionCalling = "true"'
expect 4 "multimodal as integer" '.models[2].multimodal = 0'
expect 4 "thinkingModeConfigurable as string" '.models[2].thinkingModeConfigurable = "yes"'
expect 4 "minSystemRamGb negative" '.models[0].minSystemRamGb = -1'
expect 4 "empty family" '.models[0].family = ""'
expect 4 "model entry is not an object" '.models[0] = "gemma4:26b"'
expect 4 "models not an array" '.models = {}'
expect 4 "releaseTag not semver" '.releaseTag = "latest"'
expect 4 "updated not a date" '.updated = "yesterday"'

expect 5 "unapproved extra model tag" '.models += [.models[0] | .id = "llama3:8b"] | .tiers.entry.models += ["llama3:8b"]'
expect 5 "approved model removed" '.models |= map(select(.id != "gemma4:31b")) | .tiers.frontier.models = []'
expect 5 "duplicate model id" '.models += [.models[0]]'
expect 5 "renamed tag (gemma4:26b -> gemma4:27b)" '.models[0].id = "gemma4:27b" | .tiers.entry.models = ["gemma4:27b"]'
expect 0 "--approved override changes the accepted set" '.' --approved "gemma4:26b,gemma4:31b,nemotron-3-nano:30b,qwensploit-v2:9b"
expect 5 "--approved override rejects shipped set" '.' --approved "gemma4:26b"
expect 5 "the security model is approved by default" '.' --approved "gemma4:26b,gemma4:31b,nemotron-3-nano:30b"

expect 6 "tier references unknown model" '.tiers.entry.models += ["ghost:1b"]'
expect 6 "model missing from every tier" '.tiers.frontier.models = []'
expect 6 "model listed in two tiers" '.tiers.entry.models += ["gemma4:31b"]'
expect 6 "model.tier disagrees with tier lists" '.models[0].tier = "agentic"'
expect 6 "model.tier names a nonexistent tier" '.models[0].tier = "platinum"'
expect 6 "tier without label" 'del(.tiers.entry.label)'

expect 7 "sha256 too short" '.models[0].sha256 = "abc123"'
expect 7 "sha256 63 hex characters" ".models[0].sha256 = \"${HEX64:1}\""
expect 7 "sha256 non-hex" ".models[0].sha256 = \"${HEX64/a/g}\""
expect 7 "sha256 with sha256: prefix" ".models[0].sha256 = \"sha256:${HEX64}\""
expect 7 "sha256 almost-sentinel" '.models[0].sha256 = "<pinned-per-release >"'

printf '%s' '{ "releaseTag": ' >"${WORK}/broken.json"
expect_raw 3 "invalid JSON exits 3" "$VALIDATOR" --file "${WORK}/broken.json"
expect_raw 2 "missing file exits 2" "$VALIDATOR" --file "${WORK}/nope.json"
expect_raw 2 "unknown flag exits 2" "$VALIDATOR" --bogus
expect_raw 2 "--file without value exits 2" "$VALIDATOR" --file
expect_raw 0 "--help exits 0" "$VALIDATOR" --help

jq '.models[0].sha256 = "nothex"' "$SOURCE_JSON" >"${WORK}/report.json"
REPORT="$("$VALIDATOR" --file "${WORK}/report.json" --json 2>/dev/null || true)"
if [[ "$(jq -r '.exitCode' <<<"$REPORT")" == "7" && "$(jq -r '.ok' <<<"$REPORT")" == "false" && "$(jq '.errors | length' <<<"$REPORT")" -ge 1 ]]; then
  PASS=$((PASS + 1)); echo "ok   - --json report is machine readable (exitCode 7, errors listed)"
else
  FAILED=$((FAILED + 1)); echo "FAIL - --json report malformed: ${REPORT}"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAILED"
[[ "$FAILED" -eq 0 ]]
