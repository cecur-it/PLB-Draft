#!/usr/bin/env bash
#
# validate-models-json.sh — CI gate for ollama/models.json, the single source of
# truth for the approved on-prem / air-gapped model tags.
#
# Traces: PROMPT §1 Tier 4 (sovereign LLM tier, approved models only),
#         PROMPT §2.4 (model → role → node), CONTRACT §0 (sha256 sentinel rule)
#         and §10 (models.json format, mirrors CS3 onboarding/models.json).
#
# Checks (every violation is reported, the exit code names the first failing
# category in the order listed below):
#   3  file is not valid JSON
#   4  schema: 8 mandatory keys on every model + value types (strings, int, bool)
#   5  approved set: tag set is EXACTLY the approved set, no duplicates
#   6  tiers: every tier reference resolves and each model sits in its own tier
#   7  sha256 is neither 64 hex characters nor the "<pinned-per-release>" sentinel
#   8  --release only: at least one model still carries the sentinel
# Other exit codes: 0 pass, 2 usage error / missing dependency / unreadable file.
#
# Usage:
#   scripts/validate-models-json.sh [--file <models.json>] [--release] [--approved <csv>] [--json]
#   scripts/validate-models-json.sh --help
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly SENTINEL="<pinned-per-release>"
readonly DEFAULT_APPROVED="gemma4:26b,gemma4:31b,nemotron-3-nano:30b,qwensploit-v2:9b"

FILE="$(cd "${SCRIPT_DIR}/../ollama" && pwd)/models.json"
APPROVED="${DEFAULT_APPROVED}"
RELEASE="false"
JSON_OUTPUT="false"

if [[ -t 2 ]]; then C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_RST=$'\033[0m'; else C_RED=""; C_GRN=""; C_RST=""; fi
fail() { printf '%s[validate-models-json][FAIL]%s %s\n' "$C_RED" "$C_RST" "$1" >&2; }
ok()   { printf '%s[validate-models-json][PASS]%s %s\n' "$C_GRN" "$C_RST" "$1" >&2; }

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' -e '/^#$/s/^#//'
}

die_usage() { fail "$1"; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)     [[ $# -ge 2 ]] || die_usage "--file needs a path"; FILE="$2"; shift 2 ;;
    --approved)    [[ $# -ge 2 ]] || die_usage "--approved needs a comma-separated tag list"; APPROVED="$2"; shift 2 ;;
    --release)     RELEASE="true"; shift ;;
    --json)        JSON_OUTPUT="true"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             die_usage "unknown argument: $1 (see --help)" ;;
  esac
done

command -v jq >/dev/null 2>&1 || die_usage "jq is required"
[[ -r "$FILE" ]] || die_usage "cannot read $FILE"

if ! jq empty "$FILE" 2>/dev/null; then
  fail "$FILE is not valid JSON"
  if [[ "$JSON_OUTPUT" == "true" ]]; then
    jq -n --arg file "$FILE" '{ok:false,file:$file,errors:[{category:"parse",message:"not valid JSON"}]}'
  fi
  exit 3
fi

# One jq program emits every violation as {category,message}.
JQ_RULES="$(cat <<'JQ'
def err($cat; $msg): {category: $cat, message: $msg};
def is_str: type == "string" and length > 0;
def is_posint: type == "number" and . == floor and . >= 1;
def is_nonnegint: type == "number" and . == floor and . >= 0;
def mandatory: ["id","family","variant","activeParams","minVramGb","functionCalling","multimodal","sha256"];

(if type == "object" then . else {} end) as $r
| ([$r.models[]? | select(type == "object") | .id | select(is_str)]) as $ids
| ($approved | split(",") | map(select(length > 0)) | unique) as $allowed
| [
    (if type != "object" then err("schema"; "top level must be a JSON object") else empty end),

    (["releaseTag","updated","description"][] as $k
     | select(($r[$k] | is_str) | not)
     | err("schema"; "top-level \($k) must be a non-empty string")),
    (select(($r.releaseTag | type) == "string" and ($r.releaseTag | test("^v[0-9]+\\.[0-9]+\\.[0-9]+([-+][0-9A-Za-z.-]+)?$") | not))
     | err("schema"; "releaseTag \($r.releaseTag | tojson) is not a semver tag like v1.0.0")),
    (select(($r.updated | type) == "string" and ($r.updated | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$") | not))
     | err("schema"; "updated \($r.updated | tojson) must be YYYY-MM-DD")),
    (select(($r.tiers | type) != "object") | err("schema"; "tiers must be an object")),
    (select((($r.models | type) != "array") or (($r.models | length) == 0)) | err("schema"; "models must be a non-empty array")),

    (($r.models // []) | to_entries[]
     | . as $e | $e.value as $m
     | "models[\($e.key)]\(if ($m | type) == "object" and ($m.id | type) == "string" then " (\($m.id))" else "" end)" as $where
     | if ($m | type) != "object" then err("schema"; "\($where) must be an object")
       else
         (mandatory[] | select(. as $k | $m | has($k) | not) | err("schema"; "\($where) is missing mandatory key \(.)")),
         (["id","family","variant","activeParams","sha256"][] as $k
          | select($m | has($k)) | select(($m[$k] | is_str) | not)
          | err("schema"; "\($where).\($k) must be a non-empty string")),
         (["totalParams","tier"][] as $k
          | select($m | has($k)) | select(($m[$k] | is_str) | not)
          | err("schema"; "\($where).\($k) must be a non-empty string")),
         (select($m | has("minVramGb")) | select(($m.minVramGb | is_posint) | not)
          | err("schema"; "\($where).minVramGb must be a positive integer")),
         (select($m | has("minSystemRamGb")) | select(($m.minSystemRamGb | is_nonnegint) | not)
          | err("schema"; "\($where).minSystemRamGb must be a non-negative integer")),
         (["functionCalling","multimodal","thinkingModeConfigurable"][] as $k
          | select($m | has($k)) | select(($m[$k] | type) != "boolean")
          | err("schema"; "\($where).\($k) must be a boolean"))
       end),

    ($ids | group_by(.)[] | select(length > 1) | err("approved-set"; "duplicate model id \(.[0])")),
    ($ids | unique | map(select(. as $i | $allowed | index($i) | not))[]
     | err("approved-set"; "model \(.) is not in the approved set [\($allowed | join(", "))]")),
    ($allowed | map(select(. as $a | $ids | index($a) | not))[]
     | err("approved-set"; "approved model \(.) is missing from models[]")),

    (if ($r.tiers | type) == "object" then
       ($r.tiers | to_entries[]
        | . as $t
        | if ($t.value | type) != "object" or (($t.value.models | type) != "array")
          then err("tiers"; "tier \($t.key) must be an object with a models array")
          else
            (select(($t.value.label | is_str) | not) | err("tiers"; "tier \($t.key) needs a non-empty label")),
            ($t.value.models[] | select(. as $i | $ids | index($i) | not)
             | err("tiers"; "tier \($t.key) references unknown model \(.)"))
          end)
     else empty end),
    ($r.models // [] | map(select(type == "object" and (.id | is_str))) | .[] as $m
     | ([$r.tiers | objects | to_entries[] | select((.value.models? // []) | index($m.id)) | .key]) as $homes
     | if ($homes | length) == 0 then err("tiers"; "model \($m.id) is not listed in any tier")
       elif ($homes | length) > 1 then err("tiers"; "model \($m.id) is listed in several tiers: \($homes | join(", "))")
       elif ($m | has("tier")) and ($m.tier != $homes[0]) then err("tiers"; "model \($m.id) declares tier \($m.tier | tojson) but is listed under tier \($homes[0])")
       else empty end),

    ($r.models // [] | map(select(type == "object" and has("sha256") and (.sha256 | is_str))) | .[]
     | select((.sha256 == $sentinel) or (.sha256 | test("^[0-9a-fA-F]{64}$")) | not)
     | err("sha256"; "model \(.id): sha256 \(.sha256 | tojson) is neither 64 hex characters nor the \($sentinel) sentinel")),

    (if $release then
       ($r.models // [] | map(select(type == "object" and .sha256 == $sentinel)) | .[]
        | err("sentinel"; "model \(.id) still carries the \($sentinel) sentinel; run scripts/pin-model-digests.mjs before a --release"))
     else empty end)
  ]
JQ
)"
readonly JQ_RULES

ERRORS="$(jq -c --arg approved "$APPROVED" --arg sentinel "$SENTINEL" --argjson release "$RELEASE" "$JQ_RULES" "$FILE")"

declare -A CATEGORY_CODE=([schema]=4 [approved-set]=5 [tiers]=6 [sha256]=7 [sentinel]=8)
EXIT_CODE=0
for category in schema approved-set tiers sha256 sentinel; do
  if [[ "$(jq --arg c "$category" '[.[] | select(.category == $c)] | length' <<<"$ERRORS")" -gt 0 ]]; then
    EXIT_CODE="${CATEGORY_CODE[$category]}"
    break
  fi
done

if [[ "$JSON_OUTPUT" == "true" ]]; then
  jq -n --arg file "$FILE" --argjson release "$RELEASE" --argjson errors "$ERRORS" --argjson code "$EXIT_CODE" \
    '{ok: ($code == 0), file: $file, release: $release, exitCode: $code, errors: $errors}'
fi

if [[ "$EXIT_CODE" -ne 0 ]]; then
  jq -r '.[] | "[\(.category)] \(.message)"' <<<"$ERRORS" | while IFS= read -r line; do fail "$line"; done
  fail "$FILE rejected (exit $EXIT_CODE)"
  exit "$EXIT_CODE"
fi

PINNED_COUNT="$(jq --arg s "$SENTINEL" '[.models[] | select(.sha256 != $s)] | length' "$FILE")"
TOTAL_COUNT="$(jq '.models | length' "$FILE")"
MODE_NOTE=""
[[ "$RELEASE" == "true" ]] && MODE_NOTE=" (release mode)"
ok "$FILE valid: ${TOTAL_COUNT} approved models, ${PINNED_COUNT} with pinned sha256${MODE_NOTE}"
exit 0
