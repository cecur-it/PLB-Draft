#!/usr/bin/env bash
# vendetta-to-errow.sh - turn Vendetta FIM / vulnerability / SCA alerts (and queued retests) into Errow scans.
#
# Traces: CONTRACT §6 (feedback loop), §4.4 (gateway /triage + /mcp/tool_call), §4.5 (MCP policy), §3 (vendetta-alerts-*),
#         §15 (errow.triggered / errow.run linkage), §2 (OpenSearch :9200, secret files).
#
# Sources : (1) retest queue written by errow-to-vendetta.sh ($FEEDBACK_QUEUE_FILE)
#           (2) OpenSearch vendetta-alerts-* : stream fim|vulnerability|sca, level >= ERROW_FEEDBACK_MIN_LEVEL, no
#               errow.triggered, never source.system=errow (prevents Errow -> alert -> Errow loops)
#           (3) --alert-file FILE|-  : alerts from a file/stdin instead of OpenSearch (fixtures, manual replay)
# Modes   : default (direct)  -> `errow --non-interactive --target T --scan-mode quick --instruction-file F`
#                               (needs the errow CLI, i.e. run inside the `errow` container)
#           --via-llm         -> POST gateway /triage; the model's toolCalls are forwarded to gateway /mcp/tool_call
#                               (policy + MCP_LIVE decide dry_run vs executed). This script NEVER runs a scan itself.
#                               For SCA-failure alerts it also calls gateway /forensic and records an advisory
#                               kind=errow_check proposal (draft source_aware_sast instruction text) in
#                               $FEEDBACK_PROPOSALS_FILE: status pending_analyst_review, applied false, never launched.
# Safety  : DRY-RUN unless ERROW_FEEDBACK_LIVE=true and --dry-run absent. Targets must match
#           ERROW_FEEDBACK_ALLOWED_TARGETS. Alert text is never placed in the Errow instruction file (prompt-injection guard).
# Schedule: --interval SECONDS (or ERROW_FEEDBACK_POLL_INTERVAL; 10..86400, 0/unset = single run) turns the script into a
#           long-running poller: one pass, interruptible sleep, repeat. Passes never overlap (flock on
#           ERROW_FEEDBACK_LOCK_FILE); a failed pass (exit 1) is logged and the loop continues; usage errors (2) and a closed
#           live gate (4) are fatal. SIGTERM/SIGINT finish the current pass, then exit 0. --max-passes N stops after N passes.
# Exit    : 0 ok | 1 an item failed | 2 usage | 4 --live requested but the live gate is closed
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FL_TAG=vendetta-to-errow
# shellcheck source=lib.sh source-path=SCRIPTDIR
source "${SCRIPT_DIR}/lib.sh"

usage() {
  cat <<'EOF'
Usage: vendetta-to-errow.sh [--via-llm] [--dry-run|--live] [options]

Options:
  --via-llm            plan through the LLM gateway (/triage -> /mcp/tool_call); never runs scans directly. SCA alerts also get an
                       advisory /forensic call -> kind=errow_check proposal in proposals.ndjson (pending analyst review, never launched)
  --no-forensic        skip the advisory /forensic call (same as ERROW_FEEDBACK_FORENSIC=false)
  --dry-run            print "DRY-RUN: would trigger errow scan ..." lines only (default; always wins)
  --live               assert live mode; refused (exit 4) unless ERROW_FEEDBACK_LIVE=true
  --alert-file FILE|-  read alerts (JSON/NDJSON/OpenSearch hits) from FILE or stdin instead of polling OpenSearch
  --limit N            max alerts and max queue entries per run (default 10)
  --no-queue           skip the retest queue          --no-poll   skip OpenSearch polling
  --interval SECONDS   run as a poller: repeat a pass every SECONDS (10..86400; 0 = single run, the default). Passes never
                       overlap (flock); a failed pass is logged and the loop continues; SIGTERM/SIGINT exit 0 after the
                       current pass. Exit 2 (usage) and 4 (live gate closed) are fatal.
  --max-passes N       with --interval: stop after N passes (testing)
  -h, --help

Environment (defaults):
  ERROW_FEEDBACK_LIVE=false   ERROW_FEEDBACK_ALLOWED_TARGETS=scan-target.vendetta.lab
  ERROW_FEEDBACK_POLL_INTERVAL=0  ERROW_FEEDBACK_LOCK_FILE=<FEEDBACK_DIR>/vendetta-to-errow.lock
  ERROW_FEEDBACK_HEARTBEAT_FILE=<unset>  (touched at the start of every scheduled pass; used by container healthchecks)
  ERROW_FEEDBACK_MIN_LEVEL=7  ERROW_FEEDBACK_LOOKBACK=24h  ERROW_FEEDBACK_MAX_ATTEMPTS=3
  ERROW_FEEDBACK_TARGET_URL_TEMPLATE=http://{host}:8080
  OPENSEARCH_URL=https://opensearch:9200  OPENSEARCH_USER=admin
  OPENSEARCH_PASSWORD_FILE=/run/secrets/opensearch_admin_password  FL_CA_FILE=/pki/ca.crt
  LLM_GATEWAY_URL=https://llm-gateway:9101  LLM_GATEWAY_TOKEN_FILE=/run/secrets/llm_gateway_token
  ERROW_FEEDBACK_CLIENT_CERT=/pki/errow-feedback.crt  ERROW_FEEDBACK_CLIENT_KEY=/pki/errow-feedback.key (used if present)
  ERROW_FEEDBACK_TENANT=default
  ERROW_FEEDBACK_FORENSIC=true  ERROW_FEEDBACK_FORENSIC_TIMEOUT=60  ERROW_FEEDBACK_FORENSIC_BUDGET=80
  FEEDBACK_PROPOSALS_FILE=<FEEDBACK_DIR>/proposals.ndjson
  ERROW_BIN=errow  ERROW_WORKDIR=/workspace  ERROW_FEEDBACK_SCAN_TIMEOUT=1800  ERROW_FEEDBACK_INSTR_DIR=<FEEDBACK_DIR>/instructions
  FEEDBACK_DIR=/var/log/feedback-loop
EOF
}

via_llm=false
force_dry=false
want_live=false
alert_file=''
limit=10
use_queue=true
use_poll=true
interval=${ERROW_FEEDBACK_POLL_INTERVAL:-0}
max_passes=''
ALLOWED_TARGETS=${ERROW_FEEDBACK_ALLOWED_TARGETS:-scan-target.vendetta.lab}
MIN_LEVEL=${ERROW_FEEDBACK_MIN_LEVEL:-7}
LOOKBACK=${ERROW_FEEDBACK_LOOKBACK:-24h}
MAX_ATTEMPTS=${ERROW_FEEDBACK_MAX_ATTEMPTS:-3}
TARGET_TEMPLATE=${ERROW_FEEDBACK_TARGET_URL_TEMPLATE:-'http://{host}:8080'}
OPENSEARCH_URL=${OPENSEARCH_URL:-https://opensearch:9200}
OPENSEARCH_USER=${OPENSEARCH_USER:-admin}
OPENSEARCH_PASSWORD_FILE=${OPENSEARCH_PASSWORD_FILE:-/run/secrets/opensearch_admin_password}
TENANT=${ERROW_FEEDBACK_TENANT:-default}
ERROW_BIN=${ERROW_BIN:-errow}
ERROW_WORKDIR=${ERROW_WORKDIR:-/workspace}
SCAN_TIMEOUT=${ERROW_FEEDBACK_SCAN_TIMEOUT:-1800}
INSTR_DIR=${ERROW_FEEDBACK_INSTR_DIR:-${FEEDBACK_DIR}/instructions}

while (($#)); do
  case $1 in
    --via-llm) via_llm=true; shift ;;
    --no-forensic) FORENSIC=false; shift ;;
    --dry-run) force_dry=true; shift ;;
    --live) want_live=true; shift ;;
    --alert-file) alert_file=${2:?--alert-file needs a value}; shift 2 ;;
    --limit) limit=${2:?--limit needs a value}; shift 2 ;;
    --no-queue) use_queue=false; shift ;;
    --no-poll) use_poll=false; shift ;;
    --interval) interval=${2:?--interval needs a value}; shift 2 ;;
    --max-passes) max_passes=${2:?--max-passes needs a value}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) log_err "unknown argument: $1"; usage >&2; exit 2 ;;
  esac
done

if [[ ! $limit =~ ^[0-9]+$ ]] || ((limit < 1 || limit > 500)); then
  log_err "--limit must be 1..500"
  exit 2
fi
if [[ ! $interval =~ ^[0-9]+$ ]] || { ((interval != 0)) && ((interval < 10 || interval > 86400)); }; then
  log_err "--interval / ERROW_FEEDBACK_POLL_INTERVAL must be 0 (single run) or an integer 10..86400"
  exit 2
fi
if [[ -n $max_passes ]] && { [[ ! $max_passes =~ ^[0-9]+$ ]] || ((max_passes < 1 || max_passes > 1000000)); }; then
  log_err "--max-passes must be an integer >= 1"
  exit 2
fi
if ((interval > 0)) && [[ $alert_file == - ]]; then
  log_err "--alert-file - (stdin) can only be read once; use a file with --interval"
  exit 2
fi
if [[ -n $max_passes ]] && ((interval == 0)); then
  log_err "--max-passes needs --interval"
  exit 2
fi
if [[ $force_dry == true && $want_live == true ]]; then
  log_err "--dry-run and --live are mutually exclusive"
  exit 2
fi
if [[ $want_live == true && ${ERROW_FEEDBACK_LIVE:-false} != true ]]; then
  log_err "--live refused: ERROW_FEEDBACK_LIVE is not 'true' (live gate closed)"
  exit 4
fi
if [[ ! $LOOKBACK =~ ^[0-9]+[smhd]$ || ! $MIN_LEVEL =~ ^[0-9]+$ ]]; then
  log_err "ERROW_FEEDBACK_LOOKBACK must look like 24h and ERROW_FEEDBACK_MIN_LEVEL must be an integer"
  exit 2
fi
live=false
if [[ ${ERROW_FEEDBACK_LIVE:-false} == true && $force_dry != true ]]; then
  live=true
fi
label=DRY-RUN
[[ $live == true ]] && label=LIVE

require_cmds jq curl
fl_forensic_config || exit 2
fl_prepare_log

os_secret=''
os_auth() {
  if [[ -z $os_secret ]]; then
    os_secret="${OPENSEARCH_USER}:$(read_secret "$OPENSEARCH_PASSWORD_FILE")" || return 1
  fi
}

fld() { jq -r --arg k "$2" '(.[$k] // "") | tostring' <<<"$1"; }
safe_text() { printf '%s' "$1" | tr -c 'A-Za-z0-9 ._:/()-' ' ' | tr -s ' ' | cut -c1-120; }
safe_id() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-96; }

target_for_host() {
  local t=${TARGET_TEMPLATE//\{host\}/$1}
  printf '%s' "$t"
}

# --- work-item construction -------------------------------------------------------------------------------------------
# item = {kind: alert|retest, id, host, description, rule_id, level, stream, index, doc_id, queue_id, payload}
alerts_to_items() {
  jq -c --arg idx vendetta-alerts '
    (if type == "array" then .[] else . end)
    | select(type == "object")
    | (if has("_source") then . else {_source: ., _index: $idx, _id: (.id // "")} end) as $h
    | $h._source as $a
    | {kind: "alert",
       id: (($a.id // $h._id // "") | tostring),
       doc_id: (($h._id // $a.id // "") | tostring),
       index: ($h._index // $idx),
       host: (($a.agent.name // "") | tostring),
       description: (($a.rule.description // "") | tostring),
       rule_id: (($a.rule.id // "") | tostring),
       level: ($a.rule.level // 0),
       stream: (($a.source.stream // "") | tostring),
       payload: ($a | del(.errow) | .full_log = ((.full_log // "") | tostring | .[0:2000]))}'
}

queue_to_items() {
  jq -cR --arg tpl "$TARGET_TEMPLATE" '
    fromjson? | select(type == "object" and (.id // "") != "")
    | {kind: "retest", id: .id, queue_id: .id, host: (.host // ""), target: (.target // ""),
       description: ("Retest of Errow finding " + (.rule_id // "") + " at " + (.endpoint // "/")),
       rule_id: (.rule_id // ""), level: 0, stream: "retest", index: "", doc_id: "",
       payload: {id: .id, source: {system: "errow-feedback", stream: "retest"},
                 rule: {id: (.rule_id // "retest"), level: 7, description: ("Retest of Errow finding " + (.rule_id // "") + " at " + (.endpoint // "/"))},
                 agent: {name: (.host // "")}, location: (.target // ""), full_log: ""}}' <"$FEEDBACK_QUEUE_FILE"
}

# --- state updates ----------------------------------------------------------------------------------------------------
mark_alert() { # index doc_id triggered(true|false) run mode reason
  local index=$1 doc=$2 trig=$3 run=$4 mode=$5 reason=$6 body
  if [[ ! $index =~ ^[a-z0-9._-]+$ || ! $doc =~ ^[A-Za-z0-9._:-]+$ ]]; then
    log_warn "not updating alert: unsafe index or id (${index} / ${doc})"
    return 1
  fi
  os_auth || return 1
  body=$(jq -cn --argjson t "$trig" --arg run "$run" --arg mode "$mode" --arg reason "$reason" --arg now "$(fl_now)" \
    '{doc: {errow: ({triggered: $t, trigger_mode: $mode, triggered_at: $now}
        + (if $run != "" then {run: $run} else {} end)
        + (if $reason != "" then {skip_reason: $reason} else {} end))}}')
  fl_http basic "$os_secret" POST "${OPENSEARCH_URL%/}/${index}/_update/${doc}?refresh=false" "$body"
  if http_ok; then
    emit "LIVE: marked alert id=${doc} errow.triggered=${trig} errow.run=${run:-none} index=${index}"
    return 0
  fi
  emit "LIVE: FAILED to mark alert id=${doc} (OpenSearch HTTP ${HTTP_CODE})"
  return 1
}

queue_finish() { # id outcome(completed|retry|dead) run
  local id=$1 outcome=$2 run=$3 dir tmp entry sink
  dir=$(dirname -- "$FEEDBACK_QUEUE_FILE")
  sink="${dir}/retest-dead.ndjson"
  [[ $outcome == completed ]] && sink="${dir}/retest-done.ndjson"
  tmp="${FEEDBACK_QUEUE_FILE}.tmp.$$"
  lock_queue
  entry=$(jq -cR --arg id "$id" 'fromjson? | select(type == "object" and .id == $id)' <"$FEEDBACK_QUEUE_FILE" | head -n1)
  case $outcome in
    retry)
      jq -cR --arg id "$id" 'fromjson? | select(type == "object") | if .id == $id then .attempts = ((.attempts // 0) + 1) else . end' \
        <"$FEEDBACK_QUEUE_FILE" >"$tmp"
      ;;
    *)
      jq -cR --arg id "$id" 'fromjson? | select(type == "object" and .id != $id)' <"$FEEDBACK_QUEUE_FILE" >"$tmp"
      if [[ -n $entry ]]; then
        jq -c --arg o "$outcome" --arg run "$run" --arg now "$(fl_now)" '. + {outcome: $o, run: $run, finished_at: $now}' <<<"$entry" \
          >>"$sink"
      fi
      ;;
  esac
  mv -f -- "$tmp" "$FEEDBACK_QUEUE_FILE"
  unlock_queue
}

# --- direct mode ------------------------------------------------------------------------------------------------------
write_instruction() { # file host rule_id level kind
  local file=$1 host=$2 rule=$3 level=$4 kind=$5
  mkdir -p -- "$(dirname -- "$file")"
  {
    printf '# Quick verification scan requested by the Vendetta feedback loop\n\n'
    printf -- '- Trigger: %s\n- Vendetta rule: %s (level %s)\n- Host: %s\n\n' "$kind" "$(safe_text "$rule")" "$level" "$host"
    printf 'Scope: only the listed host. Do not scan any other host, network range or Vendetta/Errow infrastructure.\n'
    printf 'Goal: confirm whether the exposure behind this alert is exploitable. Non-destructive checks only; no denial of service,\n'
    printf 'no data modification, no persistence. Report each confirmed issue with evidence and a remediation.\n'
  } >"$file"
}

runs_since() { # epoch: newest errow_runs/<run> directory modified after the given epoch
  find "${ERROW_WORKDIR}/errow_runs" -mindepth 1 -maxdepth 1 -type d -newermt "@${1}" -printf '%T@ %f\n' 2>/dev/null |
    sort -n | tail -n1 | cut -d' ' -f2- || true
}

direct_trigger() { # item target
  local item=$1 target=$2 id host instr started run rc=0 cmd_text
  id=$(fld "$item" id)
  host=$(fld "$item" host)
  instr="${INSTR_DIR}/$(safe_id "$id").md"
  local -a cmd=("$ERROW_BIN" --non-interactive --target "$target" --scan-mode quick --instruction-file "$instr")
  printf -v cmd_text '%q ' "${cmd[@]}"
  if [[ $label == DRY-RUN ]]; then
    emit "DRY-RUN: would trigger errow scan target=${target} tool=errow-cli mode=quick alert=${id} cmd=${cmd_text% }"
    return 0
  fi
  if ! command -v "$ERROW_BIN" >/dev/null 2>&1; then
    emit "LIVE: FAILED trigger target=${target} reason=errow CLI '${ERROW_BIN}' not found; run inside the errow container or use --via-llm"
    return 1
  fi
  write_instruction "$instr" "$host" "$(fld "$item" rule_id)" "$(fld "$item" level)" "$(fld "$item" kind)"
  mkdir -p -- "${ERROW_WORKDIR}/errow_runs"
  started=$(($(date -u +%s) - 1))
  emit "LIVE: triggering errow scan target=${target} tool=errow-cli alert=${id}"
  (cd -- "$ERROW_WORKDIR" && timeout "$SCAN_TIMEOUT" "${cmd[@]}") >>"${FEEDBACK_LOG}" 2>&1 || rc=$?
  run=$(runs_since "$started")
  ITEM_RUN=$run
  if ((rc != 0)); then
    emit "LIVE: FAILED errow scan target=${target} exit=${rc} run=${run:-unknown}"
    return 1
  fi
  emit "LIVE: errow scan finished target=${target} run=${run:-unknown}"
}

# --- via-llm mode -----------------------------------------------------------------------------------------------------
llm_trigger() { # item target
  local item=$1 target=$2 id host calls n i call tool args rationale tc_target req body status rc=0
  id=$(fld "$item" id)
  host=$(fld "$item" host)
  if ! gw_call /triage "$(jq -c '.payload' <<<"$item")"; then
    emit "${label}: FAILED triage alert=${id} reason=gateway token unavailable"
    return 1
  fi
  if ! http_ok; then
    emit "${label}: FAILED triage alert=${id} reason=gateway HTTP ${HTTP_CODE}"
    return 1
  fi
  calls=$(jq -c '[.results[0].analysis.toolCalls // [] | .[] | select(type == "object")]' <<<"$HTTP_BODY" 2>/dev/null || echo '[]')
  n=$(jq 'length' <<<"$calls")
  if ((n == 0)); then
    emit "SKIP alert=${id} reason=model proposed no toolCalls (target=${target})"
    ITEM_SKIP=no_tool_calls
    return 0
  fi
  for ((i = 0; i < n; i++)); do
    call=$(jq -c ".[$i]" <<<"$calls")
    tool=$(fld "$call" tool)
    if [[ ! $tool =~ ^[a-z][a-z0-9_]{0,31}$ ]]; then
      emit "SKIP alert=${id} reason=invalid tool name from model"
      continue
    fi
    args=$(jq -c '.args // {}' <<<"$call")
    rationale=$(jq -r '(.rationale // "") | tostring | .[0:500]' <<<"$call")
    tc_target=$(jq -r '.args.target // .args.domain // .args.url // empty' <<<"$call" | head -n1)
    tc_target=${tc_target:-$target}
    if [[ $label == DRY-RUN ]]; then
      emit "DRY-RUN: would trigger errow scan target=${tc_target} tool=${tool} alert=${id} via=${LLM_GATEWAY_URL%/}/mcp/tool_call"
      continue
    fi
    req=$(printf 'fb-%s-%s' "$(date -u +%s)" "$RANDOM$i")
    body=$(jq -cn --arg tenant "$TENANT" --arg inc "$id" --arg tool "$tool" --argjson args "$args" --arg why "$rationale" --arg req "$req" \
      '{tenant_id: $tenant, incident_id: $inc, role: "triage", tool: $tool, args: $args, rationale: $why, request_id: $req}')
    gw_call /mcp/tool_call "$body" || { rc=1; continue; }
    status=$(jq -r '.status // empty' <<<"$HTTP_BODY" 2>/dev/null || true)
    if http_ok; then
      emit "LIVE: tool_call tool=${tool} target=${tc_target} status=${status:-unknown} alert=${id} request_id=${req}"
      ITEM_RUN="mcp:${req}"
    else
      emit "LIVE: tool_call tool=${tool} target=${tc_target} DENIED HTTP ${HTTP_CODE} status=${status:-unknown} alert=${id} request_id=${req}"
      [[ $HTTP_CODE == 403 || $HTTP_CODE == 429 ]] || rc=1
    fi
  done
  return "$rc"
}

# --- advisory SCA forensic (gateway /forensic -> errow_check proposal) -----------------------------------------------------
# Never launches anything and never changes the item outcome: the result is only a draft Errow instruction text appended to
# proposals.ndjson for an analyst. Only sanitized identifiers enter the draft; the model text is quoted as untrusted notes.
is_sca_item() {
  jq -e '.stream == "sca" or ((.payload.rule.groups // []) | index("sca") != null)' >/dev/null 2>&1 <<<"$1"
}

sca_forensic() { # item
  local item=$1 id req draft extra
  id=$(fld "$item" id)
  if ! req=$(fl_jq -c 'include "forensic"; .payload | alert_request' <<<"$item" 2>/dev/null); then
    emit "forensic unavailable: cannot build request for alert=${id}"
    return 0
  fi
  if ! fl_forensic "$req"; then
    emit "forensic unavailable: ${FORENSIC_REASON}"
    return 0
  fi
  # shellcheck disable=SC2016 # jq program, not shell expansion
  draft=$(fl_jq -rn --argjson item "$item" --argjson res "$FORENSIC_RESULT" '
    include "forensic";
    def st: (. // "") | tostring | gsub("[^A-Za-z0-9 ._:/()-]"; " ") | .[0:120];
    ($item.payload.data.sca // {}) as $sca
    | ($res.analysis.proposedRemediation // $res.analysis.recommendedImmediateAction // $res.analysis.probableRootCause // "")
    | clean(1500) | redact as $notes
    | ["# DRAFT Errow check - pending analyst review - NOT launched",
       "# Source: Vendetta SCA failure rule " + ($item.rule_id | st) + " (level " + ($item.level | st) + ") on host " + ($item.host | st)
         + ", check " + (($sca.check.id // "n/a") | st) + ", policy " + (($sca.policy_id // "n/a") | st),
       "# Suggested style: source_aware_sast  (errow --non-interactive --scan-mode quick --instruction-file <this file>)",
       "",
       "Scope: only the host named above. Do not scan any other host, network range or Vendetta/Errow infrastructure.",
       "Goal: verify whether the failed configuration check is exploitable. Review the relevant configuration and source, then run",
       "non-destructive probes only; no denial of service, no data modification, no persistence. Report confirmed issues with",
       "evidence and a remediation.",
       "",
       "## Analyst notes (model proposal - untrusted, edit before use)",
       (if $notes == "" then "(the model proposed no remediation text)" else $notes end)]
    | join("\n")') || {
    emit "forensic unavailable: cannot build errow_check draft for alert=${id}"
    return 0
  }
  extra=$(jq -cn --arg host "$(fld "$item" host)" --arg rule "$(fld "$item" rule_id)" --arg lvl "$(fld "$item" level)" \
    '{scan_style: "source_aware_sast", stream: "sca", host: $host, rule_id: $rule, level: ($lvl | tonumber? // 0)}')
  fl_proposal_add errow_check "$id" - "$draft" "$extra"
}
ok_count=0
skip_count=0
fail_count=0

handle_item() {
  local item=$1 kind id host target rc=0 mode
  kind=$(fld "$item" kind)
  id=$(fld "$item" id)
  host=$(fld "$item" host)
  ITEM_RUN=''
  ITEM_SKIP=''
  mode=direct
  [[ $via_llm == true ]] && mode=llm
  [[ $kind == retest ]] && target=$(fld "$item" target) || target=$(target_for_host "$host")
  if [[ -z $host ]] || ! valid_hostname "$host" || ! host_allowed "$host" "$ALLOWED_TARGETS"; then
    emit "SKIP ${kind} id=${id} host=${host:-none} reason=host missing or not in ERROW_FEEDBACK_ALLOWED_TARGETS"
    skip_count=$((skip_count + 1))
    ITEM_SKIP=target_not_allowed
    finish_item "$item" "$mode" 0
    return 0
  fi
  if [[ $via_llm == true ]]; then
    llm_trigger "$item" "$target" || rc=1
    if [[ $FORENSIC == true && $kind == alert ]] && is_sca_item "$item"; then
      sca_forensic "$item" || true
    fi
  else
    direct_trigger "$item" "$target" || rc=1
  fi
  if ((rc != 0)); then
    fail_count=$((fail_count + 1))
  elif [[ -n $ITEM_SKIP ]]; then
    skip_count=$((skip_count + 1))
  else
    ok_count=$((ok_count + 1))
  fi
  finish_item "$item" "$mode" "$rc"
  return 0
}

finish_item() { # item mode rc
  local item=$1 mode=$2 rc=$3 kind qid attempts
  [[ $label == DRY-RUN ]] && return 0
  kind=$(fld "$item" kind)
  if [[ $kind == alert ]]; then
    [[ -n $alert_file ]] && return 0
    if ((rc != 0)); then
      return 0
    elif [[ -n $ITEM_SKIP ]]; then
      mark_alert "$(fld "$item" index)" "$(fld "$item" doc_id)" false "" "$mode" "$ITEM_SKIP" || true
    else
      mark_alert "$(fld "$item" index)" "$(fld "$item" doc_id)" true "$ITEM_RUN" "$mode" "" || fail_count=$((fail_count + 1))
    fi
  else
    qid=$(fld "$item" queue_id)
    if ((rc == 0)); then
      queue_finish "$qid" completed "${ITEM_RUN:-}"
    else
      attempts=$(jq -cR --arg id "$qid" 'fromjson? | select(type == "object" and .id == $id) | (.attempts // 0)' <"$FEEDBACK_QUEUE_FILE" | head -n1)
      if ((${attempts:-0} + 1 >= MAX_ATTEMPTS)); then
        queue_finish "$qid" dead "${ITEM_RUN:-}"
        emit "LIVE: retest ${qid} moved to dead-letter after ${MAX_ATTEMPTS} attempts"
      else
        queue_finish "$qid" retry ""
      fi
    fi
  fi
}

# run_pass: one full poll/queue/alert pass. Returns 0 ok, 1 an item or the poll failed, 2 unreadable --alert-file.
run_pass() {
  local item alerts alert_json query alert_count=0
  ITEM_RUN=''
  ITEM_SKIP=''
  ok_count=0
  skip_count=0
  fail_count=0
  PROPOSALS_WRITTEN=0
  os_secret=''
  gw_token=''
  # 1) retest queue
  if [[ $use_queue == true && -s $FEEDBACK_QUEUE_FILE && -z $alert_file ]]; then
    while IFS= read -r item; do
      [[ -z $item ]] && continue
      handle_item "$item"
    done < <(queue_to_items | head -n "$limit")
  fi

  # 2) alerts
  if [[ -n $alert_file ]]; then
    if [[ $alert_file == - ]]; then
      alert_json=$(head -c 4194304)
    elif [[ -r $alert_file ]]; then
      alert_json=$(head -c 4194304 -- "$alert_file")
    else
      log_err "cannot read alert file: ${alert_file}"
      return 2
    fi
    alerts=$(printf '%s\n' "$alert_json" | alerts_to_items | head -n "$limit")
  elif [[ $use_poll == true ]]; then
    os_auth || return 1
    query=$(jq -cn --argjson size "$limit" --argjson lvl "$MIN_LEVEL" --arg lb "now-${LOOKBACK}" '
      {size: $size, sort: [{"@timestamp": "asc"}],
       query: {bool: {
         filter: [
           {bool: {should: [{terms: {"source.stream": ["fim", "vulnerability", "sca"]}},
                            {terms: {"rule.groups": ["syscheck", "vulnerability-detector", "sca"]}}], minimum_should_match: 1}},
           {range: {"rule.level": {gte: $lvl}}},
           {range: {"@timestamp": {gte: $lb}}}],
         must_not: [{exists: {field: "errow.triggered"}},
                    {term: {"source.system": "errow"}},
                    {term: {"rule.groups": "errow_finding"}}]}}}')
    fl_http basic "$os_secret" POST "${OPENSEARCH_URL%/}/vendetta-alerts-*/_search" "$query"
    if ! http_ok; then
      log_err "OpenSearch poll failed (HTTP ${HTTP_CODE})"
      return 1
    fi
    alerts=$(jq -c '.hits.hits[]?' <<<"$HTTP_BODY" | alerts_to_items)
  else
    alerts=''
  fi

  alert_count=0
  if [[ -n ${alerts-} ]]; then
    while IFS= read -r item; do
      [[ -z $item ]] && continue
      alert_count=$((alert_count + 1))
      handle_item "$item"
    done <<<"$alerts"
  fi

  log_info "mode=${label}$([[ $via_llm == true ]] && echo ' via-llm') alerts=${alert_count} ok=${ok_count} skipped=${skip_count} failed=${fail_count}$([[ $via_llm == true ]] && echo " proposals=${PROPOSALS_WRITTEN}")"
  ((fail_count == 0)) || return 1
  return 0
}

stop=false
sleep_pid=''
on_signal() {
  stop=true
  log_info "signal received; stopping after the current pass"
  [[ -n $sleep_pid ]] && kill "$sleep_pid" 2>/dev/null || true
}

# Holds an exclusive non-blocking flock for one pass; without flock(1) or a writable lock file it degrades with a warning.
pass_locked() {
  local lock_fd rc=0
  if ! command -v flock >/dev/null 2>&1 || ! { exec {lock_fd}>>"$LOCK_FILE"; } 2>/dev/null; then
    log_warn "cannot lock ${LOCK_FILE}; running the pass without overlap protection"
    run_pass || rc=$?
    return "$rc"
  fi
  if ! flock -n "$lock_fd"; then
    log_warn "previous pass still running (lock ${LOCK_FILE}); skipping this pass"
    exec {lock_fd}>&-
    return 0
  fi
  run_pass || rc=$?
  exec {lock_fd}>&-
  return "$rc"
}

if ((interval == 0)); then
  rc=0
  run_pass || rc=$?
  exit "$rc"
fi

LOCK_FILE=${ERROW_FEEDBACK_LOCK_FILE:-${FEEDBACK_DIR}/vendetta-to-errow.lock}
trap on_signal TERM INT
passes=0
failed_passes=0
log_info "scheduler started: interval=${interval}s max-passes=${max_passes:-unlimited} lock=${LOCK_FILE}"
while [[ $stop != true ]]; do
  passes=$((passes + 1))
  rc=0
  [[ -z ${ERROW_FEEDBACK_HEARTBEAT_FILE-} ]] || touch -- "$ERROW_FEEDBACK_HEARTBEAT_FILE" 2>/dev/null || true
  pass_locked || rc=$?
  case $rc in
    0) ;;
    1)
      failed_passes=$((failed_passes + 1))
      log_warn "pass ${passes} failed (exit 1); next pass in ${interval}s"
      ;;
    *)
      log_err "pass ${passes} exited ${rc}; fatal, scheduler stopped"
      exit "$rc"
      ;;
  esac
  if [[ -n $max_passes ]] && ((passes >= max_passes)) || [[ $stop == true ]]; then
    break
  fi
  sleep "$interval" &
  sleep_pid=$!
  wait "$sleep_pid" 2>/dev/null || true
  sleep_pid=''
done
log_info "scheduler stopped after ${passes} pass(es), ${failed_passes} failed"
exit 0
