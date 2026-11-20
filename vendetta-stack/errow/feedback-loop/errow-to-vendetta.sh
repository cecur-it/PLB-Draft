#!/usr/bin/env bash
# errow-to-vendetta.sh - turn an Errow finding into Vendetta-side response actions.
#
# Traces: CONTRACT §6 (feedback loop, G9 offensive safety), §4.1 (normalized alert), §15 (shipper finding shape),
#         §2 (secret files, Vendetta manager API :55000). Approval format: APPROVALS.md / approval.py.
#
# Input  : stdin or --finding-file: NDJSON / JSON array / one document of shipper findings (SARIF result + rule),
#          SARIF logs, or Vendetta alerts carrying errow.fingerprint (see normalize-finding.jq).
# Actions: (1) isolate host   -> PUT /active-response on the Vendetta manager API (JWT from /security/user/authenticate)
#          (2) SOAR ticket    -> JSON file in $FEEDBACK_SOAR_DIR (+ optional webhook)
#          (3) retest request -> NDJSON queue consumed by vendetta-to-errow.sh
# Advisory LLM steps (PROMPT §2.5; gateway POST /forensic, CONTRACT §4.4) run AFTER the actions above are planned/executed and
#          never gate them: for every finding >= ERROW_FEEDBACK_FORENSIC_MIN_SEVERITY (default high) the sanitized normalized
#          record (never poc bodies) is sent to the gateway; proposedDetectionRule / proposedRemediation are appended to
#          $FEEDBACK_PROPOSALS_FILE (status pending_analyst_review, applied false) and printed as "PROPOSAL: ...". Nothing is
#          written to Vendetta rule directories and no apply API is called. Gateway failures only log "forensic unavailable".
#          --threat-model-file adds MITRE enrichment proposals (kind mitre_enrichment); --apply-enrichment + ERROW_FEEDBACK_LIVE
#          additionally ADDS mitre.tactic/technique + ai.engine to alerts of that errow.run (non-destructive _update_by_query).
# Safety : default is DRY-RUN. LIVE needs ERROW_FEEDBACK_LIVE=true AND ERROW_FEEDBACK_APPROVAL_THRESHOLD distinct
#          approvers' signed, unexpired approval lines for the finding fingerprint in APPROVALS.md. Host-targeted
#          actions also need the host in ERROW_FEEDBACK_ALLOWED_TARGETS.
# Exit   : 0 ok | 1 an action failed | 2 usage | 3 invalid input | 4 --live requested but the live gate is closed
# shellcheck disable=SC2016 # fl_jq programs are jq code, not shell expansions
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FL_TAG=errow-to-vendetta
# shellcheck source=lib.sh source-path=SCRIPTDIR
source "${SCRIPT_DIR}/lib.sh"

usage() {
  cat <<'EOF'
Usage: errow-to-vendetta.sh [options] [--finding-file FILE]   (reads stdin when no file is given)

Options:
  --finding-file FILE     read findings from FILE instead of stdin
  --run NAME              Errow run name for SARIF logs that do not carry one
  --dry-run               print what would happen (default; always wins over ERROW_FEEDBACK_LIVE)
  --live                  assert live mode; refused (exit 4) unless ERROW_FEEDBACK_LIVE=true
  --min-severity LEVEL    act only on findings >= LEVEL (default: high)
  --approvals-file FILE   approval ledger (default: APPROVALS.md next to this script)
  --no-isolate | --no-ticket | --no-retest   disable one action
  --no-forensic           skip the advisory gateway /forensic calls (same as ERROW_FEEDBACK_FORENSIC=false)
  --offline               no network at all: implies dry-run and no /forensic (tests); conflicts with --live
  --threat-model-file F   NDJSON/JSON threat-model entries (shipper stream threat_models, or a .state/threat_models.json map; "-" =
                          stdin): /forensic -> kind=mitre_enrichment proposals; alone, findings are not read from stdin
  --apply-enrichment      with --threat-model-file AND ERROW_FEEDBACK_LIVE=true AND OPENSEARCH_URL + password file: ADD
                          mitre.tactic/technique + ai.engine to alerts whose errow.run matches (default: print-only DRY-RUN)
  -h, --help              show this help

Environment (defaults):
  ERROW_FEEDBACK_LIVE=false               live gate (second gate: signed approval per fingerprint)
  ERROW_FEEDBACK_FORENSIC=true            ERROW_FEEDBACK_FORENSIC_MIN_SEVERITY=high   ERROW_FEEDBACK_FORENSIC_TIMEOUT=60
  ERROW_FEEDBACK_FORENSIC_BUDGET=80       (total seconds for all /forensic calls of one run)
  LLM_GATEWAY_URL=https://llm-gateway:9101  LLM_GATEWAY_TOKEN_FILE=/run/secrets/llm_gateway_token  (CA: FL_CA_FILE=/pki/ca.crt)
  FEEDBACK_PROPOSALS_FILE=<FEEDBACK_DIR>/proposals.ndjson
  OPENSEARCH_URL (unset)  OPENSEARCH_USER=admin  OPENSEARCH_PASSWORD_FILE=/run/secrets/opensearch_admin_password
  ERROW_FEEDBACK_ENRICH_MAX_DOCS=500
  ERROW_FEEDBACK_MIN_SEVERITY=high        ERROW_FEEDBACK_ISOLATE_MIN_SEVERITY=high
  ERROW_FEEDBACK_ALLOWED_TARGETS=scan-target.vendetta.lab   comma list, "*.suffix" allowed
  ERROW_FEEDBACK_AR_COMMAND='!host-isolate.sh'   active-response command ("!" = script on the agent)
  VENDETTA_EXECD_AGENT_REGEX (unset)      agent-id allow-list shared with the Fluentd execd gate (unset = any enrolled agent)
  ERROW_FEEDBACK_APPROVALS_FILE, ERROW_FEEDBACK_APPROVAL_KEY_FILE=/run/secrets/feedback_approval_key
  ERROW_FEEDBACK_APPROVERS (comma allow-list), ERROW_FEEDBACK_APPROVAL_MAX_DAYS=30
  ERROW_FEEDBACK_APPROVAL_KEYS_DIR=<key file dir>/keys   ERROW_FEEDBACK_APPROVAL_THRESHOLD=2
                                          per-approver keys (<approver>.key, 0600) and how many distinct approvers
                                          must sign one fingerprint; unset threshold counts the keys present
  VENDETTA_API_URL=https://vendetta-manager:55000   VENDETTA_API_USER=wazuh-wui
  VENDETTA_API_PASSWORD_FILE=/run/secrets/vendetta_api_password   VENDETTA_API_CA_FILE=<FL_CA_FILE>
                                          manager TLS: pin it with scripts/pin-manager-cert.sh; unreadable ⇒ no live action
  FL_CA_FILE=/pki/ca.crt                  LLM gateway TLS
  ERROW_SOAR_WEBHOOK_URL (optional)   ERROW_SOAR_WEBHOOK_TOKEN_FILE (optional bearer file)
  FEEDBACK_DIR=/var/log/feedback-loop  (feedback.log, retest-queue.ndjson, soar/, state/)
  ERROW_FEEDBACK_MAX_INPUT_BYTES=4194304
EOF
}

finding_file=''
run_name=''
force_dry=false
want_live=false
do_isolate=true
do_ticket=true
do_retest=true
offline=false
threat_model_file=''
apply_enrichment=false
ENRICH_MAX_DOCS=${ERROW_FEEDBACK_ENRICH_MAX_DOCS:-500}
OPENSEARCH_URL=${OPENSEARCH_URL:-}
OPENSEARCH_USER=${OPENSEARCH_USER:-admin}
OPENSEARCH_PASSWORD_FILE=${OPENSEARCH_PASSWORD_FILE:-/run/secrets/opensearch_admin_password}
MIN_SEVERITY=${ERROW_FEEDBACK_MIN_SEVERITY:-high}
ISOLATE_MIN=${ERROW_FEEDBACK_ISOLATE_MIN_SEVERITY:-high}
ALLOWED_TARGETS=${ERROW_FEEDBACK_ALLOWED_TARGETS:-scan-target.vendetta.lab}
AR_COMMAND=${ERROW_FEEDBACK_AR_COMMAND:-!host-isolate.sh}
APPROVALS_FILE=${ERROW_FEEDBACK_APPROVALS_FILE:-${SCRIPT_DIR}/APPROVALS.md}
MAX_INPUT=${ERROW_FEEDBACK_MAX_INPUT_BYTES:-4194304}
SOAR_WEBHOOK_URL=${ERROW_SOAR_WEBHOOK_URL:-}
SOAR_WEBHOOK_TOKEN_FILE=${ERROW_SOAR_WEBHOOK_TOKEN_FILE:-}

while (($#)); do
  case $1 in
    --finding-file) finding_file=${2:?--finding-file needs a value}; shift 2 ;;
    --run) run_name=${2:?--run needs a value}; shift 2 ;;
    --dry-run) force_dry=true; shift ;;
    --live) want_live=true; shift ;;
    --min-severity) MIN_SEVERITY=${2:?--min-severity needs a value}; shift 2 ;;
    --approvals-file) APPROVALS_FILE=${2:?--approvals-file needs a value}; shift 2 ;;
    --no-isolate) do_isolate=false; shift ;;
    --no-ticket) do_ticket=false; shift ;;
    --no-retest) do_retest=false; shift ;;
    --no-forensic) FORENSIC=false; shift ;;
    --offline) offline=true; shift ;;
    --threat-model-file) threat_model_file=${2:?--threat-model-file needs a value}; shift 2 ;;
    --apply-enrichment) apply_enrichment=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *) log_err "unknown argument: $1"; usage >&2; exit 2 ;;
  esac
done

if [[ $force_dry == true && $want_live == true ]]; then
  log_err "--dry-run and --live are mutually exclusive"
  exit 2
fi
if [[ $(sev_rank "$MIN_SEVERITY") -eq 0 && ${MIN_SEVERITY,,} != info ]]; then
  log_err "invalid severity: ${MIN_SEVERITY}"
  exit 2
fi
if [[ $want_live == true && ${ERROW_FEEDBACK_LIVE:-false} != true ]]; then
  log_err "--live refused: ERROW_FEEDBACK_LIVE is not 'true' (live gate closed)"
  exit 4
fi
live=false
if [[ ${ERROW_FEEDBACK_LIVE:-false} == true && $force_dry != true ]]; then
  live=true
fi
if [[ $offline == true ]]; then
  if [[ $want_live == true ]]; then
    log_err "--offline and --live are mutually exclusive"
    exit 2
  fi
  live=false
  FORENSIC=false
fi
if [[ $apply_enrichment == true && -z $threat_model_file ]]; then
  log_err "--apply-enrichment needs --threat-model-file"
  exit 2
fi
if [[ ! $ENRICH_MAX_DOCS =~ ^[1-9][0-9]{0,4}$ ]]; then
  log_err "ERROW_FEEDBACK_ENRICH_MAX_DOCS must be 1..99999"
  exit 2
fi

require_cmds jq curl python3
fl_forensic_config || exit 2
fl_prepare_log

findings=''
if [[ -n $finding_file || -z $threat_model_file ]]; then
  if [[ -n $finding_file ]]; then
    if [[ ! -r $finding_file ]]; then
      log_err "cannot read finding file: ${finding_file}"
      exit 2
    fi
    input=$(head -c "$((MAX_INPUT + 1))" -- "$finding_file")
  else
    input=$(head -c "$((MAX_INPUT + 1))")
  fi
  if (($(printf '%s' "$input" | wc -c) > MAX_INPUT)); then
    log_err "input exceeds ERROW_FEEDBACK_MAX_INPUT_BYTES=${MAX_INPUT}"
    exit 3
  fi
  if [[ -z ${input//[[:space:]]/} ]]; then
    log_err "no input: expected an Errow finding on stdin or via --finding-file"
    exit 3
  fi
  if ! findings=$(printf '%s\n' "$input" | jq -c --arg run "$run_name" -f "${SCRIPT_DIR}/normalize-finding.jq" 2>/dev/null); then
    log_err "input is not valid JSON/NDJSON"
    exit 3
  fi
fi

fld() { jq -r --arg k "$2" '(.[$k] // "") | tostring' <<<"$1"; }

priority_of() {
  case $1 in
    critical) echo P1 ;;
    high) echo P2 ;;
    medium) echo P3 ;;
    low) echo P4 ;;
    *) echo P5 ;;
  esac
}

marker() { printf '%s/%s.%s.done' "$FEEDBACK_STATE_DIR" "$1" "$2"; }

act_isolate() { # host fp run
  local host=$1 fp=$2 run=$3 jwt agent_id body
  if ! jwt=$(vendetta_jwt); then
    return 1
  fi
  fl_http bearer "$jwt" GET "${VENDETTA_API_URL%/}/agents?name=${host}&select=id,name"
  if ! http_ok; then
    emit "LIVE: FAILED isolate host=${host} fingerprint=${fp} reason=agent lookup HTTP ${HTTP_CODE}"
    return 1
  fi
  agent_id=$(jq -r '.data.affected_items[0].id // empty' <<<"$HTTP_BODY")
  if [[ -z $agent_id ]]; then
    emit "LIVE: SKIP isolate host=${host} fingerprint=${fp} reason=no enrolled Vendetta agent with that name"
    return 0
  fi
  if [[ ! $agent_id =~ ^[0-9A-Za-z_-]+$ || $agent_id =~ ^0+$ ]]; then
    emit "LIVE: SKIP isolate host=${host} fingerprint=${fp} reason=refusing agent id '${agent_id}' (manager or malformed)"
    return 0
  fi
  # Same allow-list as the Fluentd gate (action_gate.py): an agent outside VENDETTA_EXECD_AGENT_REGEX is not a live target.
  if [[ -n ${VENDETTA_EXECD_AGENT_REGEX:-} && ! $agent_id =~ $VENDETTA_EXECD_AGENT_REGEX ]]; then
    emit "LIVE: SKIP isolate host=${host} fingerprint=${fp} reason=agent id '${agent_id}' does not match VENDETTA_EXECD_AGENT_REGEX"
    return 0
  fi
  body=$(jq -cn --arg cmd "$AR_COMMAND" --arg fp "$fp" --arg run "$run" \
    '{command: $cmd, arguments: ["-"], alert: {data: {action: "isolate", errow_fingerprint: $fp, errow_run: $run}}}')
  fl_http bearer "$jwt" PUT "${VENDETTA_API_URL%/}/active-response?agents_list=${agent_id}" "$body"
  if http_ok && jq -e '.error == 0' >/dev/null 2>&1 <<<"$HTTP_BODY"; then
    emit "LIVE: isolated host=${host} agent_id=${agent_id} command=${AR_COMMAND} fingerprint=${fp}"
    mkdir -p -- "$FEEDBACK_STATE_DIR"
    : >"$(marker "$fp" isolate)"
    return 0
  fi
  emit "LIVE: FAILED isolate host=${host} agent_id=${agent_id} fingerprint=${fp} reason=active-response HTTP ${HTTP_CODE}"
  return 1
}

act_ticket() { # rec tid file
  local rec=$1 tid=$2 file=$3 ticket tok='' kind=none
  ticket=$(jq -c --arg id "$tid" --arg now "$(fl_now)" '
      {ticket_id: $id, created_at: $now, status: "open", source: "errow-feedback",
       title: ("[Errow] " + .title),
       severity: .severity,
       fingerprint: .fingerprint, run: .run, rule_id: .rule_id, cwe: .cwe, cve: .cve, cvss: .cvss,
       target: .target, host: .host, endpoint: .endpoint,
       description: .description, remediation: .remediation,
       retest: ("rt-" + .fingerprint[0:16])}' <<<"$rec")
  ticket=$(jq -c --arg p "$(priority_of "$(fld "$rec" severity)")" '. + {priority: $p}' <<<"$ticket")
  mkdir -p -- "$FEEDBACK_SOAR_DIR"
  if [[ -e $file ]]; then
    emit "LIVE: SOAR ticket ${tid} already exists file=${file}"
  else
    printf '%s\n' "$ticket" >"${file}.tmp.$$"
    mv -f -- "${file}.tmp.$$" "$file"
    emit "LIVE: opened SOAR ticket ${tid} file=${file}"
  fi
  if [[ -n $SOAR_WEBHOOK_URL ]]; then
    if [[ $SOAR_WEBHOOK_URL != http://* && $SOAR_WEBHOOK_URL != https://* ]]; then
      emit "LIVE: FAILED SOAR webhook ticket=${tid} reason=ERROW_SOAR_WEBHOOK_URL is not http(s)"
      return 1
    fi
    if [[ -n $SOAR_WEBHOOK_TOKEN_FILE ]]; then
      tok=$(read_secret "$SOAR_WEBHOOK_TOKEN_FILE") || return 1
      kind=bearer
    fi
    fl_http "$kind" "$tok" POST "$SOAR_WEBHOOK_URL" "$ticket"
    if ! http_ok; then
      emit "LIVE: FAILED SOAR webhook ticket=${tid} reason=HTTP ${HTTP_CODE}"
      return 1
    fi
    emit "LIVE: SOAR webhook delivered ticket=${tid} HTTP ${HTTP_CODE}"
  fi
  return 0
}

act_retest() { # rec rid
  local rec=$1 rid=$2 entry
  entry=$(jq -c --arg id "$rid" --arg now "$(fl_now)" \
    '{id: $id, queued_at: $now, origin: "errow-to-vendetta", attempts: 0, fingerprint: .fingerprint, run: .run,
      target: .target, host: .host, endpoint: .endpoint, rule_id: .rule_id, cwe: .cwe, severity: .severity}' <<<"$rec")
  lock_queue
  if [[ -f $FEEDBACK_QUEUE_FILE ]] && grep -Fq "\"id\":\"${rid}\"" "$FEEDBACK_QUEUE_FILE"; then
    unlock_queue
    emit "LIVE: retest ${rid} already queued file=${FEEDBACK_QUEUE_FILE}"
    return 0
  fi
  mkdir -p -- "$(dirname -- "$FEEDBACK_QUEUE_FILE")"
  printf '%s\n' "$entry" >>"$FEEDBACK_QUEUE_FILE"
  unlock_queue
  emit "LIVE: enqueued retest ${rid} target=$(fld "$rec" target) file=${FEEDBACK_QUEUE_FILE}"
}

processed=0
skipped=0
failed=0
invalid=0
total=0
declare -a FORENSIC_QUEUE=()
declare -A forensic_seen=()

process_finding() {
  local rec=$1 fp sev host target run label note='' approval tid rid file
  total=$((total + 1))
  if jq -e 'has("invalid")' >/dev/null <<<"$rec"; then
    log_warn "ignoring record: $(jq -r '.invalid' <<<"$rec")"
    invalid=$((invalid + 1))
    return 0
  fi
  fp=$(fld "$rec" fingerprint)
  sev=$(fld "$rec" severity)
  host=$(fld "$rec" host)
  target=$(fld "$rec" target)
  run=$(fld "$rec" run)
  if [[ ! $fp =~ ^[0-9a-f]{64}$ ]]; then
    log_warn "ignoring finding without a 64-hex primaryLocationLineHash fingerprint (rule=$(fld "$rec" rule_id))"
    invalid=$((invalid + 1))
    return 0
  fi
  if (($(sev_rank "$sev") < $(sev_rank "$MIN_SEVERITY"))); then
    emit "SKIP fingerprint=${fp} severity=${sev} reason=below minimum severity ${MIN_SEVERITY}"
    skipped=$((skipped + 1))
    return 0
  fi
  if [[ $FORENSIC == true && -z ${forensic_seen[$fp]-} ]] && (($(sev_rank "$sev") >= $(sev_rank "$FORENSIC_MIN_SEVERITY"))); then
    forensic_seen[$fp]=1
    FORENSIC_QUEUE+=("$rec")
  fi

  label=DRY-RUN
  if [[ $live == true ]]; then
    if approval=$(python3 "${SCRIPT_DIR}/approval.py" verify --fingerprint "$fp" --file "$APPROVALS_FILE" 2>&1); then
      label=LIVE
      log_info "fingerprint ${fp:0:12}: ${approval}"
    else
      note=" (live requested but not approved: ${approval//$'\n'/ })"
      emit "DENIED fingerprint=${fp} reason=${approval//$'\n'/ }"
    fi
  fi

  local rc=0
  tid="ERW-${fp:0:12}"
  rid="rt-${fp:0:16}"

  if [[ $do_isolate == true ]]; then
    if (($(sev_rank "$sev") < $(sev_rank "$ISOLATE_MIN"))); then
      emit "SKIP isolate fingerprint=${fp} reason=severity ${sev} below isolate minimum ${ISOLATE_MIN}"
    elif [[ -z $host ]] || ! valid_hostname "$host"; then
      emit "SKIP isolate fingerprint=${fp} reason=no valid host in finding target '${target}'"
    elif ! host_allowed "$host" "$ALLOWED_TARGETS"; then
      emit "SKIP isolate host=${host} fingerprint=${fp} reason=host not in ERROW_FEEDBACK_ALLOWED_TARGETS"
    elif [[ $label == DRY-RUN ]]; then
      emit "DRY-RUN: would isolate host=${host} via PUT ${VENDETTA_API_URL%/}/active-response command=${AR_COMMAND} fingerprint=${fp} severity=${sev}${note}"
    elif [[ -e $(marker "$fp" isolate) ]]; then
      emit "LIVE: isolate host=${host} fingerprint=${fp} already done (marker present)"
    else
      act_isolate "$host" "$fp" "$run" || rc=1
    fi
  fi

  if [[ $do_ticket == true ]]; then
    file="${FEEDBACK_SOAR_DIR}/${tid}.json"
    if [[ $label == DRY-RUN ]]; then
      emit "DRY-RUN: would open SOAR ticket id=${tid} severity=${sev} priority=$(priority_of "$sev") file=${file} webhook=${SOAR_WEBHOOK_URL:-none}${note}"
    elif [[ -e $(marker "$fp" ticket) ]]; then
      emit "LIVE: SOAR ticket ${tid} already done (marker present)"
    elif act_ticket "$rec" "$tid" "$file"; then
      mkdir -p -- "$FEEDBACK_STATE_DIR"
      : >"$(marker "$fp" ticket)"
    else
      rc=1
    fi
  fi

  if [[ $do_retest == true ]]; then
    if [[ -z $target || -z $host ]] || ! valid_hostname "$host"; then
      emit "SKIP retest fingerprint=${fp} reason=finding has no target"
    elif ! host_allowed "$host" "$ALLOWED_TARGETS"; then
      emit "SKIP retest host=${host} fingerprint=${fp} reason=host not in ERROW_FEEDBACK_ALLOWED_TARGETS"
    elif [[ $label == DRY-RUN ]]; then
      emit "DRY-RUN: would enqueue retest id=${rid} target=${target} endpoint=$(fld "$rec" endpoint) queue=${FEEDBACK_QUEUE_FILE}${note}"
    elif ! act_retest "$rec" "$rid"; then
      rc=1
    fi
  fi

  if ((rc != 0)); then
    failed=$((failed + 1))
  else
    processed=$((processed + 1))
  fi
  return 0
}

while IFS= read -r rec; do
  [[ -z $rec ]] && continue
  process_finding "$rec"
done <<<"$findings"

# --- advisory forensic phase (never gates the actions above) ----------------------------------------------------------------
FORENSIC_DOWN=false
fstate=on
[[ $FORENSIC == true ]] || fstate=off
[[ $offline == true ]] && fstate=offline

safe_subject() { printf '%s' "$1" | tr -c 'A-Za-z0-9._:/@-' '_' | cut -c1-160; }

# A gateway that is unreachable, too slow or rejecting our token will fail every remaining call the same way: stop asking.
forensic_fatal() {
  case $FORENSIC_REASON in
    "gateway unreachable"* | "timeout after"* | "gateway token unreadable"* | "gateway rejected the bearer token"* | "time budget"*) return 0 ;;
  esac
  return 1
}

forensic_findings() {
  local i n=${#FORENSIC_QUEUE[@]} rec fp req ctx pair kind field content
  for ((i = 0; i < n; i++)); do
    rec=${FORENSIC_QUEUE[i]}
    fp=$(fld "$rec" fingerprint)
    if ! req=$(fl_jq -c 'include "forensic"; finding_request' <<<"$rec" 2>/dev/null); then
      emit "forensic unavailable: cannot build a sanitized request for fingerprint=${fp}"
      continue
    fi
    if ! fl_forensic "$req"; then
      emit "forensic unavailable: ${FORENSIC_REASON}"
      if forensic_fatal; then
        FORENSIC_DOWN=true
        ((n - i - 1 > 0)) && emit "forensic: skipping $((n - i - 1)) remaining finding(s) after a gateway failure"
        break
      fi
      continue
    fi
    ctx=$(jq -c '{run, rule_id, severity, target, endpoint, cwe}' <<<"$rec")
    for pair in detection_rule:proposedDetectionRule remediation:proposedRemediation; do
      kind=${pair%%:*}
      field=${pair#*:}
      content=$(fl_jq -r --arg f "$field" 'include "forensic"; .analysis[$f] | clean(20000)' <<<"$FORENSIC_RESULT" 2>/dev/null || true)
      if [[ -z ${content//[[:space:]]/} ]]; then
        emit "forensic: no ${kind} proposed for ${fp}"
        continue
      fi
      fl_proposal_add "$kind" "$fp" "$fp" "$content" "$ctx"
    done
  done
}

# Painless script for --apply-enrichment: only ever ADDS values (union into the arrays, ai.engine only when absent).
read -r -d '' ENRICH_SCRIPT <<'EOF' || true
def m = ctx._source.mitre;
if (m == null) { ctx._source.mitre = new HashMap(); m = ctx._source.mitre; }
boolean changed = false;
for (String f : ['tactic', 'technique']) {
  def want = params.get(f);
  def cur = m.get(f);
  List l = new ArrayList();
  if (cur instanceof List) { l.addAll(cur); } else if (cur != null) { l.add(cur); }
  if (!l.contains(want)) { l.add(want); m.put(f, l); changed = true; }
}
def ai = ctx._source.ai;
if (ai == null) { ctx._source.ai = new HashMap(); ai = ctx._source.ai; }
if (ai.get('engine') == null) { ai.put('engine', params.engine); changed = true; }
if (!changed) { ctx.op = 'noop'; }
EOF

# enrich_gate_reason prints why --apply-enrichment cannot act (nothing when every gate is open).
enrich_gate_reason() {
  if [[ $apply_enrichment != true ]]; then
    printf '%s' "--apply-enrichment not given"
  elif [[ $live != true ]]; then
    printf '%s' "live gate closed (needs ERROW_FEEDBACK_LIVE=true without --dry-run/--offline)"
  elif [[ $OPENSEARCH_URL != http://* && $OPENSEARCH_URL != https://* ]]; then
    printf '%s' "OPENSEARCH_URL is not configured"
  elif [[ ! -r $OPENSEARCH_PASSWORD_FILE ]]; then
    printf '%s' "OpenSearch password file not readable (${OPENSEARCH_PASSWORD_FILE})"
  fi
}

enrich_apply() { # run tactic technique engine
  local run=$1 tactic=$2 technique=$3 engine=$4 secret body updated noops failures
  if ! secret="${OPENSEARCH_USER}:$(read_secret "$OPENSEARCH_PASSWORD_FILE")"; then
    emit "LIVE: FAILED enrichment run=${run} reason=OpenSearch credentials unavailable"
    return 1
  fi
  body=$(jq -cn --arg run "$run" --arg tac "$tactic" --arg tech "$technique" --arg eng "$engine" --arg src "$ENRICH_SCRIPT" \
    '{query: {bool: {filter: [{term: {"errow.run": $run}}]}},
      script: {lang: "painless", source: $src, params: {tactic: $tac, technique: $tech, engine: $eng}}}')
  fl_http basic "$secret" POST "${OPENSEARCH_URL%/}/vendetta-alerts-*/_update_by_query?conflicts=proceed&refresh=false&max_docs=${ENRICH_MAX_DOCS}" "$body"
  if ! http_ok; then
    emit "LIVE: FAILED enrichment run=${run} reason=OpenSearch HTTP ${HTTP_CODE}"
    return 1
  fi
  updated=$(jq -r '.updated // 0' <<<"$HTTP_BODY" 2>/dev/null || echo 0)
  noops=$(jq -r '.noops // 0' <<<"$HTTP_BODY" 2>/dev/null || echo 0)
  failures=$(jq -r '(.failures // []) | length' <<<"$HTTP_BODY" 2>/dev/null || echo 0)
  emit "LIVE: enriched alerts errow.run=${run} updated=${updated} noops=${noops} failures=${failures} added mitre.tactic=\"${tactic}\" mitre.technique=\"${technique}\" ai.engine=\"${engine}\""
  ((failures == 0)) || return 1
}

tactic_re="^[A-Za-z][A-Za-z ,/&-]{1,79}\$"
technique_re="^T[0-9]{4}(\\.[0-9]{3})?( - [A-Za-z0-9][A-Za-z0-9 ,/()&.'-]{0,79})?\$"
engine_re="^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,79}\$"
run_re="^[A-Za-z0-9._-]{1,128}\$"
tm_total=0
tm_invalid=0

forensic_threat_models() {
  local raw entries entry i n did run identity target subj req tactic technique engine valid extra content gate
  local -a arr=()
  if [[ $threat_model_file == - ]]; then
    raw=$(head -c "$((MAX_INPUT + 1))")
  elif [[ -r $threat_model_file ]]; then
    raw=$(head -c "$((MAX_INPUT + 1))" -- "$threat_model_file")
  else
    log_err "cannot read threat-model file: ${threat_model_file}"
    exit 2
  fi
  if (($(printf '%s' "$raw" | wc -c) > MAX_INPUT)); then
    log_err "threat-model input exceeds ERROW_FEEDBACK_MAX_INPUT_BYTES=${MAX_INPUT}"
    exit 3
  fi
  if [[ -z ${raw//[[:space:]]/} ]]; then
    log_err "no threat-model input"
    exit 3
  fi
  if ! entries=$(printf '%s\n' "$raw" | fl_jq -c --arg run "$run_name" 'include "forensic"; threat_entries($run)' 2>/dev/null); then
    log_err "threat-model input is not valid JSON/NDJSON"
    exit 3
  fi
  mapfile -t arr <<<"$entries"
  n=${#arr[@]}
  gate=$(enrich_gate_reason)
  for ((i = 0; i < n; i++)); do
    entry=${arr[i]}
    [[ -z $entry ]] && continue
    tm_total=$((tm_total + 1))
    if jq -e 'has("invalid")' >/dev/null <<<"$entry"; then
      log_warn "ignoring threat-model record: $(jq -r '.invalid' <<<"$entry")"
      tm_invalid=$((tm_invalid + 1))
      continue
    fi
    run=$(fld "$entry" run)
    identity=$(fld "$entry" identity)
    target=$(fld "$entry" target)
    did=$(fld "$entry" doc_id)
    [[ -n $did ]] || did=$(printf '%s|%s' "$run" "$identity" | sha256sum | cut -c1-16)
    entry=$(jq -c --arg d "$did" '.doc_id = $d' <<<"$entry")
    subj=$(safe_subject "${run:-unknown-run}/${target:-${identity:-threat-model}}")
    if [[ $FORENSIC_DOWN == true ]]; then
      emit "forensic unavailable: ${FORENSIC_REASON}"
      break
    fi
    if [[ -z $(fld "$entry" content | tr -d '[:space:]') ]]; then
      emit "forensic: threat model ${subj} has no content, skipped"
      continue
    fi
    if ! req=$(fl_jq -c 'include "forensic"; threat_request' <<<"$entry" 2>/dev/null); then
      emit "forensic unavailable: cannot build a sanitized request for threat model ${subj}"
      continue
    fi
    if ! fl_forensic "$req"; then
      emit "forensic unavailable: ${FORENSIC_REASON}"
      if forensic_fatal; then
        FORENSIC_DOWN=true
        break
      fi
      continue
    fi
    tactic=$(fl_jq -r 'include "forensic"; .analysis.mitreTactic | oneline(120)' <<<"$FORENSIC_RESULT" 2>/dev/null || true)
    technique=$(fl_jq -r 'include "forensic"; .analysis.mitreTechnique | oneline(120)' <<<"$FORENSIC_RESULT" 2>/dev/null || true)
    engine=$(fl_jq -r 'include "forensic"; .analysis.engineUsed | oneline(80)' <<<"$FORENSIC_RESULT" 2>/dev/null || true)
    if [[ -z $tactic && -z $technique ]]; then
      emit "forensic: no MITRE mapping proposed for ${subj}"
      continue
    fi
    valid=false
    if [[ $tactic =~ $tactic_re && $technique =~ $technique_re && $engine =~ $engine_re && $run =~ $run_re ]]; then
      valid=true
    fi
    content="MITRE ATT&CK enrichment proposal for threat model ${subj}: tactic=${tactic:-none}; technique=${technique:-none}; engine=${engine:-unknown}"
    extra=$(fl_jq -c --arg run "$run" --arg target "$target" --arg tac "$tactic" --arg tech "$technique" --argjson valid "$valid" \
      'include "forensic"; {mitreTactic: $tac, mitreTechnique: $tech, mitre_valid: $valid, run: $run, target: $target,
        confidenceScore: (.analysis.confidenceScore | if type == "number" then . else null end)}
       | with_entries(select(.value != null and .value != ""))' <<<"$FORENSIC_RESULT")
    fl_proposal_add mitre_enrichment "$subj" - "$content" "$extra"
    if [[ $valid != true ]]; then
      emit "SKIP enrichment ${subj} reason=proposed MITRE values failed validation or no valid errow.run (proposal kept for review)"
    elif [[ -z $gate ]]; then
      enrich_apply "$run" "$tactic" "$technique" "$engine" || failed=$((failed + 1))
    else
      emit "DRY-RUN: would add mitre.tactic=\"${tactic}\" mitre.technique=\"${technique}\" ai.engine=\"${engine}\" to alerts with errow.run=${run} (not applied: ${gate})"
    fi
  done
}

if [[ $FORENSIC == true && ${#FORENSIC_QUEUE[@]} -gt 0 ]]; then
  forensic_findings
fi
if [[ -n $threat_model_file ]]; then
  if [[ $FORENSIC == true ]]; then
    forensic_threat_models
  else
    emit "SKIP threat-model enrichment: forensic is disabled (--offline, --no-forensic or ERROW_FEEDBACK_FORENSIC=false)"
  fi
fi

mode=DRY-RUN
[[ $live == true ]] && mode=LIVE
log_info "mode=${mode} records=${total} processed=${processed} skipped=${skipped} invalid=${invalid} failed=${failed} forensic=${fstate} proposals=${PROPOSALS_WRITTEN}"

if ((total > 0 && invalid == total)) || ((total == 0 && tm_total > 0 && tm_invalid == tm_total)); then
  exit 3
fi
if ((failed > 0)); then
  exit 1
fi
exit 0
