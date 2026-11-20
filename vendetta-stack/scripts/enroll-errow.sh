#!/usr/bin/env bash
#
# enroll-errow.sh — register the Errow runner with the vendetta-stack (errow-mcp bridge, API token, target allow-list).
#
# Traces: PROMPT §2.3 / §3 Phase 3 scripts/enroll-errow.sh; CONTRACT §2 (errow_api_token, errow-mcp :9103 mTLS, ERROW_CLOUD_*),
#         §4.5 (mcp_policy.yaml = source of truth for tools/targets), errow/mcp/RUNTIME.md (MCP_TARGETS_FILE, MCP_ALLOWED_CLIENTS).
#
# Steps (each idempotent):
#   1. FailClosed check and validation of the errow_api_token file (non-empty, >= 32 chars, one line, not world-readable).
#   2. Errow cloud: only when ERROW_CLOUD_ENABLED=true — refused under CS3_PROFILE=airgap (exit 3), otherwise a TLS reachability
#      probe of ERROW_CLOUD_URL (no credentials are sent to it by this script). Disabled ⇒ skipped.
#   3. MCP_TARGETS_FILE (default $STACK/errow/config/targets.yaml): created as an empty skeleton when absent and validated with
#      the same rules errow-mcp applies (keys hostnames/cidrs/domains/repo_paths, CIDR syntax, absolute repo_paths without "..");
#      a /0 CIDR is refused (exit 3), CIDRs inside the policy's denied ranges are reported (the denied list always wins).
#   4. Smoke over mTLS: GET /health, JSON-RPC initialize and tools/list against https://errow-mcp:9103/mcp; the tool names must
#      equal the keys of llm-gateway/mcp_policy.yaml `tools:`; the client certificate must be in MCP_ALLOWED_CLIENTS.
#   5. Writes ~/.errow/mcp-servers.json (JSON list; entry merged by name, mode 0600, previous file kept as .bak.<ts>) and the
#      sidecar ~/.errow/mcp-mtls.json with the CA/cert/key paths (Errow's loader forbids unknown keys, so mTLS material cannot
#      live in the entry itself; the supported mTLS caller of errow-mcp is llm-gateway). No token is copied into either file.
# --dry-run runs every read-only check but writes nothing.
#
# Exit codes: 0 ok | 1 verification failed (smoke, tool-list drift, invalid targets file) | 2 usage | 3 policy (FailClosedError,
#             cloud in air-gap, loose token permissions, over-broad target) | 4 missing prerequisite | 5 errow-mcp unreachable

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/pki.sh
source "$SCRIPT_DIR/lib/pki.sh"

trap 'vs_cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
enroll-errow.sh — register the Errow runner with the vendetta-stack.

Usage: scripts/enroll-errow.sh [options]

  --mcp-url URL              default https://errow-mcp:9103/mcp (must be https)
  --mcp-resolve H:P:ADDR     pin the errow-mcp name to an address, e.g. errow-mcp:9103:127.0.0.1 when 9103 is published locally
  --name NAME                entry name in mcp-servers.json (default vendetta-errow-mcp)
  --errow-home DIR           default $ERROW_HOME or ~/.errow
  --token-file F             default $STACK/secrets/errow_api_token     --allow-loose-token-perms (dev only)
  --targets-file F           default $MCP_TARGETS_FILE or $STACK/errow/config/targets.yaml (created empty when absent)
  --client-cert F --client-key F --ca F    mTLS identity (default pki/errow.crt|key, pki/ca.crt)
  --policy-file F            default $STACK/llm-gateway/mcp_policy.yaml
  --skip-smoke               do not contact errow-mcp          --skip-cloud   do not probe the Errow cloud
  --no-config                validate only; do not write mcp-servers.json / mcp-mtls.json
  --dry-run                  all read-only checks, no writes     --stack-dir DIR  -q  -v  -h

Environment/.env: ERROW_CLOUD_ENABLED (true|false), ERROW_CLOUD_URL (default https://app.errow.ai), MCP_TARGETS_FILE,
  MCP_ALLOWED_CLIENTS (default llm-gateway,errow,errow-mcp), CS3_PROFILE.

Exit codes: 0 ok | 1 verification failed | 2 usage | 3 policy | 4 prerequisite | 5 errow-mcp unreachable
EOF
}

MCP_URL=""
MCP_RESOLVES=()
ENTRY_NAME="vendetta-errow-mcp"
ERROW_HOME_DIR=""
TOKEN_FILE=""
LOOSE_TOKEN=0
TARGETS_FILE=""
CLIENT_CERT=""
CLIENT_KEY=""
CA_FILE=""
POLICY_FILE=""
SKIP_SMOKE=0
SKIP_CLOUD=0
NO_CONFIG=0

while (($#)); do
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]}"
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --mcp-url) vs_need "$@"; MCP_URL=$2; shift 2 ;;
    --mcp-resolve) vs_need "$@"; MCP_RESOLVES+=("$2"); shift 2 ;;
    --name) vs_need "$@"; ENTRY_NAME=$2; shift 2 ;;
    --errow-home) vs_need "$@"; ERROW_HOME_DIR=$2; shift 2 ;;
    --token-file) vs_need "$@"; TOKEN_FILE=$2; shift 2 ;;
    --allow-loose-token-perms) LOOSE_TOKEN=1; shift ;;
    --targets-file) vs_need "$@"; TARGETS_FILE=$2; shift 2 ;;
    --client-cert) vs_need "$@"; CLIENT_CERT=$2; shift 2 ;;
    --client-key) vs_need "$@"; CLIENT_KEY=$2; shift 2 ;;
    --ca) vs_need "$@"; CA_FILE=$2; shift 2 ;;
    --policy-file) vs_need "$@"; POLICY_FILE=$2; shift 2 ;;
    --skip-smoke) SKIP_SMOKE=1; shift ;;
    --skip-cloud) SKIP_CLOUD=1; shift ;;
    --no-config) NO_CONFIG=1; shift ;;
    --dry-run) VS_DRY_RUN=1; shift ;;
    -q|--quiet) VS_QUIET=1; shift ;;
    -v|--verbose) VS_VERBOSE=1; shift ;;
    --stack-dir)
      vs_need "$@"
      [[ -d "$2" ]] || die "$EX_USAGE" "stack dir not found: $2"
      STACK_DIR="$(cd "$2" && pwd)"
      SECRETS_DIR="$STACK_DIR/secrets"; PKI_DIR="$STACK_DIR/pki"; ENV_FILE="$STACK_DIR/.env"
      shift 2 ;;
    *) die "$EX_USAGE" "unknown option: $1 (see --help)" ;;
  esac
done

vs_require curl jq openssl
vs_valid_name "$ENTRY_NAME" || die "$EX_USAGE" "invalid --name: $ENTRY_NAME"
MCP_URL="${MCP_URL:-$(vs_cfg ERROW_MCP_URL https://errow-mcp:9103/mcp)}"
[[ "$MCP_URL" =~ ^https://$VS_HOSTPORT_RE(/[A-Za-z0-9._~/-]*)?$ ]] || die "$EX_USAGE" "--mcp-url must be an https:// URL without credentials or query"
MCP_BASE="${MCP_URL%/mcp}"
ERROW_HOME_DIR="${ERROW_HOME_DIR:-${ERROW_HOME:-$HOME/.errow}}"
TOKEN_FILE="${TOKEN_FILE:-$SECRETS_DIR/errow_api_token}"
TARGETS_FILE="${TARGETS_FILE:-$(vs_cfg MCP_TARGETS_FILE "$STACK_DIR/errow/config/targets.yaml")}"
CLIENT_CERT="${CLIENT_CERT:-$PKI_DIR/errow.crt}"
CLIENT_KEY="${CLIENT_KEY:-$PKI_DIR/errow.key}"
CA_FILE="${CA_FILE:-$PKI_DIR/ca.crt}"
POLICY_FILE="${POLICY_FILE:-$STACK_DIR/llm-gateway/mcp_policy.yaml}"

FAILURES=()
fail() { FAILURES+=("$1"); log_err "$1"; }

# ---------------------------------------------------------------------------------------------------
# 1. FailClosed + token file
# ---------------------------------------------------------------------------------------------------
fc_rc=0
vs_failclosed_check || fc_rc=$?
if ((fc_rc != 0)); then exit "$fc_rc"; fi

log_step "validating errow_api_token ($TOKEN_FILE)"
[[ -f "$TOKEN_FILE" ]] || die "$EX_USAGE" "token file not found: $TOKEN_FILE (run scripts/bootstrap.sh)"
mode="$(vs_file_mode "$TOKEN_FILE")"
if ((8#$mode & 8#007)); then
  if ((LOOSE_TOKEN)); then log_warn "token file is world-readable (mode $mode) — allowed by --allow-loose-token-perms"
  else log_err "token file $TOKEN_FILE is world-readable (mode $mode); chmod 600 it"; exit "$EX_POLICY"; fi
fi
token="$(vs_read_secret "$TOKEN_FILE")" || exit "$EX_USAGE"
if ((${#token} < 32)) || [[ "$token" =~ [[:space:]] ]]; then
  die "$EX_USAGE" "errow_api_token must be a single-line value of at least 32 characters (regenerate with scripts/bootstrap.sh after deleting the file)"
fi
unset token
log_ok "token file valid (mode $mode)"

# ---------------------------------------------------------------------------------------------------
# 2. Errow cloud (optional)
# ---------------------------------------------------------------------------------------------------
cloud="$(vs_cfg ERROW_CLOUD_ENABLED false)"
if [[ "$cloud" == true ]] && ((!SKIP_CLOUD)); then
  if [[ "$(vs_cfg CS3_PROFILE "")" == airgap ]]; then
    log_err "ERROW_CLOUD_ENABLED=true is forbidden with CS3_PROFILE=airgap (no external egress)"
    exit "$EX_POLICY"
  fi
  cloud_url="$(vs_cfg ERROW_CLOUD_URL https://app.errow.ai)"
  [[ "$cloud_url" =~ ^https://[A-Za-z0-9._:-]+(/.*)?$ ]] || die "$EX_USAGE" "ERROW_CLOUD_URL must be an https:// URL"
  crc=0
  retry 3 2 vs_http GET "$cloud_url/" --max-time 15 --ok 200,204,301,302,307,308,401,403,404 || crc=$?
  if ((crc != 0)); then
    fail "Errow cloud $cloud_url unreachable or TLS verification failed (HTTP $VS_HTTP_CODE)"
  else
    log_ok "Errow cloud reachable (HTTP $VS_HTTP_CODE, TLS verified)"
  fi
else
  log_info "Errow cloud disabled (ERROW_CLOUD_ENABLED=$cloud) — skipped"
fi

# ---------------------------------------------------------------------------------------------------
# 3. MCP_TARGETS_FILE
# ---------------------------------------------------------------------------------------------------
denied_cidrs() { # one denied CIDR per line from the policy file (awk: no YAML library needed)
  [[ -f "$POLICY_FILE" ]] || return 0
  awk '/^denied:/{d=1; next} /^[a-z_]+:/{d=0} d && /^  cidrs:/{c=1; next} d && /^  [a-z_]+:/{c=0} d && c && /^    - /{sub(/^    - /,""); gsub(/["\047 ]/,""); print}' "$POLICY_FILE"
}

validate_targets() { # <file> → prints findings; rc 0 ok | 1 invalid | 3 over-broad
  local file=$1 denied
  denied="$(denied_cidrs | paste -sd, -)"
  python3 - "$file" "$denied" <<'PY'
import ipaddress, re, sys
path, denied_csv = sys.argv[1], sys.argv[2]
KEYS = ("hostnames", "cidrs", "domains", "repo_paths")
text = open(path, encoding="utf-8").read()
try:
    import yaml
    data = yaml.safe_load(text) or {}
except ImportError:
    data, cur = {}, None
    for raw in text.splitlines():
        line = raw.split(" #")[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if m and not line.startswith(" "):
            cur, rest = m.group(1), m.group(2).strip()
            if rest.startswith("["):
                body = rest.strip("[]").strip()
                data[cur] = [i.strip().strip("'\"") for i in body.split(",")] if body else []
            elif rest == "":
                data[cur] = []
            else:
                print(f"{cur}: unsupported scalar value"); sys.exit(1)
        elif cur and line.strip().startswith("- "):
            data[cur].append(line.strip()[2:].strip().strip("'\""))
        else:
            print(f"unparseable line: {raw!r}"); sys.exit(1)
except Exception as exc:
    print(f"YAML parse error: {exc}"); sys.exit(1)
if not isinstance(data, dict) or set(data) - set(KEYS):
    print(f"only {', '.join(KEYS)} are allowed"); sys.exit(1)
denied = [ipaddress.ip_network(c, strict=False) for c in denied_csv.split(",") if c]
rc = 0
for key in KEYS:
    items = data.get(key) or []
    if not isinstance(items, list) or any(not isinstance(i, str) or not i for i in items):
        print(f"{key} must be a list of non-empty strings"); sys.exit(1)
    for it in items:
        if key == "cidrs":
            try:
                net = ipaddress.ip_network(it, strict=False)
            except ValueError as exc:
                print(f"cidrs: {exc}"); sys.exit(1)
            if net.prefixlen == 0:
                print(f"cidrs: {it} matches every address — refused"); rc = 3
            elif any(net.version == d.version and (net.subnet_of(d) or d.subnet_of(net)) for d in denied):
                print(f"WARN cidrs: {it} overlaps the policy's denied ranges (denied always wins)")
        elif key == "repo_paths":
            if not it.startswith("/") or ".." in it.split("/"):
                print(f"repo_paths: {it!r} must be absolute without .."); sys.exit(1)
        elif key in ("hostnames", "domains"):
            if not re.fullmatch(r"(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", it):
                print(f"{key}: {it!r} is not a valid DNS name"); sys.exit(1)
sys.exit(rc)
PY
}

log_step "validating the target allow-list ($TARGETS_FILE)"
vs_have python3 || die "$EX_PREREQ" "python3 is required to validate the targets file"
if [[ ! -f "$TARGETS_FILE" ]]; then
  if ((VS_DRY_RUN || NO_CONFIG)); then
    log_dry "would create the empty targets skeleton $TARGETS_FILE"
  else
    mkdir -p "$(dirname "$TARGETS_FILE")"
    printf '%s\n' "# Additional authorised targets for errow-mcp (MCP_TARGETS_FILE). Entries only ADD to llm-gateway/mcp_policy.yaml;" \
      "# the policy's denied ranges, tool allow-list and rate limits always win." \
      "hostnames: []" "cidrs: []" "domains: []" "repo_paths: []" | vs_atomic_write "$TARGETS_FILE" 0644
    log_ok "created empty targets skeleton $TARGETS_FILE"
  fi
fi
if [[ -f "$TARGETS_FILE" ]]; then
  vrc=0
  findings="$(validate_targets "$TARGETS_FILE" 2>&1)" || vrc=$?
  if [[ -n "$findings" ]]; then
    while IFS= read -r line; do
      if [[ "$line" == WARN* ]]; then log_warn "${line#WARN }"; else log_err "$line"; fi
    done <<<"$findings"
  fi
  case "$vrc" in
    0) log_ok "targets file valid" ;;
    3) exit "$EX_POLICY" ;;
    *) fail "targets file $TARGETS_FILE is invalid — errow-mcp would refuse it (fail-closed)" ;;
  esac
fi

# ---------------------------------------------------------------------------------------------------
# 4. mTLS smoke against errow-mcp
# ---------------------------------------------------------------------------------------------------
policy_tools() { # tool names (keys under `tools:`) from the policy, sorted
  awk '/^tools:/{t=1; next} /^[A-Za-z_]+:/{t=0} t && /^  [A-Za-z0-9_]+:/{k=$1; sub(/:$/,"",k); print k}' "$POLICY_FILE" | sort
}

mcp_call() { # <path-or-empty for /mcp> <json-body|empty for GET>
  local opts=(--ca "$CA_FILE" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" --max-time 20 --header 'Accept: application/json, text/event-stream') r
  for r in "${MCP_RESOLVES[@]}"; do opts+=(--resolve "$r"); done
  if [[ -n "${2:-}" ]]; then vs_http POST "$MCP_BASE${1:-/mcp}" "${opts[@]}" --data "$2"; else vs_http GET "$MCP_BASE$1" "${opts[@]}"; fi
}

check_client_allowed() {
  local allowed cn sans names n a
  allowed="$(vs_cfg MCP_ALLOWED_CLIENTS "llm-gateway,errow,errow-mcp")"
  [[ ",$allowed," == *,'*',* ]] && return 0
  cn="$(pki_cert_subject "$CLIENT_CERT" | sed -n 's/.*CN=\([^,]*\).*/\1/p')"
  sans="$(pki_cert_sans "$CLIENT_CERT" | sed -n 's/^DNS://p')"
  names="$cn"$'\n'"$sans"
  while IFS= read -r n; do
    [[ -n "$n" ]] || continue
    for a in ${allowed//,/$'\n'}; do
      if [[ "$n" == "$a" ]]; then return 0; fi
    done
  done <<<"$names"
  return 1
}

SMOKE_DONE=0
if ((SKIP_SMOKE)); then
  log_warn "smoke test skipped (--skip-smoke)"
else
  for f in "$CLIENT_CERT" "$CLIENT_KEY" "$CA_FILE"; do
    [[ -r "$f" ]] || die "$EX_USAGE" "mTLS material not readable: $f (run scripts/bootstrap.sh; the key must be readable by this user)"
  done
  [[ -f "$POLICY_FILE" ]] || die "$EX_USAGE" "policy file not found: $POLICY_FILE"
  log_step "smoke test: $MCP_URL (mTLS client $(basename "$CLIENT_CERT"))"
  if ! check_client_allowed; then
    fail "client certificate $CLIENT_CERT is not in MCP_ALLOWED_CLIENTS ($(vs_cfg MCP_ALLOWED_CLIENTS "llm-gateway,errow,errow-mcp")) — POST /mcp would be rejected"
  fi
  if ! retry 3 2 mcp_call /health ""; then
    if [[ "$VS_HTTP_CODE" == 000 ]]; then die "$EX_NOTREADY" "errow-mcp not reachable / client certificate rejected: ${VS_HTTP_BODY:0:200}"; fi
    die "$EX_FAIL" "GET /health returned HTTP $VS_HTTP_CODE"
  fi
  log_ok "errow-mcp /health HTTP $VS_HTTP_CODE"
  init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"vendetta-enroll-errow","version":"1"}}}'
  if mcp_call /mcp "$init" && jq -e '.result.serverInfo != null' <<<"$VS_HTTP_BODY" >/dev/null 2>&1; then
    log_ok "initialize: $(jq -r '.result.serverInfo.name // "?"' <<<"$VS_HTTP_BODY") $(jq -r '.result.serverInfo.version // ""' <<<"$VS_HTTP_BODY")"
  else
    fail "JSON-RPC initialize failed (HTTP $VS_HTTP_CODE: ${VS_HTTP_BODY:0:200})"
  fi
  if mcp_call /mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'; then
    served="$(jq -r '.result.tools[]?.name' <<<"$VS_HTTP_BODY" 2>/dev/null | sort)"
    expected="$(policy_tools)"
    if [[ -z "$served" ]]; then
      fail "tools/list returned no tools"
    elif [[ "$served" == "$expected" ]]; then
      log_ok "tools/list matches the policy ($(wc -l <<<"$served" | tr -d ' ') tools)"
      SMOKE_DONE=1
    else
      fail "tools/list differs from $POLICY_FILE (only on server: $(comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$served") | paste -sd' ' -); missing on server: $(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$served") | paste -sd' ' -)) — run scripts/sync-mcp-policy.sh --check and rebuild errow-mcp"
    fi
  else
    fail "JSON-RPC tools/list failed (HTTP $VS_HTTP_CODE: ${VS_HTTP_BODY:0:200})"
  fi
fi

if ((${#FAILURES[@]})); then
  log_err "${#FAILURES[@]} check(s) failed — Errow configuration NOT written"
  exit "$EX_FAIL"
fi

# ---------------------------------------------------------------------------------------------------
# 5. mcp-servers.json + sidecar
# ---------------------------------------------------------------------------------------------------
if ((NO_CONFIG)); then
  log_info "--no-config: nothing written"
  exit "$EX_OK"
fi
CFG="$ERROW_HOME_DIR/mcp-servers.json"
SIDE="$ERROW_HOME_DIR/mcp-mtls.json"

if [[ -f "$POLICY_FILE" ]]; then
  allowed_json="$(policy_tools | jq -R . | jq -sc 'map(select(length > 0))')"
else
  allowed_json='null'
fi
entry="$(jq -cn --arg n "$ENTRY_NAME" --arg u "$MCP_URL" --argjson t "$allowed_json" \
  '{name: $n, transport: "http", url: $u, allowed_tools: $t, active_tools: [],
    notes: "vendetta-stack errow-mcp bridge (mTLS; client material in mcp-mtls.json). Policy: llm-gateway/mcp_policy.yaml.",
    http_timeout_seconds: 30, max_concurrent_calls: 4}')"

existing='[]'
if [[ -f "$CFG" ]]; then
  existing="$(jq -c 'if type == "array" then . else error("not a list") end' "$CFG" 2>/dev/null)" \
    || die "$EX_FAIL" "$CFG exists but is not a JSON list of server entries — refusing to overwrite it"
fi
merged="$(jq -c --argjson e "$entry" 'if any(.[]; .name == $e.name) then map(if .name == $e.name then $e else . end) else . + [$e] end' <<<"$existing")"
side_json="$(jq -n --arg n "$ENTRY_NAME" --arg ca "$CA_FILE" --arg c "$CLIENT_CERT" --arg k "$CLIENT_KEY" \
  '{servers: {($n): {ca: $ca, cert: $c, key: $k}}}')"

if ((VS_DRY_RUN)); then
  log_dry "would write $CFG: $merged"
  log_dry "would write $SIDE: $(jq -c . <<<"$side_json")"
  exit "$EX_OK"
fi

(umask 077; mkdir -p "$ERROW_HOME_DIR")
chmod 0700 "$ERROW_HOME_DIR"
if [[ -f "$CFG" ]] && [[ "$(jq -c . "$CFG")" == "$merged" ]]; then
  log_ok "$CFG already up to date"
else
  if [[ -f "$CFG" ]]; then (umask 077; cp -p -- "$CFG" "$CFG.bak.$(vs_ts)"); fi
  jq . <<<"$merged" | vs_atomic_write "$CFG" 0600
  log_ok "wrote $CFG (entry '$ENTRY_NAME')"
fi
if [[ -f "$SIDE" ]] && [[ "$(jq -S -c . "$SIDE")" == "$(jq -S -c . <<<"$side_json")" ]]; then
  log_ok "$SIDE already up to date"
else
  jq . <<<"$side_json" | vs_atomic_write "$SIDE" 0600
  log_ok "wrote $SIDE (mTLS paths; contains no secrets)"
fi

printf 'errow enrolled: entry=%s url=%s smoke=%s targets=%s\n' "$ENTRY_NAME" "$MCP_URL" "$([[ $SMOKE_DONE -eq 1 ]] && echo passed || echo skipped)" "$TARGETS_FILE"
exit "$EX_OK"
