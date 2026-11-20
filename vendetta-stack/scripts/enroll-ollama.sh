#!/usr/bin/env bash
#
# enroll-ollama.sh — verify and register an Ollama worker node for the llm-gateway's HAProxy tier.
#
# Traces: PROMPT §1 Tier 4 / §3 Phase 3 scripts/enroll-ollama.sh; CONTRACT §2 (OLLAMA_PINNED_VERSION=0.40.5, Ollama bound
#         to 127.0.0.1:11434 only), §8.2/§10 (worker topology, models.json pins), CS3 §3.3 (digest pins, air-gap).
#
# A worker node = Ollama on 127.0.0.1:11434 + the mTLS terminator sidecar (ollama/ollama-lb/worker-proxy.cfg) on :11443.
# The load balancer discovers workers by the DNS name `ollama-workers` (port 11443), so "registering" a node means
# (a) proving it is safe to receive traffic and (b) making it resolvable under that name. Checks:
#   1. GET https://<sni>:11443/api/version over mTLS (client pki/ollama-lb.crt, CA pki/ca.crt, SNI/verify host
#      `ollama-1` unless --sni) must report OLLAMA_PINNED_VERSION (default 0.40.5).
#   2. Port 11434 must NOT be reachable on the node's address (and, with --local/--container, must be loopback-only/unpublished).
#   3. Every required model tag (default: primary+fallback+security, --models CSV|all) is present in /api/tags and approved
#      in models.json.
#   4. Weight blobs are verified against the SHA-256 pins in ollama/models.json (--models-dir DIR, or --container NAME which
#      hashes inside the container). The sentinel "<pinned-per-release>" is refused under --release or CS3_PROFILE=airgap;
#      with --release/airgap an unverifiable store (no --models-dir/--container) is refused too.
#   5. Writes the inventory ollama/ollama-lb/workers.d/<node>.json and regenerates ollama/ollama-lb/workers.hosts
#      (`<ip> ollama-workers  # <node>` — hosts/dnsmasq addn-hosts/CoreDNS `hosts` format; HAProxy re-resolves every ~10 s,
#      no reload needed) and prints equivalent DNS A records. Compose workers (--container) are found through the compose
#      network alias `ollama-workers`; they are inventoried but not added to workers.hosts.
#   6. Confirms through the gateway: GET <gateway>/health must report backend.reachable=true (poll with --wait SECS).
#   --remove NAME de-registers a node (inventory + hosts line).
# --dry-run performs every read-only check but writes nothing.
#
# Exit codes: 0 enrolled | 1 verification failed (version, models, gateway) | 2 usage | 3 policy/integrity (11434 exposed,
#             pin mismatch, sentinel or unverifiable under --release/airgap, unapproved model) | 4 missing prerequisite |
#             5 node unreachable / mTLS refused

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/models.sh
source "$SCRIPT_DIR/lib/models.sh"

trap 'vs_cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
enroll-ollama.sh — verify an Ollama worker node and register it behind the llm-gateway LB.

Usage: scripts/enroll-ollama.sh --node NAME (--address IP | --container NAME | --local) [options]
       scripts/enroll-ollama.sh --remove NAME

Node selection:
  --node NAME              inventory name (letters, digits, . _ -)
  --address IP|HOST        node address reachable from here (mTLS proxy port --port, default 11443)
  --container NAME         the node is a local Docker container (compose worker): IP from `docker inspect`, blobs hashed with docker exec
  --container-models-dir D Ollama models dir inside the container (default /root/.ollama/models)
  --local                  the node is this host (address defaults to 127.0.0.1; uses `ss` for the loopback check)
  --sni NAME               server name the worker certificate carries (default ollama-1)
  --port N                 worker mTLS proxy port (default 11443)
Verification:
  --models CSV|all|none    required tags (default $OLLAMA_PRELOAD_MODELS, else $OLLAMA_PRIMARY_MODEL + $OLLAMA_FALLBACK_MODEL
                           + $OLLAMA_SECURITY_MODEL)
  --models-json FILE       default $STACK/ollama/models.json
  --models-dir DIR         the node's Ollama models directory, readable from here (blobs/, manifests/) for SHA-256 verification
  --version V              expected Ollama version (default $OLLAMA_PINNED_VERSION or 0.40.5)
  --release                refuse the sentinel pin and refuse an unverifiable store (implied by CS3_PROFILE=airgap)
Registration / confirmation:
  --inventory-dir DIR      default $STACK/ollama/ollama-lb/workers.d   (hosts file: DIR/../workers.hosts)
  --gateway-url URL        default $ENROLL_GATEWAY_URL or https://localhost:9101   --gateway-resolve HOST:PORT:ADDR
  --wait SECS              poll the gateway /health for up to SECS (default 60)    --skip-gateway
  --client-cert F --client-key F --ca F   mTLS identity (default pki/ollama-lb.crt|key, pki/ca.crt)
General: --dry-run  --stack-dir DIR  -q  -v  -h

Exit codes: 0 enrolled | 1 verification failed | 2 usage | 3 policy/integrity | 4 prerequisite | 5 node unreachable
EOF
}

NODE=""
ADDRESS=""
CONTAINER=""
CONT_MODELS="/root/.ollama/models"
LOCAL=0
SNI="ollama-1"
PORT=11443
MODELS_ARG=""
MODELS_JSON=""
EXPECT_VERSION=""
RELEASE=0
INVENTORY_DIR=""
GATEWAY_URL=""
GATEWAY_RESOLVE=()
WAIT=60
SKIP_GATEWAY=0
CLIENT_CERT=""
CLIENT_KEY=""
CA_FILE=""
REMOVE=""
BLOB_SOURCE="none"
REQUIRED=()
PROBE_ADDR=""
NODE_VERSION=""
NODE_TAGS=()
PINNED_COUNT=0
SENTINEL_COUNT=0

while (($#)); do
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]}"
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --node) vs_need "$@"; NODE=$2; shift 2 ;;
    --address) vs_need "$@"; ADDRESS=$2; shift 2 ;;
    --container) vs_need "$@"; CONTAINER=$2; shift 2 ;;
    --container-models-dir) vs_need "$@"; CONT_MODELS=$2; shift 2 ;;
    --local) LOCAL=1; shift ;;
    --sni) vs_need "$@"; SNI=$2; shift 2 ;;
    --port) vs_need "$@"; PORT=$2; shift 2 ;;
    --models) vs_need "$@"; MODELS_ARG=$2; shift 2 ;;
    --models-json) vs_need "$@"; MODELS_JSON=$2; shift 2 ;;
    --models-dir) vs_need "$@"; MODELS_DIR=$2; shift 2 ;;
    --version) vs_need "$@"; EXPECT_VERSION=$2; shift 2 ;;
    --release) RELEASE=1; shift ;;
    --inventory-dir) vs_need "$@"; INVENTORY_DIR=$2; shift 2 ;;
    --gateway-url) vs_need "$@"; GATEWAY_URL=$2; shift 2 ;;
    --gateway-resolve) vs_need "$@"; GATEWAY_RESOLVE+=("$2"); shift 2 ;;
    --wait) vs_need "$@"; WAIT=$2; shift 2 ;;
    --skip-gateway) SKIP_GATEWAY=1; shift ;;
    --client-cert) vs_need "$@"; CLIENT_CERT=$2; shift 2 ;;
    --client-key) vs_need "$@"; CLIENT_KEY=$2; shift 2 ;;
    --ca) vs_need "$@"; CA_FILE=$2; shift 2 ;;
    --remove) vs_need "$@"; REMOVE=$2; shift 2 ;;
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
INVENTORY_DIR="${INVENTORY_DIR:-$STACK_DIR/ollama/ollama-lb/workers.d}"
HOSTS_FILE="$(dirname "$INVENTORY_DIR")/workers.hosts"

# ---------------------------------------------------------------------------------------------------
# Inventory (shared by enroll and --remove)
# ---------------------------------------------------------------------------------------------------
regenerate_hosts() {
  local f out="" ip
  out+="# Generated by scripts/enroll-ollama.sh — one line per enrolled Ollama worker (DNS name resolved by the LB)."$'\n'
  out+="# Serve this file with dnsmasq addn-hosts / CoreDNS 'hosts' / /etc/hosts of the llm-gateway network; do not edit by hand."$'\n'
  if [[ -d "$INVENTORY_DIR" ]]; then
    for f in "$INVENTORY_DIR"/*.json; do
      [[ -f "$f" ]] || continue
      if [[ "$(jq -r '.discovery // ""' "$f")" != dns-hosts ]]; then continue; fi
      ip="$(jq -r '.address' "$f")"
      out+="$ip ollama-workers # $(jq -r '.node' "$f")"$'\n'
    done
  fi
  if [[ -f "$HOSTS_FILE" ]] && [[ "$(<"$HOSTS_FILE")" == "${out%$'\n'}" ]]; then
    log_ok "workers.hosts unchanged"
    return 0
  fi
  if ((VS_DRY_RUN)); then log_dry "would write $HOSTS_FILE:"$'\n'"$out"; return 0; fi
  printf '%s' "$out" | vs_atomic_write "$HOSTS_FILE" 0644
  log_ok "updated $HOSTS_FILE"
}

if [[ -n "$REMOVE" ]]; then
  vs_valid_name "$REMOVE" || die "$EX_USAGE" "invalid node name: $REMOVE"
  if [[ -f "$INVENTORY_DIR/$REMOVE.json" ]]; then
    if ((VS_DRY_RUN)); then log_dry "would remove $INVENTORY_DIR/$REMOVE.json"; else rm -f -- "$INVENTORY_DIR/$REMOVE.json"; log_ok "removed inventory entry $REMOVE"; fi
  else
    log_info "node $REMOVE is not enrolled — nothing to remove"
  fi
  regenerate_hosts
  exit "$EX_OK"
fi

# ---------------------------------------------------------------------------------------------------
# Validation of the request
# ---------------------------------------------------------------------------------------------------
[[ -n "$NODE" ]] || die "$EX_USAGE" "--node NAME is required"
vs_valid_name "$NODE" || die "$EX_USAGE" "invalid --node name: $NODE"
vs_valid_port "$PORT" || die "$EX_USAGE" "invalid --port: $PORT"
vs_is_uint "$WAIT" || die "$EX_USAGE" "--wait must be a number of seconds"
[[ "$SNI" =~ ^[A-Za-z0-9.-]+$ ]] || die "$EX_USAGE" "invalid --sni: $SNI"
if [[ -z "$ADDRESS" && -z "$CONTAINER" && $LOCAL -eq 0 ]]; then die "$EX_USAGE" "one of --address, --container or --local is required"; fi
if [[ -n "$CONTAINER" && $LOCAL -eq 1 ]]; then die "$EX_USAGE" "--container and --local are mutually exclusive"; fi
if [[ -n "$CONTAINER" && -n "$MODELS_DIR" ]]; then die "$EX_USAGE" "--container and --models-dir are mutually exclusive"; fi
if [[ -n "$MODELS_DIR" && ! -d "$MODELS_DIR" ]]; then die "$EX_USAGE" "--models-dir not found: $MODELS_DIR"; fi
if [[ "$(vs_cfg CS3_PROFILE "")" == airgap ]]; then RELEASE=1; fi
MODELS_JSON="${MODELS_JSON:-$(vs_cfg OLLAMA_MODELS_JSON "$STACK_DIR/ollama/models.json")}"
EXPECT_VERSION="${EXPECT_VERSION:-$(vs_cfg OLLAMA_PINNED_VERSION 0.40.5)}"
GATEWAY_URL="${GATEWAY_URL:-$(vs_cfg ENROLL_GATEWAY_URL https://localhost:9101)}"
GATEWAY_URL="${GATEWAY_URL%/}"
vs_is_https_hostport "$GATEWAY_URL" || die "$EX_USAGE" "--gateway-url must be https://host[:port]"
CLIENT_CERT="${CLIENT_CERT:-$PKI_DIR/ollama-lb.crt}"
CLIENT_KEY="${CLIENT_KEY:-$PKI_DIR/ollama-lb.key}"
CA_FILE="${CA_FILE:-$PKI_DIR/ca.crt}"
for f in "$CLIENT_CERT" "$CLIENT_KEY" "$CA_FILE"; do
  [[ -r "$f" ]] || die "$EX_USAGE" "mTLS material not readable: $f (run scripts/bootstrap.sh; the key must be readable by this user)"
done
models_json_validate "$MODELS_JSON" || exit "$EX_USAGE"
if [[ -n "$CONTAINER" ]]; then vs_require docker; fi

is_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$1" == *:* ]]; }

resolve_models() {
  local csv=$MODELS_ARG id ids=()
  if [[ -z "$csv" ]]; then csv="$(vs_cfg OLLAMA_PRELOAD_MODELS "")"; fi
  case "$csv" in
    none) REQUIRED=(); return 0 ;;
    all) mapfile -t REQUIRED < <(models_json_ids "$MODELS_JSON"); return 0 ;;
    "") ids=("$(vs_cfg OLLAMA_PRIMARY_MODEL nemotron-3-nano:30b)" "$(vs_cfg OLLAMA_FALLBACK_MODEL gemma4:26b)" \
             "$(vs_cfg OLLAMA_SECURITY_MODEL nemotron-3-nano:30b)") ;;
    *) IFS=, read -r -a ids <<<"$csv" ;;
  esac
  REQUIRED=()
  for id in "${ids[@]}"; do
    [[ -n "$id" ]] || continue
    if [[ -z "$(jq -r --arg id "$id" '.models[] | select(.id == $id) | .id' "$MODELS_JSON")" ]]; then
      die "$EX_POLICY" "model '$id' is not approved in $MODELS_JSON (approved: $(models_json_ids "$MODELS_JSON" | paste -sd' ' -))"
    fi
    REQUIRED+=("$id")
  done
}
resolve_models

# ---------------------------------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------------------------------
resolve_address() {
  local ip=""
  if [[ -n "$CONTAINER" ]]; then
    ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$CONTAINER" 2>/dev/null | awk '{print $1}')" || ip=""
    [[ -n "$ip" ]] || die "$EX_NOTREADY" "container $CONTAINER not found or has no network address"
    ADDRESS=$ip
  elif ((LOCAL)) && [[ -z "$ADDRESS" ]]; then
    ADDRESS=127.0.0.1
  fi
  PROBE_ADDR=$ADDRESS
  if ! is_ip "$ADDRESS"; then
    PROBE_ADDR="$(getent ahostsv4 "$ADDRESS" 2>/dev/null | awk 'NR==1{print $1}')" || PROBE_ADDR=""
    [[ -n "$PROBE_ADDR" ]] || die "$EX_NOTREADY" "cannot resolve node address $ADDRESS"
  fi
}
resolve_address

# shellcheck disable=SC2317  # node_get is invoked indirectly through retry
node_get() { # <path> — mTLS GET against the worker proxy
  local ra=$PROBE_ADDR
  [[ "$ra" == *:* ]] && ra="[$ra]"
  vs_http GET "https://$SNI:$PORT$1" --ca "$CA_FILE" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    --resolve "$SNI:$PORT:$ra" --max-time 15
}

FAILURES=()
fail() { FAILURES+=("$1"); log_err "$1"; }

# ---------------------------------------------------------------------------------------------------
# 1. version over mTLS
# ---------------------------------------------------------------------------------------------------
log_step "node $NODE ($ADDRESS): mTLS probe of https://$SNI:$PORT"
if ! retry 3 2 node_get /api/version; then
  if [[ "$VS_HTTP_CODE" == 000 ]]; then
    die "$EX_NOTREADY" "worker proxy not reachable/accepting our client certificate at $PROBE_ADDR:$PORT: ${VS_HTTP_BODY:0:200}"
  fi
  die "$EX_FAIL" "GET /api/version returned HTTP $VS_HTTP_CODE"
fi
NODE_VERSION="$(jq -r '.version // empty' <<<"$VS_HTTP_BODY" 2>/dev/null || true)"
if [[ "$NODE_VERSION" == "$EXPECT_VERSION" ]]; then
  log_ok "Ollama version $NODE_VERSION (pinned $EXPECT_VERSION)"
else
  fail "Ollama version is '${NODE_VERSION:-unknown}', expected the pinned $EXPECT_VERSION"
fi

# ---------------------------------------------------------------------------------------------------
# 2. 11434 must be loopback-only
# ---------------------------------------------------------------------------------------------------
# shellcheck disable=SC2016  # $0/$1 are expanded by the inner bash, not here
tcp_open() { timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>/dev/null; }

check_loopback_only() {
  local exposed=0 bind
  if [[ -n "$CONTAINER" ]]; then
    bind="$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$CONTAINER" 2>/dev/null || echo '{}')"
    if jq -e '[to_entries[] | select(.key | startswith("11434/")) | .value[]? | select(.HostIp != "127.0.0.1" and .HostIp != "::1")] | length > 0' <<<"$bind" >/dev/null 2>&1; then
      exposed=1
    fi
  elif ((LOCAL)); then
    if vs_have ss; then
      if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E ':11434$' | grep -Ev '^(127\.0\.0\.1|\[::1\]):11434$' >/dev/null; then exposed=1; fi
    else
      log_warn "ss not available — loopback-only check for 11434 limited to a connect test"
    fi
  fi
  if [[ "$PROBE_ADDR" != 127.0.0.1 && "$PROBE_ADDR" != "::1" ]] && tcp_open "$PROBE_ADDR" 11434; then exposed=1; fi
  if ((exposed)); then
    log_err "Ollama port 11434 is reachable beyond loopback on $ADDRESS — bind OLLAMA_HOST=127.0.0.1:11434 and expose only the mTLS proxy ($PORT)"
    exit "$EX_POLICY"
  fi
  log_ok "11434 is not exposed beyond loopback"
}
check_loopback_only

# ---------------------------------------------------------------------------------------------------
# 3. required tags
# ---------------------------------------------------------------------------------------------------
log_step "model inventory"
if retry 3 2 node_get /api/tags; then
  mapfile -t NODE_TAGS < <(jq -r '.models[]? | (.name // .model)' <<<"$VS_HTTP_BODY")
  for m in "${REQUIRED[@]}"; do
    present=0
    for t in "${NODE_TAGS[@]}"; do
      if [[ "$t" == "$m" || "$t" == "$m:latest" ]]; then present=1; break; fi
    done
    if ((present)); then log_ok "model $m present"; else fail "required model $m is not present on the node (have: $(vs_join , "${NODE_TAGS[@]}"))"; fi
  done
else
  fail "GET /api/tags failed (HTTP $VS_HTTP_CODE)"
fi

# ---------------------------------------------------------------------------------------------------
# 4. blob SHA-256 vs models.json
# ---------------------------------------------------------------------------------------------------
if [[ -n "$CONTAINER" ]]; then
  BLOB_SOURCE="container:$CONTAINER"
  models_io_exists() { docker exec "$CONTAINER" test -f "$CONT_MODELS/$1" </dev/null 2>/dev/null; }
  models_io_read() { docker exec "$CONTAINER" cat "$CONT_MODELS/$1" </dev/null; }
  models_io_hash() { docker exec "$CONTAINER" sha256sum "$CONT_MODELS/$1" </dev/null | cut -d' ' -f1; }
elif [[ -n "$MODELS_DIR" ]]; then
  BLOB_SOURCE="dir:$MODELS_DIR"
fi

if [[ "$BLOB_SOURCE" == none ]]; then
  if ((RELEASE)); then
    log_err "release/air-gap mode: the model store cannot be verified — pass --models-dir DIR or --container NAME"
    exit "$EX_POLICY"
  fi
  log_warn "model blobs NOT verified against models.json (no --models-dir/--container)"
else
  log_step "verifying weight blobs against $MODELS_JSON ($BLOB_SOURCE)"
  for m in "${REQUIRED[@]}"; do
    rc=0
    models_check_pin "$MODELS_JSON" "$m" || rc=$?
    case "$rc" in
      0) log_ok "$MODELS_RESULT"; PINNED_COUNT=$((PINNED_COUNT + 1)) ;;
      3)
        SENTINEL_COUNT=$((SENTINEL_COUNT + 1))
        if ((RELEASE)); then log_err "$MODELS_RESULT — refused under --release/air-gap (run scripts/pin-model-digests.mjs)"; exit "$EX_POLICY"; fi
        log_warn "$MODELS_RESULT" ;;
      *)
        if [[ "$MODELS_RESULT" == *mismatch* || "$MODELS_RESULT" == *tampered* ]]; then
          log_err "$MODELS_RESULT"
          exit "$EX_POLICY"
        fi
        fail "$MODELS_RESULT" ;;
    esac
  done
fi

if ((${#FAILURES[@]})); then
  log_err "node $NODE failed ${#FAILURES[@]} check(s) — not registered"
  exit "$EX_FAIL"
fi

# ---------------------------------------------------------------------------------------------------
# 5. register
# ---------------------------------------------------------------------------------------------------
if [[ -n "$CONTAINER" ]]; then DISCOVERY=compose-alias; else DISCOVERY=dns-hosts; fi
if [[ "$DISCOVERY" == dns-hosts && ( "$ADDRESS" == 127.* || "$ADDRESS" == "::1" || "$ADDRESS" == localhost ) ]]; then
  die "$EX_USAGE" "refusing to register the loopback address $ADDRESS for DNS discovery — pass the node's routable --address"
fi
if [[ "$DISCOVERY" == dns-hosts ]] && ! is_ip "$ADDRESS"; then
  ADDRESS=$PROBE_ADDR
fi

ENTRY="$(jq -S -n --arg node "$NODE" --arg addr "$ADDRESS" --argjson port "$PORT" --arg sni "$SNI" --arg ver "$NODE_VERSION" \
  --arg disc "$DISCOVERY" --arg blobs "$BLOB_SOURCE" --argjson pinned "$PINNED_COUNT" --argjson sentinel "$SENTINEL_COUNT" \
  --arg rel "$(jq -r '.releaseTag' "$MODELS_JSON")" --argjson models "$(printf '%s\n' "${REQUIRED[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
  '{node: $node, address: $addr, port: $port, sni: $sni, discovery: $disc, ollamaVersion: $ver, models: $models,
    verification: {blobSource: $blobs, pinnedVerified: $pinned, sentinelPins: $sentinel, releaseTag: $rel}}')"

if ((VS_DRY_RUN)); then
  log_dry "would write $INVENTORY_DIR/$NODE.json: $(jq -c . <<<"$ENTRY")"
else
  mkdir -p "$INVENTORY_DIR"
  if [[ -f "$INVENTORY_DIR/$NODE.json" ]] && [[ "$(jq -S -c 'del(.enrolled)' "$INVENTORY_DIR/$NODE.json")" == "$(jq -c . <<<"$ENTRY")" ]]; then
    log_ok "inventory entry $NODE already up to date"
  else
    jq --arg ts "$(vs_now_iso)" '. + {enrolled: $ts}' <<<"$ENTRY" | vs_atomic_write "$INVENTORY_DIR/$NODE.json" 0644
    log_ok "wrote inventory $INVENTORY_DIR/$NODE.json"
  fi
fi
regenerate_hosts

if [[ "$DISCOVERY" == dns-hosts ]]; then
  log_info "DNS: publish  ollama-workers. IN A $ADDRESS   (port $PORT, mTLS); the LB re-resolves within ~10 s — no reload needed"
else
  log_info "compose worker: reachable through the network alias ollama-workers on the inference network — nothing else to register"
fi

# ---------------------------------------------------------------------------------------------------
# 6. gateway confirmation
# ---------------------------------------------------------------------------------------------------
if ((SKIP_GATEWAY)); then
  log_warn "gateway confirmation skipped (--skip-gateway)"
else
  polls=0
  max_polls=$((WAIT / 5))
  opts=(--ca "$CA_FILE" --max-time 10)
  for r in "${GATEWAY_RESOLVE[@]}"; do opts+=(--resolve "$r"); done
  while :; do
    rc=0
    vs_http GET "$GATEWAY_URL/health" "${opts[@]}" || rc=$?
    if ((rc == 0)) && [[ "$(jq -r '.backend.reachable // false' <<<"$VS_HTTP_BODY" 2>/dev/null)" == true ]]; then
      log_ok "gateway /health: status $(jq -r '.status // "?"' <<<"$VS_HTTP_BODY"), Ollama backend reachable"
      break
    fi
    if ((polls >= max_polls)); then
      log_err "gateway $GATEWAY_URL/health did not report backend.reachable=true within ${WAIT}s (HTTP $VS_HTTP_CODE) — the node is registered; check DNS for ollama-workers and the gateway logs"
      exit "$EX_FAIL"
    fi
    polls=$((polls + 1))
    vs_sleep 5
  done
fi

printf 'enrolled: node=%s address=%s version=%s models=%s blobs=%s\n' "$NODE" "$ADDRESS" "$NODE_VERSION" "${#REQUIRED[@]}" "$BLOB_SOURCE"
exit "$EX_OK"
