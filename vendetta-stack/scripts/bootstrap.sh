#!/usr/bin/env bash
#
# bootstrap.sh — one-command bring-up helper for the vendetta-stack (preflight → secrets → PKI → .env → summary).
#
# Traces: PROMPT §3 Phase 3 scripts/bootstrap.sh; CONTRACT §0 (shell rules), §2 (secret names, PKI file names,
#         FailClosed), §8.6 (<svc>.pem for HAProxy), §12 (hygiene: secrets/pki/.env are git-ignored, files only).
#
# What it does (every step is idempotent and never rotates anything silently):
#   1. FailClosed policy   CS3_PROFILE=onprem|airgap plus any cloud LLM credential (GEMINI/DEEPSEEK/OPENAI/
#                          ANTHROPIC/LLM_API_KEY, or *_FILE variants; LLM_API_KEY is allowed only when LLM_API_BASE
#                          points at the local gateway) → prints "FailClosedError" (variable NAMES only) and exits 3.
#   2. Preflight           docker ≥ 24 + Compose v2, vm.max_map_count ≥ 262144, free disk/RAM, host ports free,
#                          openssl + jq present.
#   3. Secrets             $STACK/secrets/{opensearch_admin_password,llm_gateway_token,errow_api_token,
#                          grafana_admin_password,feedback_webhook_token,vendetta_api_password,cs3_approval_token}:
#                          created ONLY when
#                          missing/empty. Passwords: 32 chars, upper+lower+digit+special (.*+-); tokens: 256-bit hex.
#                          Files are written without a trailing newline, mode 0600 (0640 with --key-group,
#                          0644 with --dev-readable-secrets), directory 0700.
#                          Also $STACK/secrets/approval/ (ERROW_FEEDBACK_APPROVAL_DIR; mode 0700, 0750 with
#                          --key-group, 0755 with --dev-readable-secrets) so the compose bind mount of
#                          /run/approval is not auto-created root-owned. The feedback_approval_key inside it is
#                          NEVER generated (live feedback is opt-in, see errow/feedback-loop/APPROVALS.md); a
#                          NOTE row says so, and --check fails when ERROW_FEEDBACK_LIVE=true and it is missing.
#   4. PKI                 $STACK/pki/: private CA (ca.crt 0644, ca.key 0600) + per-service <svc>.crt/.key/.pem for
#                          opensearch fluentd-1 fluentd-2 fluent-bit llm-gateway ollama-lb ollama-1 mock-ollama
#                          errow-mcp errow errow-feedback prometheus (+ vendetta-manager, opensearch-dashboards,
#                          and opensearch-admin.* = the OpenSearch admin-DN client cert). SAN = service DNS name(s)
#                          + localhost + 127.0.0.1; EKU serverAuth+clientAuth; subject CN=<svc>,O=Vendetta Stack.
#                          Algorithm: ECDSA P-384 by default (CA and leaves; sha384), --pki-algo rsa → RSA 4096 CA /
#                          3072 leaves. Existing certificates are kept while valid (> PKI_RENEW_DAYS=30 days left,
#                          chain to ca.crt, SAN/EKU as expected, key matches); otherwise the old set is archived to
#                          pki-archive/<ts>/ (PKI_ARCHIVE_DIR, 0700, OUTSIDE pki/ because compose mounts the whole
#                          pki/ tree into OpenSearch, which cannot boot with an unreadable subdirectory) and
#                          re-issued. A legacy pki/archive/ or pki/.mkcert/ is moved there. Modes: openssl
#                          (default), step-ca (needs `step` CLI), mkcert (local smoke only; ignores PKI_DAYS).
#   5. .env                rendered from .env.example ONLY if .env is absent (mode 0600; never overwritten).
#   6. Summary             what was created/kept + next steps (incl. key-ownership guidance for non-root containers).
#
# Key readability: container users (uid 10001/1000/999/100 …) can only read 0600 keys they own. Choose ONE of
#   • chown/ACL: sudo chown <uid> pki/<svc>.key  /  setfacl -m u:<uid>:r pki/<svc>.key  (default 0600 stays)
#   • --key-group GID  → keys + secrets 0640 group GID, add `group_add: ["GID"]` to the compose services
#   • --dev-readable-keys → 0644 keys (local development only; never on shared hosts)
#
# Usage: scripts/bootstrap.sh [options]        (see --help)
#
# Exit codes: 0 ok | 1 unexpected failure | 2 usage | 3 FailClosedError (policy) | 4 preflight failed
#             5 --check found problems

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
bootstrap.sh — preflight, secrets, PKI and .env for the vendetta-stack.

Usage: scripts/bootstrap.sh [options]

General:
  --check                    validate everything (preflight, FailClosed, secrets, PKI, .env); write nothing; exit 5 on problems
  --dry-run                  show what would be created; write nothing
  --skip-preflight           skip the docker/kernel/disk/RAM/port checks (CI, containers)
  --no-secrets | --no-pki | --no-env    skip that step
  --stack-dir DIR            stack root (default: parent of scripts/)
  --ports "P1 P2 …"          host ports to require free (default: 9200 5601 3000 9090 9093 24224 9880 2020 9101 8765)
  -q, --quiet | -v, --verbose
  -h, --help

Secrets:
  --dev-readable-secrets     secret files 0644 instead of 0600 (local development only)
  --key-group GID            keys and secrets mode 0640, group GID (pair with compose group_add)

PKI:
  --pki openssl|step-ca|mkcert   issuer (default openssl)
  --pki-algo ec|rsa              ec = ECDSA P-384 (default); rsa = RSA 4096 CA / 3072 leaves
  --pki-days N                   leaf validity in days (default 397, env PKI_DAYS)
  --ca-days N                    CA validity in days (default 3650, env PKI_CA_DAYS)
  --ca-passphrase-file FILE      encrypt ca.key with this passphrase file (openssl mode)
  --extra-services A,B           additional service names to issue certificates for
  --dev-readable-keys            keys 0644 (container uids can read them; local development only)
  --step-ca-url URL --step-ca-root FILE | --step-ca-fingerprint SHA256
  --step-provisioner NAME --step-password-file FILE      (step-ca mode)

.env:
  --set KEY=VALUE            override a value while rendering a NEW .env (repeatable; secret values are refused,
                             use KEY_FILE=… paths instead)

Environment: STACK_DIR, SECRETS_DIR, PKI_DIR, ENV_FILE, PKI_*, MIN_DISK_GB (20), MIN_RAM_MB (6144),
             VS_WORK_ROOT (scratch, default $STACK/.scratch), NO_COLOR.

Exit codes: 0 ok | 1 failure | 2 usage | 3 FailClosedError | 4 preflight failed | 5 --check found problems
EOF
}

MODE_CHECK=0
SKIP_PREFLIGHT=0
DO_SECRETS=1
DO_PKI=1
DO_ENV=1
DEV_SECRETS=0
PORTS="${BOOTSTRAP_PORTS:-9200 5601 3000 9090 9093 24224 9880 2020 9101 8765}"
MIN_DISK_GB="${MIN_DISK_GB:-20}"
MIN_RAM_MB="${MIN_RAM_MB:-6144}"
SET_ARGS=()
FAILS=0
WARNS=0
CREATED=()
KEPT=()

parse_args() {
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]:-}"
  while (($#)); do
    if [[ -z "$1" ]]; then shift; continue; fi
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --check) MODE_CHECK=1; shift ;;
      --dry-run) VS_DRY_RUN=1; shift ;;
      --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
      --no-secrets) DO_SECRETS=0; shift ;;
      --no-pki) DO_PKI=0; shift ;;
      --no-env) DO_ENV=0; shift ;;
      -q|--quiet) VS_QUIET=1; shift ;;
      -v|--verbose) VS_VERBOSE=1; shift ;;
      --stack-dir) vs_need "$@"; reroot "$2"; shift 2 ;;
      --ports) vs_need "$@"; PORTS=$2; shift 2 ;;
      --dev-readable-secrets) DEV_SECRETS=1; shift ;;
      --dev-readable-keys) PKI_DEV_READABLE_KEYS=1; shift ;;
      --key-group) vs_need "$@"; PKI_KEY_GROUP=$2; shift 2 ;;
      --pki) vs_need "$@"; PKI_MODE=$2; shift 2 ;;
      --pki-algo) vs_need "$@"; PKI_ALGO=$2; shift 2 ;;
      --pki-days) vs_need "$@"; PKI_DAYS=$2; shift 2 ;;
      --ca-days) vs_need "$@"; PKI_CA_DAYS=$2; shift 2 ;;
      --ca-passphrase-file) vs_need "$@"; PKI_CA_PASSPHRASE_FILE=$2; shift 2 ;;
      --extra-services) vs_need "$@"; PKI_EXTRA_SERVICES=$2; shift 2 ;;
      --step-ca-url) vs_need "$@"; PKI_STEP_URL=$2; shift 2 ;;
      --step-ca-root) vs_need "$@"; PKI_STEP_ROOT=$2; shift 2 ;;
      --step-ca-fingerprint) vs_need "$@"; PKI_STEP_FINGERPRINT=$2; shift 2 ;;
      --step-provisioner) vs_need "$@"; PKI_STEP_PROVISIONER=$2; shift 2 ;;
      --step-password-file) vs_need "$@"; PKI_STEP_PASSWORD_FILE=$2; shift 2 ;;
      --set) vs_need "$@"; SET_ARGS+=("$2"); shift 2 ;;
      *) die "$EX_USAGE" "unknown option: $1 (see --help)" ;;
    esac
  done
}

reroot() {
  [[ -d "$1" ]] || die "$EX_USAGE" "stack dir not found: $1"
  STACK_DIR="$(cd "$1" && pwd)"
  SECRETS_DIR="$STACK_DIR/secrets"
  PKI_DIR="$STACK_DIR/pki"
  PKI_ARCHIVE_DIR="${VS_PKI_ARCHIVE_ENV:-$STACK_DIR/pki-archive}"
  ENV_FILE="$STACK_DIR/.env"
}

# --- result rows --------------------------------------------------------------------------------------
row() { # <STATUS> <item> <detail>
  local st=$1 col=""
  case "$st" in
    OK) col=$O_GRN ;;
    WARN) col=$O_YEL; WARNS=$((WARNS + 1)) ;;
    FAIL) col=$O_RED; FAILS=$((FAILS + 1)) ;;
    SKIP|NEW|KEEP|NOTE) col="" ;;
  esac
  printf '%s%-5s%s %-34s %s\n' "$col" "$st" "$O_RST" "$2" "$3"
}

# --- 1. FailClosed ------------------------------------------------------------------------------------
step_failclosed() {
  local rc=0
  vs_failclosed_check || rc=$?
  if ((rc != 0)); then
    echo "bootstrap: refusing to continue (FailClosedError). Remove the listed variables from the environment/.env or use CS3_PROFILE=cloud|edge." >&2
    exit "$EX_POLICY"
  fi
  row OK "failclosed" "profile '$(vs_cfg CS3_PROFILE "unset")': no cloud LLM credentials present"
}

# --- 2. Preflight -------------------------------------------------------------------------------------
listening_ports() {
  if vs_have ss; then ss -H -ltn 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}'
  elif vs_have netstat; then netstat -ltn 2>/dev/null | awk 'NR>2{n=split($4,a,":"); print a[n]}'
  else return 1
  fi
}

project_published_ports() {
  vs_have docker || return 0
  docker ps --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" --format '{{.Ports}}' 2>/dev/null \
    | grep -oE ':[0-9]+->' | tr -d ':>-' || true
}

step_preflight() {
  local dv cv mm free_kb free_gb mem_mb p listening="" own="" busy=() ports=()

  if ! vs_have docker; then
    row FAIL "docker" "not installed (need Docker Engine ≥ 24)"
  else
    dv="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
    if [[ -z "$dv" ]]; then
      row FAIL "docker daemon" "not reachable (is the daemon running and the user in the docker group?)"
    elif vs_version_ge "${dv%%[-+]*}" 24.0.0; then
      row OK "docker" "engine $dv"
    else
      row FAIL "docker" "engine $dv < 24"
    fi
    if cv="$(docker compose version --short 2>/dev/null)" && [[ "$cv" =~ ^v?[2-9] ]]; then
      row OK "docker compose" "v${cv#v}"
    elif vs_have docker-compose && cv="$(docker-compose version --short 2>/dev/null)" && [[ "$cv" =~ ^v?[2-9] ]]; then
      row OK "docker-compose" "standalone v${cv#v}"
    else
      row FAIL "docker compose" "Compose v2 not found (install the docker-compose-plugin)"
    fi
  fi

  if [[ -r /proc/sys/vm/max_map_count ]]; then
    mm="$(</proc/sys/vm/max_map_count)"
    if ((mm >= 262144)); then row OK "vm.max_map_count" "$mm"
    else row FAIL "vm.max_map_count" "$mm < 262144 → sudo sysctl -w vm.max_map_count=262144 (persist in /etc/sysctl.d/99-vendetta.conf)"
    fi
  else
    row WARN "vm.max_map_count" "not readable here; Docker Desktop/macOS users must set it ≥ 262144 inside the VM"
  fi

  free_kb="$(df -Pk "$STACK_DIR" 2>/dev/null | awk 'NR==2{print $4}')"
  if vs_is_uint "$free_kb"; then
    free_gb=$((free_kb / 1048576))
    if ((free_gb >= MIN_DISK_GB)); then row OK "disk" "${free_gb} GB free (≥ ${MIN_DISK_GB})"
    else row FAIL "disk" "${free_gb} GB free < ${MIN_DISK_GB} GB (model blobs + indices need space; MIN_DISK_GB overrides)"
    fi
  else
    row WARN "disk" "cannot determine free space"
  fi

  if [[ -r /proc/meminfo ]]; then
    mem_mb="$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)"
    if ((mem_mb < MIN_RAM_MB)); then row FAIL "memory" "${mem_mb} MB < ${MIN_RAM_MB} MB minimum"
    elif ((mem_mb < 16384)); then row WARN "memory" "${mem_mb} MB — fine for the mock-llm smoke profile; 16 GB+ recommended, real LLM nodes need far more"
    else row OK "memory" "${mem_mb} MB"
    fi
  else
    row WARN "memory" "cannot determine RAM"
  fi

  local t
  for t in openssl jq curl; do
    if vs_have "$t"; then row OK "tool: $t" "$(command -v "$t")"; else row FAIL "tool: $t" "not installed"; fi
  done

  IFS=' ' read -r -a ports <<<"$PORTS"
  if listening="$(listening_ports)"; then
    own="$(project_published_ports)"
    for p in "${ports[@]}"; do
      vs_valid_port "$p" || { row FAIL "ports" "invalid port '$p'"; continue; }
      if grep -qx -- "$p" <<<"$listening" && ! grep -qx -- "$p" <<<"$own"; then busy+=("$p"); fi
    done
    if ((${#busy[@]})); then row FAIL "host ports" "already in use: $(vs_join " " "${busy[@]}")"
    else row OK "host ports" "free: $(vs_join " " "${ports[@]}")"
    fi
  else
    row WARN "host ports" "neither ss nor netstat available — port check skipped"
  fi
}

# --- 3. Secrets ---------------------------------------------------------------------------------------
secret_mode() {
  if [[ -n "$PKI_KEY_GROUP" ]]; then printf '0640'
  elif ((DEV_SECRETS)); then printf '0644'
  else printf '0600'
  fi
}

step_secrets() {
  local name f mode val
  mode="$(secret_mode)"
  if [[ -e "$SECRETS_DIR" && ! -d "$SECRETS_DIR" ]]; then die "$EX_FAIL" "$SECRETS_DIR exists and is not a directory"; fi
  if ((MODE_CHECK)); then
    [[ -d "$SECRETS_DIR" ]] || row FAIL "secrets/" "directory missing (run bootstrap.sh)"
  elif ((VS_DRY_RUN)); then
    [[ -d "$SECRETS_DIR" ]] || log_dry "would create $SECRETS_DIR (0700)"
  else
    (umask 077; mkdir -p "$SECRETS_DIR")
    chmod 0700 "$SECRETS_DIR"
  fi
  for name in "${VS_SECRET_NAMES[@]}"; do
    f="$SECRETS_DIR/$name"
    if [[ -d "$f" ]]; then
      row FAIL "secret $name" "is a directory (Docker creates one when a bind-mounted file is missing) — remove it and re-run"
      continue
    fi
    if [[ -s "$f" ]]; then
      if ((MODE_CHECK)); then check_secret "$name" "$f" "$mode"; else keep_secret "$name" "$f" "$mode"; fi
      continue
    fi
    if ((MODE_CHECK)); then row FAIL "secret $name" "missing or empty"; continue; fi
    if ((VS_DRY_RUN)); then row NEW "secret $name" "would be generated (mode $mode)"; CREATED+=("secrets/$name"); continue; fi
    case "$name" in
      *_password) val="$(vs_gen_password 32)" ;;
      *) val="$(vs_gen_token 32)" ;;
    esac
    printf '%s' "$val" | vs_atomic_write "$f" "$mode"
    val=""
    if [[ -n "$PKI_KEY_GROUP" ]]; then chgrp "$PKI_KEY_GROUP" "$f" 2>/dev/null || log_warn "cannot chgrp $f to $PKI_KEY_GROUP"; fi
    CREATED+=("secrets/$name")
    row NEW "secret $name" "generated (mode $mode)"
  done
}

# Errow feedback approval directory: compose bind-mounts ${ERROW_FEEDBACK_APPROVAL_DIR:-./secrets/approval} read-only
# at /run/approval; when it is missing Docker creates it root-owned. The directory is created here, the key inside it
# (feedback_approval_key) never is — live feedback is opt-in and the operator generates that key (APPROVALS.md).
approval_dir() {
  local d
  d="$(vs_cfg ERROW_FEEDBACK_APPROVAL_DIR ./secrets/approval)"
  case "$d" in
    /*) printf '%s' "$d" ;;
    *) printf '%s/%s' "$STACK_DIR" "${d#./}" ;;
  esac
}

approval_dir_mode() {
  if [[ -n "$PKI_KEY_GROUP" ]]; then printf '0750'
  elif ((DEV_SECRETS)); then printf '0755'
  else printf '0700'
  fi
}

step_approval_dir() {
  local d mode cur key live
  d="$(approval_dir)"
  mode="$(approval_dir_mode)"
  key="$d/feedback_approval_key"
  live="$(vs_cfg ERROW_FEEDBACK_LIVE false)"
  if [[ -e "$d" && ! -d "$d" ]]; then
    row FAIL "approval dir" "${d#"$STACK_DIR"/} exists and is not a directory"
    return 0
  fi
  if [[ -d "$d" ]]; then
    cur="$(vs_file_mode "$d")"
    if ((MODE_CHECK)); then
      if vs_mode_looser "$cur" "$mode"; then row FAIL "approval dir" "mode $cur is looser than $mode"; else row OK "approval dir" "present, mode $cur"; fi
    else
      if [[ "$cur" != "${mode#0}" && "$cur" != "$mode" ]]; then
        if ((VS_DRY_RUN)); then log_dry "would chmod $mode $d (was $cur)"; else chmod "$mode" "$d"; log_info "approval dir: mode $cur → $mode"; fi
      fi
      KEPT+=("${d#"$STACK_DIR"/}")
      row KEEP "approval dir" "exists — kept"
    fi
  elif ((MODE_CHECK)); then
    row FAIL "approval dir" "${d#"$STACK_DIR"/} missing — compose would auto-create it root-owned (run bootstrap.sh)"
  elif ((VS_DRY_RUN)); then
    row NEW "approval dir" "would be created (mode $mode)"
    CREATED+=("${d#"$STACK_DIR"/}")
  else
    (umask 077; mkdir -p "$d")
    chmod "$mode" "$d"
    if [[ -n "$PKI_KEY_GROUP" ]]; then chgrp "$PKI_KEY_GROUP" "$d" 2>/dev/null || log_warn "cannot chgrp $d to $PKI_KEY_GROUP"; fi
    CREATED+=("${d#"$STACK_DIR"/}")
    row NEW "approval dir" "created (mode $mode)"
  fi
  local keys authority=0
  keys="$d/keys"
  # the per-approver key directory is where approval.py keygen writes; create it so operators have a target
  if [[ -d "$d" && ! -e "$keys" ]]; then
    if ((MODE_CHECK)); then
      row NOTE "approval keys" "keys/ missing — create it (approval.py keygen writes there)"
    elif ((VS_DRY_RUN)); then
      row NOTE "approval keys" "would be created (mode $mode)"
    else
      (umask 077; mkdir -p "$keys")
      chmod "$mode" "$keys"
      if [[ -n "$PKI_KEY_GROUP" ]]; then chgrp "$PKI_KEY_GROUP" "$keys" 2>/dev/null || log_warn "cannot chgrp $keys to $PKI_KEY_GROUP"; fi
      row NEW "approval keys" "created empty (mode $mode) — populate with approval.py keygen"
    fi
  fi
  if [[ -s "$key" ]]; then
    authority=1
    if ((MODE_CHECK)) && vs_mode_looser "$(vs_file_mode "$key")" "$(secret_mode)"; then
      row WARN "feedback_approval_key" "mode $(vs_file_mode "$key") is looser than $(secret_mode)"
    else
      row KEEP "feedback_approval_key" "present — never touched by bootstrap"
    fi
  elif [[ "$live" == true ]]; then
    if ((MODE_CHECK)); then
      row FAIL "feedback_approval_key" "ERROW_FEEDBACK_LIVE=true but the key is missing — generate it per errow/feedback-loop/APPROVALS.md"
    else
      row WARN "feedback_approval_key" "ERROW_FEEDBACK_LIVE=true but the key is missing — generate it per errow/feedback-loop/APPROVALS.md"
    fi
  else
    row NOTE "feedback_approval_key" "not generated: live feedback is opt-in; the operator creates it per errow/feedback-loop/APPROVALS.md"
  fi
  step_approval_keys "$d" "$key" "$live" "$authority"
}

# Per-approver keys ($d/keys/<approver>.key, 0600) are what makes approvals dual-control: one person's key cannot
# sign for another, and ERROW_FEEDBACK_APPROVAL_THRESHOLD (default 2) distinct approvers are required. A deployment
# that only has the shared key keeps working (the threshold clamps to the authorities available), so this check
# reports rather than fails unless live feedback is on.
step_approval_keys() { # <approval-dir> <shared-key> <live> <shared-key-present>
  local d=$1 key=$2 live=$3 authority=$4 k keys approvers=() loose=() short=() threshold n
  keys="$d/keys"
  if [[ -e "$keys" && ! -d "$keys" ]]; then
    row FAIL "approval keys" "${keys#"$STACK_DIR"/} exists and is not a directory"
    return 0
  fi
  if [[ -d "$keys" ]]; then
    for k in "$keys"/*.key; do
      [[ -f "$k" ]] || continue
      approvers+=("$(basename "$k" .key)")
      authority=1
      if vs_mode_looser "$(vs_file_mode "$k")" 0600; then loose+=("$(basename "$k")"); fi
      if (($(vs_file_size "$k") < 32)); then short+=("$(basename "$k")"); fi
    done
    if ((${#loose[@]})); then row FAIL "approval keys" "per-approver key(s) looser than 0600: ${loose[*]}"; fi
    if ((${#short[@]})); then row FAIL "approval keys" "per-approver key(s) shorter than 32 characters: ${short[*]}"; fi
    if ((MODE_CHECK)) && vs_mode_looser "$(vs_file_mode "$keys")" "$(approval_dir_mode)"; then
      row WARN "approval keys" "keys/ mode $(vs_file_mode "$keys") is looser than $(approval_dir_mode)"
    elif ((${#approvers[@]})); then
      row KEEP "approval keys" "${#approvers[@]} per-approver key(s) — never touched by bootstrap"
    fi
  fi
  if ((authority == 0)); then
    row NOTE "approval keys" "no per-approver keys: add one per approver with approval.py keygen for dual control"
    return 0
  fi
  threshold="$(vs_cfg ERROW_FEEDBACK_APPROVAL_THRESHOLD 2)"
  if ! vs_is_uint "$threshold" || ((threshold < 1)); then
    row FAIL "approval threshold" "ERROW_FEEDBACK_APPROVAL_THRESHOLD must be a positive integer (got '$threshold')"
    return 0
  fi
  n=${#approvers[@]}
  if [[ -s "$key" ]]; then n=$((n + 1)); fi   # the shared key can carry one distinct approval
  if ((${#approvers[@]} == 0)); then
    # shared key only: approval.py clamps the threshold to 1
    if ((threshold > 1)); then
      row WARN "approval threshold" "threshold $threshold but only the shared key exists — approval.py clamps it to 1 (no dual control)"
    else
      row OK "approval threshold" "1 (shared key only)"
    fi
    return 0
  fi
  if ((n < threshold)); then
    if [[ "$live" == true ]] && ((MODE_CHECK)); then
      row FAIL "approval threshold" "threshold $threshold but only $n approver(s)/key(s) available — add keys with approval.py keygen"
    else
      row WARN "approval threshold" "threshold $threshold but only $n approver(s)/key(s) available — add keys with approval.py keygen"
    fi
  else
    row OK "approval threshold" "$threshold of $n approver key(s), shared key $([[ -s "$key" ]] && echo 'also present' || echo 'absent')"
  fi
}

keep_secret() { # existing secret: never touched, only the mode is normalised
  local name=$1 f=$2 mode=$3 cur
  cur="$(vs_file_mode "$f")"
  if [[ "$cur" != "${mode#0}" && "$cur" != "$mode" ]]; then
    if ((VS_DRY_RUN)); then log_dry "would chmod $mode $f (was $cur)"; else chmod "$mode" "$f"; log_info "secret $name: mode $cur → $mode"; fi
  fi
  KEPT+=("secrets/$name")
  row KEEP "secret $name" "exists — kept (never rotated silently)"
}

check_secret() {
  local name=$1 f=$2 mode=$3 cur pw
  cur="$(vs_file_mode "$f")"
  if vs_mode_looser "$cur" "$mode"; then
    row FAIL "secret $name" "mode $cur is looser than $mode"
    return 0
  fi
  if [[ "$name" == *_password ]]; then
    pw="$(<"$f")"
    if ! vs_password_strong "$pw"; then
      row WARN "secret $name" "weak (need ≥16 chars with upper/lower/digit/special) — rotate deliberately, bootstrap will not"
      return 0
    fi
  elif (($(vs_file_size "$f") < 32)); then
    row WARN "secret $name" "shorter than 32 chars"
    return 0
  fi
  row OK "secret $name" "present, mode $cur"
}

# --- 4. PKI -------------------------------------------------------------------------------------------
step_pki() {
  local svc had_ca=0
  pki_validate_config
  vs_require openssl
  if ((MODE_CHECK)); then check_pki; return 0; fi

  if ((VS_DRY_RUN)); then
    [[ -d "$PKI_DIR" ]] || log_dry "would create $PKI_DIR (0755)"
    if [[ ! -s "$PKI_DIR/ca.crt" ]]; then log_dry "would create the private CA ($PKI_MODE/$PKI_ALGO) in $PKI_DIR"; fi
  else
    mkdir -p "$PKI_DIR"
    chmod 0755 "$PKI_DIR"
    pki_ensure_archive_root
    if [[ -s "$PKI_DIR/ca.crt" ]]; then had_ca=1; fi
    pki_ensure_ca
    if ((had_ca)); then row KEEP "pki/ca.crt" "exists — kept"; else row NEW "pki/ca.crt" "private CA created ($PKI_MODE, $PKI_ALGO)"; CREATED+=("pki/ca.crt"); fi
  fi
  pki_migrate_legacy_archive

  pki_ensure_services 0
  for svc in "${PKI_ISSUED[@]}"; do row NEW "pki/$svc" "issued (${PKI_DAYS}d, EKU serverAuth+clientAuth)"; CREATED+=("pki/$svc"); done
  for svc in "${PKI_SKIPPED[@]}"; do row KEEP "pki/$svc" "valid — kept"; KEPT+=("pki/$svc"); done
  if ((VS_DRY_RUN == 0)); then pki_apply_modes; fi
}

# check_pki_tree — compose mounts pki/ wholesale at OpenSearch's config/certs (uid 1000); its security setup walks that
# tree and dies on any subdirectory it cannot read, so pki/ must hold files only and the archive must live outside.
check_pki_tree() {
  local d name mode
  for d in "$PKI_DIR"/* "$PKI_DIR"/.[!.]*; do
    [[ -d "$d" ]] || continue
    name="$(basename "$d")"
    case "$name" in
      archive|.mkcert)
        row FAIL "pki/$name" "legacy layout: move it to pki-archive/ (OpenSearch cannot read a subdirectory of the mounted pki/ tree) — 'bootstrap.sh' without --check migrates it" ;;
      *)
        mode="$(vs_file_mode "$d")"
        if (((8#$mode & 5) != 5)); then row FAIL "pki/$name/" "subdirectory with mode $mode is unreadable for container users — move it out of pki/"; fi ;;
    esac
  done
  case "$PKI_ARCHIVE_DIR/" in
    "$PKI_DIR"/*) row FAIL "pki-archive" "PKI_ARCHIVE_DIR ($PKI_ARCHIVE_DIR) is inside pki/ — it must be outside the mounted tree" ;;
    *)
      if [[ ! -d "$PKI_ARCHIVE_DIR" ]]; then
        row WARN "pki-archive" "missing — bootstrap.sh creates it (0700, previous certificate sets and old CAs are archived there)"
      else
        mode="$(vs_file_mode "$PKI_ARCHIVE_DIR")"
        if vs_mode_looser "$mode" 0700; then row FAIL "pki-archive" "mode $mode is looser than 0700 (holds archived private keys)"; else row OK "pki-archive" "outside pki/, mode $mode"; fi
      fi ;;
  esac
}

check_pki() {
  local svc cur ca="$PKI_DIR/ca.crt" keymode
  keymode="$(pki_key_mode)"
  check_pki_tree
  if [[ ! -s "$ca" || ! -s "$PKI_DIR/ca.key" ]]; then
    row FAIL "pki/ca" "ca.crt/ca.key missing (step-ca mode only needs ca.crt)"
    [[ "$PKI_MODE" == step-ca && -s "$ca" ]] || return 0
  else
    cur="$(vs_file_mode "$PKI_DIR/ca.key")"
    if vs_mode_looser "$cur" 0600; then row FAIL "pki/ca.key" "mode $cur is looser than 0600"; else row OK "pki/ca.key" "mode $cur"; fi
    if pki_key_matches "$ca" "$PKI_DIR/ca.key" 2>/dev/null || [[ -n "$PKI_CA_PASSPHRASE_FILE" ]]; then row OK "pki/ca.crt" "$(pki_cert_days_left "$ca")d left, key matches"
    else row FAIL "pki/ca.crt" "ca.key does not match ca.crt"
    fi
  fi
  while IFS= read -r svc; do
    if pki_cert_check "$svc"; then
      cur="$(vs_file_mode "$PKI_DIR/$svc.key")"
      if vs_mode_looser "$cur" "$keymode"; then row FAIL "pki/$svc" "key mode $cur is looser than $keymode"
      else row OK "pki/$svc" "${PKI_DAYS_LEFT}d left, SAN/EKU/chain ok, key mode $cur"
      fi
    elif [[ "$PKI_REASON" == *"d left"* ]] && ((PKI_DAYS_LEFT >= 0)); then
      row WARN "pki/$svc" "$PKI_REASON — run scripts/rotate-certs.sh"
    else
      row FAIL "pki/$svc" "$PKI_REASON"
    fi
  done < <({ pki_all_services; printf '%s\n' "$PKI_ADMIN_SERVICE"; })
}

# --- 5. .env ------------------------------------------------------------------------------------------
secret_like_key() { [[ "$1" =~ (PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|PASSPHRASE|PRIVATE_KEY)$ ]] && [[ "$1" != *_FILE ]]; }

render_env() {
  local example="$STACK_DIR/.env.example" out kv k v tmp
  declare -A over=()
  for kv in "${SET_ARGS[@]:-}"; do
    [[ -n "$kv" ]] || continue
    [[ "$kv" == *=* ]] || die "$EX_USAGE" "--set expects KEY=VALUE (got '$kv')"
    k=${kv%%=*}; v=${kv#*=}
    [[ "$k" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "$EX_USAGE" "--set: invalid key '$k'"
    if secret_like_key "$k"; then die "$EX_USAGE" "--set refuses secret-looking key $k (values must live in files; set ${k}_FILE=/run/secrets/<name> instead)"; fi
    [[ "$v" != *$'\n'* ]] || die "$EX_USAGE" "--set: newline in value of $k"
    over[$k]=$v
  done
  tmp="$ENV_FILE.new.$$"
  vs_register_cleanup "$tmp"
  (
    umask 077
    : >"$tmp"
    local line key seen=" "
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" =~ ^([A-Z][A-Z0-9_]*)= && -n "${over[${BASH_REMATCH[1]}]+x}" ]]; then
        key=${BASH_REMATCH[1]}
        printf '%s=%s\n' "$key" "${over[$key]}" >>"$tmp"
        seen+="$key "
      else
        printf '%s\n' "$line" >>"$tmp"
      fi
    done <"$example"
    for key in "${!over[@]}"; do
      [[ "$seen" == *" $key "* ]] || printf '%s=%s\n' "$key" "${over[$key]}" >>"$tmp"
    done
  )
  out=$tmp
  chmod 0600 "$out"
  mv -f "$out" "$ENV_FILE"
}

step_env() {
  local example="$STACK_DIR/.env.example"
  if [[ -f "$ENV_FILE" ]]; then
    if ((${#SET_ARGS[@]})); then log_warn ".env already exists — --set values were NOT applied (edit .env yourself)"; fi
    KEPT+=(".env")
    row KEEP ".env" "exists — not overwritten"
    return 0
  fi
  if [[ ! -f "$example" ]]; then
    if ((MODE_CHECK)); then row WARN ".env" "no .env and no .env.example yet (compose defaults apply)"
    else row SKIP ".env" ".env.example not found (written by the compose/deploy step) — nothing rendered"
    fi
    return 0
  fi
  if ((MODE_CHECK)); then row FAIL ".env" "missing — run bootstrap.sh to render it from .env.example"; return 0; fi
  if ((VS_DRY_RUN)); then row NEW ".env" "would be rendered from .env.example"; CREATED+=(".env"); return 0; fi
  render_env
  CREATED+=(".env")
  row NEW ".env" "rendered from .env.example (mode 0600)"
}

check_gitignore() {
  local gi="$STACK_DIR/.gitignore" pat missing=()
  [[ -f "$gi" ]] || { row WARN ".gitignore" "none — secrets/, pki/ and .env must never be committed"; return 0; }
  for pat in secrets pki .env; do
    grep -Eq "^/?${pat//./\\.}/?\$" "$gi" || missing+=("$pat")
  done
  if ((${#missing[@]})); then row WARN ".gitignore" "does not ignore: $(vs_join ", " "${missing[@]}")"; else row OK ".gitignore" "ignores secrets/, pki/, .env"; fi
}

check_compose_config() {
  local f="$STACK_DIR/docker-compose.yml"
  [[ -f "$f" ]] || { row SKIP "compose config" "docker-compose.yml not present yet"; return 0; }
  vs_compose_init || { row SKIP "compose config" "Compose v2 unavailable"; return 0; }
  if "${COMPOSE[@]}" config --quiet >/dev/null 2>&1; then row OK "compose config" "valid"; else row WARN "compose config" "docker compose config failed (missing .env values or secrets?)"; fi
}

# --- summary ------------------------------------------------------------------------------------------
summary() {
  local mode_note
  echo
  if ((MODE_CHECK)); then
    if ((FAILS)); then echo "CHECK FAILED: $FAILS problem(s), $WARNS warning(s) — nothing was written."; else echo "CHECK PASSED: $WARNS warning(s) — nothing was written."; fi
    return 0
  fi
  if ((VS_DRY_RUN)); then echo "DRY RUN complete: ${#CREATED[@]} item(s) would be created, ${#KEPT[@]} kept — nothing was written."; return 0; fi
  mode_note="keys are mode $(pki_key_mode), secrets mode $(secret_mode)"
  cat <<EOF
Bootstrap complete: ${#CREATED[@]} item(s) created, ${#KEPT[@]} kept ($mode_note). $WARNS warning(s).

Next steps
  1. Key ownership: containers run as non-root users, so they must be able to read pki/*.key and secrets/*.
     Pick one — chown/setfacl the files to the container uid; or re-run with --key-group GID and add
     group_add: ["GID"] to the services; or (local dev only) --dev-readable-keys --dev-readable-secrets.
  2. Review .env (CS3_PROFILE, OLLAMA_* models, MCP_TARGETS_FILE) — it is git-ignored.
     Live Errow feedback actions (ERROW_FEEDBACK_LIVE=true) additionally need secrets/approval/feedback_approval_key,
     which you generate yourself — see errow/feedback-loop/APPROVALS.md.
  3. Start the stack:   docker compose -p $COMPOSE_PROJECT up -d     (add --profile mock-llm for the mock Ollama)
  4. Verify:            scripts/healthcheck.sh
  5. OpenSearch security identities (for opensearch.yml/roles): node DN  CN=opensearch,O=$PKI_ORG
                        admin DN  CN=opensearch-admin,O=$PKI_ORG   (pki/opensearch-admin.{crt,key})
  6. Back up pki/ and secrets/ (scripts/backup-opensearch.sh --include-secrets) — they are never stored in git.
EOF
}

main() {
  parse_args "$@"
  if ((MODE_CHECK && VS_DRY_RUN)); then die "$EX_USAGE" "--check and --dry-run are mutually exclusive"; fi
  if ((MODE_CHECK)); then VS_DRY_RUN=1; fi
  log_step "vendetta-stack bootstrap — stack: $STACK_DIR"
  step_failclosed
  if ((SKIP_PREFLIGHT)); then
    row SKIP "preflight" "skipped (--skip-preflight)"
  else
    step_preflight
    if ((FAILS && MODE_CHECK == 0)); then
      echo >&2
      die "$EX_PREREQ" "preflight failed ($FAILS problem(s)) — fix the FAIL rows above (or --skip-preflight at your own risk)"
    fi
  fi
  if ((DO_SECRETS)); then step_secrets; step_approval_dir; fi
  if ((DO_PKI)); then step_pki; fi
  if ((DO_ENV)); then step_env; fi
  if ((MODE_CHECK)); then
    check_gitignore
    check_compose_config
  fi
  if ((DO_ENV && MODE_CHECK == 0 && VS_DRY_RUN == 0)); then
    step_failclosed >/dev/null
  fi
  summary
  if ((MODE_CHECK && FAILS)); then exit "$EX_NOTREADY"; fi
  exit "$EX_OK"
}

main "$@"
