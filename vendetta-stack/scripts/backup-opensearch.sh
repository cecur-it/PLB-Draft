#!/usr/bin/env bash
#
# backup-opensearch.sh — OpenSearch snapshots + encrypted file backups for the vendetta-stack.
#
# Traces: PROMPT §3 Phase 3 scripts/backup-opensearch.sh; CONTRACT §2 (opensearch 9200 https + basic auth, secret
#         names, pki/), §4.5/§10 (ollama/models.json), CS3 deployment/ansible/playbooks/backup.yml and
#         deployment/operations/backup-restore.md (daily snapshot, verified restore, retention).
#
# What it does
#   1. Registers the filesystem snapshot repository `vendetta-snapshots` when missing (idempotent; the server needs
#      `path.repo: [/usr/share/opensearch/snapshots]` — set in opensearch/opensearch.yml — backed by a volume).
#   2. Creates a dated snapshot `vendetta-YYYYMMDD-HHMMSS` of vendetta-alerts-*, errow-*, cs3-ai-* (override with
#      --indices), waits for it and requires state SUCCESS with 0 failed shards.
#   3. Retention: keeps the newest --keep (default 14) `vendetta-*` snapshots, deletes older SUCCESS ones; snapshots
#      that were not created by this script (other prefixes) are never touched.
#   4. --verify-restore: restores up to --restore-sample indices of the new snapshot as `restore-test-<index>`, checks the
#      shards are searchable and the document count is readable, then deletes exactly those scratch indices.
#   5. File backup into <backup-dir>/<UTC timestamp>/: ollama-models.json, pki.tar.enc (the whole pki/ tree incl. the CA
#      key, always encrypted with `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` from a passphrase FILE), secrets.tar.enc
#      only with --include-secrets, SHA256SUMS and MANIFEST.json. Old backup directories beyond --keep are pruned.
#   --decrypt FILE --extract-to DIR restores such an archive (refuses unsafe member paths).
#
# Secrets are read from files only (admin password: $STACK/secrets/opensearch_admin_password; passphrase file mode must
# be 0600 or stricter) and never appear on argv or in logs. The default backup directory is $STACK/secrets/backups
# (git-ignored, 0700).
#
# Exit codes: 0 success | 1 snapshot/restore/verification failure | 2 usage | 3 policy refusal (loose passphrase file
#             permissions) | 4 missing prerequisite | 5 OpenSearch unreachable or credentials refused

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

trap 'vs_cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
backup-opensearch.sh — OpenSearch snapshot (+verified restore) and encrypted file backups.

Usage: scripts/backup-opensearch.sh [options]

Connection:
  --url URL                  OpenSearch base URL (default $OPENSEARCH_URL or https://localhost:9200)
  --resolve HOST:PORT:ADDR   pin a name to an address (TLS is verified against pki/ca.crt and the URL host name)
  --user NAME                (default admin)   --password-file F (default secrets/opensearch_admin_password)
  --ca F                     (default pki/ca.crt)
Snapshot:
  --repo NAME                snapshot repository (default vendetta-snapshots)
  --location PATH            server-side repository path (default /usr/share/opensearch/snapshots)
  --indices CSV              default vendetta-alerts-*,errow-*,cs3-ai-*
  --keep N                   retention for snapshots and file backups (default 14, minimum 1)
  --wait-timeout SECS        wait for the snapshot (default 3600)
  --verify-restore           restore a sample into restore-test-* indices, check, delete   (--restore-sample N, default 3)
  --snapshot-only | --files-only
Files:
  --backup-dir DIR           default $STACK/secrets/backups (created 0700)
  --passphrase-file F        encryption passphrase (>= 16 chars, mode 0600); required for pki/ and secrets archives
  --create-passphrase        generate the passphrase file when it does not exist (store a copy OFFLINE)
  --skip-pki                 do not archive pki/
  --include-secrets          also archive secrets/ (always encrypted; backups/ itself is excluded)
Restore helper:
  --decrypt FILE --extract-to DIR --passphrase-file F
General: --dry-run (no network calls, no writes)  --stack-dir DIR  -q  -v  -h

Exit codes: 0 ok | 1 snapshot/restore/verification failed | 2 usage | 3 policy | 4 prerequisite | 5 unreachable/auth
EOF
}

URL=""
RESOLVES=()
OS_USER="admin"
PASSWORD_FILE=""
CA_FILE=""
REPO="vendetta-snapshots"
LOCATION="/usr/share/opensearch/snapshots"
INDICES="vendetta-alerts-*,errow-*,cs3-ai-*"
KEEP=14
WAIT_TIMEOUT=3600
VERIFY_RESTORE=0
RESTORE_SAMPLE=3
DO_SNAPSHOT=1
DO_FILES=1
BACKUP_DIR=""
PASSPHRASE_FILE=""
CREATE_PASSPHRASE=0
SKIP_PKI=0
INCLUDE_SECRETS=0
DECRYPT_IN=""
EXTRACT_TO=""
SCRATCH_PREFIX="restore-test-"
RESTORED=()
SNAP=""
SNAP_STATE=""
SNAP_INDICES=()
PRUNED_SNAPSHOTS=()
FILES_DIR=""
PRUNED_DIRS=()

while (($#)); do
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]}"
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --url) vs_need "$@"; URL=$2; shift 2 ;;
    --resolve) vs_need "$@"; RESOLVES+=("$2"); shift 2 ;;
    --user) vs_need "$@"; OS_USER=$2; shift 2 ;;
    --password-file) vs_need "$@"; PASSWORD_FILE=$2; shift 2 ;;
    --ca) vs_need "$@"; CA_FILE=$2; shift 2 ;;
    --repo) vs_need "$@"; REPO=$2; shift 2 ;;
    --location) vs_need "$@"; LOCATION=$2; shift 2 ;;
    --indices) vs_need "$@"; INDICES=$2; shift 2 ;;
    --keep) vs_need "$@"; KEEP=$2; shift 2 ;;
    --wait-timeout) vs_need "$@"; WAIT_TIMEOUT=$2; shift 2 ;;
    --verify-restore) VERIFY_RESTORE=1; shift ;;
    --restore-sample) vs_need "$@"; RESTORE_SAMPLE=$2; shift 2 ;;
    --snapshot-only) DO_FILES=0; shift ;;
    --files-only) DO_SNAPSHOT=0; shift ;;
    --backup-dir) vs_need "$@"; BACKUP_DIR=$2; shift 2 ;;
    --passphrase-file) vs_need "$@"; PASSPHRASE_FILE=$2; shift 2 ;;
    --create-passphrase) CREATE_PASSPHRASE=1; shift ;;
    --skip-pki) SKIP_PKI=1; shift ;;
    --include-secrets) INCLUDE_SECRETS=1; shift ;;
    --decrypt) vs_need "$@"; DECRYPT_IN=$2; shift 2 ;;
    --extract-to) vs_need "$@"; EXTRACT_TO=$2; shift 2 ;;
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

vs_require curl jq openssl tar
if ! vs_is_uint "$KEEP" || ((KEEP < 1)); then die "$EX_USAGE" "--keep must be an integer >= 1"; fi
if ! vs_is_uint "$WAIT_TIMEOUT" || ((WAIT_TIMEOUT < 1)); then die "$EX_USAGE" "--wait-timeout must be a positive integer"; fi
if ! vs_is_uint "$RESTORE_SAMPLE" || ((RESTORE_SAMPLE < 1)); then die "$EX_USAGE" "--restore-sample must be an integer >= 1"; fi
[[ "$REPO" =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "$EX_USAGE" "--repo must be a lowercase repository name"
[[ "$LOCATION" == /* ]] || die "$EX_USAGE" "--location must be an absolute server-side path"
[[ "$INDICES" =~ ^[a-z0-9*._,-]+$ ]] || die "$EX_USAGE" "--indices may only contain lowercase letters, digits and * . _ , -"
[[ "$OS_USER" =~ ^[A-Za-z0-9._@-]+$ ]] || die "$EX_USAGE" "--user contains unsupported characters"
((DO_SNAPSHOT || DO_FILES)) || die "$EX_USAGE" "--snapshot-only and --files-only are mutually exclusive"
if ((VERIFY_RESTORE && !DO_SNAPSHOT)); then die "$EX_USAGE" "--verify-restore needs the snapshot step (drop --files-only)"; fi

URL="${URL:-$(vs_cfg OPENSEARCH_URL https://localhost:9200)}"
URL="${URL%/}"
vs_is_https_hostport "$URL" || die "$EX_USAGE" "--url must be https://host[:port] (TLS is mandatory)"
PASSWORD_FILE="${PASSWORD_FILE:-$(vs_cfg OPENSEARCH_PASSWORD_FILE "$SECRETS_DIR/opensearch_admin_password")}"
CA_FILE="${CA_FILE:-$PKI_DIR/ca.crt}"
PASSPHRASE_FILE="${PASSPHRASE_FILE:-$(vs_cfg BACKUP_PASSPHRASE_FILE "")}"
BACKUP_DIR="${BACKUP_DIR:-$(vs_cfg BACKUP_DIR "$SECRETS_DIR/backups")}"

# ---------------------------------------------------------------------------------------------------
# Decrypt helper (no OpenSearch access needed)
# ---------------------------------------------------------------------------------------------------
check_passphrase_file() { # <file> — policy: exists, >= 16 chars, not group/world accessible
  local f=$1 mode pw
  [[ -f "$f" ]] || { log_err "passphrase file not found: $f"; return 2; }
  mode="$(vs_file_mode "$f")"
  if vs_mode_looser "$mode" 600; then
    log_err "passphrase file $f has mode $mode — must be 0600 or stricter (chmod 600 $f)"
    return 3
  fi
  pw="$(vs_read_secret "$f")" || return 2
  if ((${#pw} < 16)); then log_err "passphrase in $f is shorter than 16 characters"; return 2; fi
}

decrypt_archive() {
  local rc=0 member
  [[ -f "$DECRYPT_IN" ]] || die "$EX_USAGE" "archive not found: $DECRYPT_IN"
  [[ -n "$EXTRACT_TO" ]] || die "$EX_USAGE" "--decrypt needs --extract-to DIR"
  [[ -n "$PASSPHRASE_FILE" ]] || die "$EX_USAGE" "--decrypt needs --passphrase-file"
  check_passphrase_file "$PASSPHRASE_FILE" || exit $?
  if [[ -d "$EXTRACT_TO" ]] && [[ -n "$(ls -A "$EXTRACT_TO" 2>/dev/null)" ]]; then die "$EX_USAGE" "--extract-to must be empty or absent: $EXTRACT_TO"; fi
  if ((VS_DRY_RUN)); then log_dry "would decrypt $DECRYPT_IN into $EXTRACT_TO"; return 0; fi
  vs_mkwork decrypt
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$PASSPHRASE_FILE" -in "$DECRYPT_IN" -out "$VS_WORK/archive.tar" 2>/dev/null \
    || die "$EX_FAIL" "decryption failed (wrong passphrase or corrupt archive)"
  tar -tf "$VS_WORK/archive.tar" >"$VS_WORK/members" 2>/dev/null || die "$EX_FAIL" "decrypted data is not a tar archive"
  while IFS= read -r member; do
    if [[ "$member" == /* || "$member" == ..* || "$member" == */../* || "$member" == */.. ]]; then
      die "$EX_FAIL" "refusing archive with unsafe member path: $member"
    fi
  done <"$VS_WORK/members"
  mkdir -p "$EXTRACT_TO"
  chmod 0700 "$EXTRACT_TO"
  tar -xf "$VS_WORK/archive.tar" -C "$EXTRACT_TO" --no-same-owner || rc=$?
  ((rc == 0)) || die "$EX_FAIL" "tar extraction failed"
  log_ok "extracted $(wc -l <"$VS_WORK/members" | tr -d ' ') entries into $EXTRACT_TO"
}

if [[ -n "$DECRYPT_IN" ]]; then
  decrypt_archive
  exit "$EX_OK"
fi

# ---------------------------------------------------------------------------------------------------
# OpenSearch access
# ---------------------------------------------------------------------------------------------------
OS_ERR=""

# os_req METHOD PATH [JSON-BODY] [OK-CSV] — retries connection-level failures with backoff; sets VS_HTTP_CODE/BODY.
# Returns 0 on an accepted status, 22 on another HTTP status, 5 when OpenSearch is unreachable or refuses the credentials.
os_req() {
  local method=$1 path=$2 body=${3:-} ok=${4:-} opts rc=0 n=1 delay=2 r
  opts=(--ca "$CA_FILE" --basic "$OS_USER:$PASSWORD_FILE" --max-time 120)
  [[ -z "$body" ]] || opts+=(--data "$body")
  [[ -z "$ok" ]] || opts+=(--ok "$ok")
  for r in "${RESOLVES[@]}"; do opts+=(--resolve "$r"); done
  while :; do
    rc=0
    vs_http "$method" "$URL$path" "${opts[@]}" || rc=$?
    if ((rc == 0)); then OS_ERR=""; return 0; fi
    if ((rc == 22)); then
      OS_ERR="$(jq -r '.error.reason // .error.root_cause[0].reason // .error // empty' <<<"$VS_HTTP_BODY" 2>/dev/null || true)"
      if [[ "$VS_HTTP_CODE" == 401 || "$VS_HTTP_CODE" == 403 ]]; then
        log_err "OpenSearch refused the credentials for user '$OS_USER' (HTTP $VS_HTTP_CODE)"
        return "$EX_NOTREADY"
      fi
      return 22
    fi
    if ((rc == 65)); then die "$EX_USAGE" "cannot read the password file: $PASSWORD_FILE"; fi
    if ((n >= 4)); then
      log_err "OpenSearch unreachable at $URL (curl exit $rc): ${VS_HTTP_BODY:0:200}"
      return "$EX_NOTREADY"
    fi
    log_warn "request $method $path failed (curl exit $rc), retry $n/3 in ${delay}s"
    vs_sleep "$delay"
    delay=$((delay * 2))
    n=$((n + 1))
  done
}

# os_must METHOD PATH [BODY] [OK] — like os_req but exits with a precise code on failure.
os_must() {
  local rc=0
  os_req "$@" || rc=$?
  if ((rc == EX_NOTREADY)); then exit "$EX_NOTREADY"; fi
  if ((rc != 0)); then die "$EX_FAIL" "$1 $2 failed: HTTP $VS_HTTP_CODE ${OS_ERR:-${VS_HTTP_BODY:0:300}}"; fi
}

cleanup_restored() {
  local idx rc=0
  if [[ ${#RESTORED[@]} -eq 0 ]]; then return 0; fi
  for idx in "${RESTORED[@]}"; do
    # exact scratch names only: the guard makes it impossible to delete anything outside restore-test-*
    if [[ "$idx" == "$SCRATCH_PREFIX"* && "$idx" != *'*'* ]]; then
      os_req DELETE "/$idx" "" 200,404 >/dev/null 2>&1 || rc=1
    fi
  done
  RESTORED=()
  return "$rc"
}

ensure_repo() {
  local payload cur
  os_must GET "/_snapshot/$REPO" "" 200,404
  if [[ "$VS_HTTP_CODE" == 200 ]]; then
    cur="$(jq -r --arg r "$REPO" '.[$r].settings.location // empty' <<<"$VS_HTTP_BODY")"
    if [[ -n "$cur" && "$cur" != "$LOCATION" ]]; then
      log_warn "repository $REPO exists with location $cur (requested $LOCATION) — keeping the existing repository"
    else
      log_ok "snapshot repository $REPO already registered"
    fi
    return 0
  fi
  payload="$(jq -cn --arg l "$LOCATION" '{type: "fs", settings: {location: $l, compress: true}}')"
  os_req PUT "/_snapshot/$REPO" "$payload" || die "$EX_FAIL" "registering repository $REPO failed (HTTP $VS_HTTP_CODE ${OS_ERR:-}); is path.repo set to $LOCATION and the volume mounted?"
  log_ok "registered snapshot repository $REPO ($LOCATION)"
}

take_snapshot() {
  local base payload n=0 state polls=0 max_polls=$((WAIT_TIMEOUT / 5))
  base="vendetta-$(date -u +%Y%m%d-%H%M%S)"
  SNAP=$base
  while :; do
    os_must GET "/_snapshot/$REPO/$SNAP" "" 200,404
    [[ "$VS_HTTP_CODE" == 404 ]] && break
    n=$((n + 1))
    SNAP="$base-$n"
  done
  payload="$(jq -cn --arg i "$INDICES" --arg v "${STACK_VERSION:-$(vs_cfg STACK_VERSION unknown)}" \
    '{indices: $i, ignore_unavailable: true, include_global_state: false, metadata: {taken_by: "backup-opensearch.sh", stack_version: $v}}')"
  log_step "creating snapshot $REPO/$SNAP of $INDICES"
  os_must PUT "/_snapshot/$REPO/$SNAP?wait_for_completion=false" "$payload"
  while :; do
    os_must GET "/_snapshot/$REPO/$SNAP"
    state="$(jq -r '.snapshots[0].state // empty' <<<"$VS_HTTP_BODY")"
    if [[ "$state" != IN_PROGRESS && "$state" != STARTED && -n "$state" ]]; then break; fi
    if ((polls >= max_polls)); then die "$EX_FAIL" "snapshot $SNAP still ${state:-pending} after ${WAIT_TIMEOUT}s"; fi
    polls=$((polls + 1))
    log_info "snapshot $SNAP ${state:-pending} (poll $polls)"
    vs_sleep 5
  done
  SNAP_STATE=$state
  if [[ "$state" != SUCCESS ]]; then
    die "$EX_FAIL" "snapshot $SNAP finished as $state: $(jq -c '.snapshots[0].failures // []' <<<"$VS_HTTP_BODY" | cut -c1-400)"
  fi
  if [[ "$(jq -r '.snapshots[0].shards.failed // 0' <<<"$VS_HTTP_BODY")" != 0 ]]; then
    die "$EX_FAIL" "snapshot $SNAP reports failed shards"
  fi
  mapfile -t SNAP_INDICES < <(jq -r '.snapshots[0].indices[]?' <<<"$VS_HTTP_BODY")
  log_ok "snapshot $SNAP SUCCESS: ${#SNAP_INDICES[@]} index/indices, $(jq -r '.snapshots[0].shards.total // 0' <<<"$VS_HTTP_BODY") shard(s)"
  if ((${#SNAP_INDICES[@]} == 0)); then log_warn "no index matched '$INDICES' yet — the snapshot is empty"; fi
}

prune_snapshots() {
  local s
  os_must GET "/_snapshot/$REPO/_all"
  mapfile -t victims < <(jq -r --argjson keep "$KEEP" --arg cur "$SNAP" '
      [.snapshots[] | select((.snapshot | test("^vendetta-[a-z0-9._-]+$")) and .state == "SUCCESS")]
      | sort_by(.start_time_in_millis) | reverse | .[$keep:] | .[].snapshot | select(. != $cur)' <<<"$VS_HTTP_BODY")
  for s in "${victims[@]}"; do
    [[ -n "$s" ]] || continue
    os_must DELETE "/_snapshot/$REPO/$s" "" 200,404
    PRUNED_SNAPSHOTS+=("$s")
    log_info "pruned snapshot $s (retention: newest $KEEP kept)"
  done
}

verify_restore() {
  local sample=() idx payload target health total=0 failed docs
  for idx in "${SNAP_INDICES[@]}"; do
    [[ "$idx" == .* || "$idx" == "$SCRATCH_PREFIX"* ]] && continue
    sample+=("$idx")
    ((${#sample[@]} >= RESTORE_SAMPLE)) && break
  done
  if ((${#sample[@]} == 0)); then
    log_warn "restore verification skipped: the snapshot holds no restorable data indices"
    return 0
  fi
  log_step "restore test: ${#sample[@]} index/indices → ${SCRATCH_PREFIX}*"
  for idx in "${sample[@]}"; do
    target="$SCRATCH_PREFIX$idx"
    RESTORED+=("$target")
    os_must DELETE "/$target" "" 200,404
  done
  payload="$(jq -cn --arg i "$(vs_join , "${sample[@]}")" --arg p "$SCRATCH_PREFIX" \
    '{indices: $i, ignore_unavailable: false, include_global_state: false, include_aliases: false,
      rename_pattern: "(.+)", rename_replacement: ($p + "$1"), index_settings: {"index.number_of_replicas": 0}}')"
  os_must POST "/_snapshot/$REPO/$SNAP/_restore?wait_for_completion=true" "$payload"
  failed="$(jq -r '.snapshot.shards.failed // 0' <<<"$VS_HTTP_BODY")"
  ((failed == 0)) || die "$EX_FAIL" "restore of $SNAP reported $failed failed shard(s)"
  for idx in "${RESTORED[@]}"; do
    os_must GET "/_cluster/health/$idx?wait_for_status=yellow&timeout=60s"
    health="$(jq -r '.status // "unknown"' <<<"$VS_HTTP_BODY")"
    [[ "$health" == green || "$health" == yellow ]] || die "$EX_FAIL" "restored index $idx is $health"
    os_must GET "/$idx/_count"
    docs="$(jq -r '.count // empty' <<<"$VS_HTTP_BODY")"
    vs_is_uint "$docs" || die "$EX_FAIL" "restored index $idx: document count unreadable"
    [[ "$(jq -r '._shards.failed // 0' <<<"$VS_HTTP_BODY")" == 0 ]] || die "$EX_FAIL" "restored index $idx: shard failures on search"
    total=$((total + docs))
    log_info "restored $idx: $docs document(s), health $health"
  done
  cleanup_restored || log_warn "could not delete every ${SCRATCH_PREFIX}* scratch index — remove them manually"
  log_ok "restore test passed ($total document(s) readable); scratch indices removed"
}

# ---------------------------------------------------------------------------------------------------
# File backups
# ---------------------------------------------------------------------------------------------------
# GNU tar sorts entries; bsdtar has no --sort/--format=gnu, so it is asked for ustar (no ctime headers) instead
TAR_BIN="$(command -v gtar 2>/dev/null || command -v tar 2>/dev/null || true)"
TAR_DETERMINISTIC_ARGS=()
if [[ -n "$TAR_BIN" ]] && "$TAR_BIN" --version 2>/dev/null | grep -qi 'GNU tar'; then
  TAR_DETERMINISTIC_ARGS=(--sort=name)
else
  TAR_DETERMINISTIC_ARGS=(--format ustar)
fi

encrypt_tar() { # <out-file> <parent-dir> <member> [tar-args...]
  local out=$1 parent=$2 member=$3
  shift 3
  "$TAR_BIN" -C "$parent" --numeric-owner "${TAR_DETERMINISTIC_ARGS[@]}" "$@" -cf - "$member" \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$PASSPHRASE_FILE" -out "$out"
  chmod 0600 "$out"
}

prepare_passphrase() {
  local need=0
  ((DO_FILES)) || return 0
  if ((!SKIP_PKI)) && [[ -d "$PKI_DIR" ]]; then need=1; fi
  if ((INCLUDE_SECRETS)); then need=1; fi
  ((need)) || return 0
  [[ -n "$PASSPHRASE_FILE" ]] || die "$EX_USAGE" "pki/ and secrets/ archives are always encrypted: pass --passphrase-file F (or --skip-pki)"
  if [[ ! -f "$PASSPHRASE_FILE" ]]; then
    ((CREATE_PASSPHRASE)) || die "$EX_USAGE" "passphrase file not found: $PASSPHRASE_FILE (use --create-passphrase to generate it)"
    if ((VS_DRY_RUN)); then log_dry "would generate passphrase file $PASSPHRASE_FILE (0600)"; return 0; fi
    mkdir -p "$(dirname "$PASSPHRASE_FILE")"
    vs_gen_password 48 | vs_atomic_write "$PASSPHRASE_FILE" 0600
    log_warn "generated $PASSPHRASE_FILE — keep a copy OFFLINE; without it the encrypted archives cannot be restored"
  fi
  if ((VS_DRY_RUN)); then return 0; fi
  check_passphrase_file "$PASSPHRASE_FILE" || exit $?
}

backup_files() {
  local ts dir f rel entries=() sums size
  ts="$(vs_ts)"
  dir="$BACKUP_DIR/$ts"
  if ((VS_DRY_RUN)); then
    log_dry "would write $dir/{ollama-models.json,$([[ -d "$PKI_DIR" && $SKIP_PKI -eq 0 ]] && echo 'pki.tar.enc,')$([[ $INCLUDE_SECRETS -eq 1 ]] && echo 'secrets.tar.enc,')SHA256SUMS,MANIFEST.json}"
    log_dry "would keep the newest $KEEP backup directories in $BACKUP_DIR"
    return 0
  fi
  (umask 077; mkdir -p "$BACKUP_DIR" "$dir")
  chmod 0700 "$BACKUP_DIR" "$dir"
  FILES_DIR=$dir

  if [[ -f "$STACK_DIR/ollama/models.json" ]]; then
    install -m 0644 "$STACK_DIR/ollama/models.json" "$dir/ollama-models.json"
    entries+=(ollama-models.json)
  else
    log_warn "ollama/models.json not found — skipped"
  fi
  if ((!SKIP_PKI)); then
    if [[ -d "$PKI_DIR" ]]; then
      encrypt_tar "$dir/pki.tar.enc" "$(dirname "$PKI_DIR")" "$(basename "$PKI_DIR")"
      entries+=(pki.tar.enc)
    else
      log_warn "pki/ not found — skipped"
    fi
  fi
  if ((INCLUDE_SECRETS)); then
    [[ -d "$SECRETS_DIR" ]] || die "$EX_FAIL" "secrets/ not found but --include-secrets was given"
    encrypt_tar "$dir/secrets.tar.enc" "$(dirname "$SECRETS_DIR")" "$(basename "$SECRETS_DIR")" \
      --exclude="$(basename "$SECRETS_DIR")/backups"
    entries+=(secrets.tar.enc)
  fi
  ((${#entries[@]})) || die "$EX_FAIL" "nothing to back up"

  sums=""
  for f in "${entries[@]}"; do sums+="$(vs_sha256 "$dir/$f")  $f"$'\n'; done
  printf '%s' "$sums" | vs_atomic_write "$dir/SHA256SUMS" 0600
  for f in "${entries[@]}"; do
    size="$(vs_file_size "$dir/$f")"
    rel="$(jq -cn --arg n "$f" --arg h "$(vs_sha256 "$dir/$f")" --argjson s "$size" \
      --argjson enc "$([[ "$f" == *.enc ]] && echo true || echo false)" '{name: $n, sha256: $h, bytes: $s, encrypted: $enc}')"
    printf '%s\n' "$rel"
  done | jq -s --arg ts "$ts" --arg snap "${SNAP:-}" --arg repo "$REPO" --arg v "$(vs_cfg STACK_VERSION unknown)" \
      '{created: $ts, stack_version: $v, snapshot: (if $snap == "" then null else {repository: $repo, name: $snap} end),
        encryption: {cipher: "aes-256-cbc", kdf: "pbkdf2", iterations: 600000, passphrase: "file (not stored)"}, files: .}' \
    | vs_atomic_write "$dir/MANIFEST.json" 0600
  log_ok "file backup written to $dir (${#entries[@]} file(s))"

  # -printf is GNU-only: list paths, then keep just the basenames
  mapfile -t old < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*T[0-9]*Z' | sed 's#.*/##' | sort -r | tail -n +"$((KEEP + 1))")
  for f in "${old[@]}"; do
    [[ "$f" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || continue
    rm -rf -- "${BACKUP_DIR:?}/$f"
    PRUNED_DIRS+=("$f")
    log_info "pruned old backup directory $f (retention: newest $KEEP kept)"
  done
}

# ---------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------
prepare_passphrase

if ((VS_DRY_RUN)); then
  log_dry "OpenSearch: $URL (user $OS_USER, CA $CA_FILE) — no network calls in dry-run mode"
  if ((DO_SNAPSHOT)); then
    log_dry "would ensure repository $REPO (fs, $LOCATION), snapshot indices '$INDICES' as vendetta-<UTC timestamp>, wait for SUCCESS"
    log_dry "would prune to the newest $KEEP vendetta-* snapshots"
    if ((VERIFY_RESTORE)); then log_dry "would restore up to $RESTORE_SAMPLE index/indices as ${SCRATCH_PREFIX}* and delete them again"; fi
  fi
  if ((DO_FILES)); then backup_files; fi
  exit "$EX_OK"
fi

if ((DO_SNAPSHOT)); then
  [[ -f "$CA_FILE" ]] || die "$EX_USAGE" "CA certificate not found: $CA_FILE (run scripts/bootstrap.sh first)"
  [[ -r "$PASSWORD_FILE" ]] || die "$EX_USAGE" "admin password file not readable: $PASSWORD_FILE"
  vs_on_exit cleanup_restored
  os_must GET "/_cluster/health"
  log_info "cluster status: $(jq -r '.status // "unknown"' <<<"$VS_HTTP_BODY")"
  ensure_repo
  take_snapshot
  prune_snapshots
  if ((VERIFY_RESTORE)); then verify_restore; fi
fi
if ((DO_FILES)); then backup_files; fi

printf 'backup complete: snapshot=%s state=%s pruned_snapshots=%d files_dir=%s pruned_dirs=%d\n' \
  "${SNAP:-none}" "${SNAP_STATE:-n/a}" "${#PRUNED_SNAPSHOTS[@]}" "${FILES_DIR:-none}" "${#PRUNED_DIRS[@]}"
exit "$EX_OK"
