#!/usr/bin/env bash
#
# rotate-certs.sh — re-issue the stack's service certificates and reload services with minimal disruption.
#
# Traces: PROMPT §3 Phase 3 scripts/rotate-certs.sh; CONTRACT §2 (PKI names), §8.6 (<svc>.pem), CS3
#         deployment/ansible/playbooks/rotate-certs.yml + deployment/operations/{certificate-rotation,
#         mtls-certificate-pinning}.md (overlap → deploy new → drop old; 30-day window; verify with openssl).
#
# Standard rotation (default): every service certificate is re-issued with the EXISTING CA (pki/ca.key), the
# previous set is kept in pki-archive/<UTC ts>/ (PKI_ARCHIVE_DIR, mode 0700 — deliberately OUTSIDE pki/, which compose
# mounts wholesale into OpenSearch: an unreadable subdirectory there stops it from booting), the new set is verified
# with openssl (chain to ca.crt, key/cert match, SAN/EKU, expiry) and only then are services reloaded. If anything
# fails before the reload, the archived files are restored automatically. A legacy pki/archive/ is moved out first.
#
# CA rotation (--rotate-ca, openssl mode only) is a three-run, dual-trust procedure — never a flag-day:
#   run 1  overlap   new CA generated (pki/ca-next.*); pki/ca.crt becomes a bundle OLD+NEW; leaves unchanged.
#                    → distribute pki/ca.crt to every verifier (edge agents, remote Ollama nodes, K8s) and wait.
#   run 2  reissue   signing key switches to the new CA; all leaves re-issued; ca.crt still trusts OLD+NEW.
#   run 3  finalize  ca.crt = NEW CA only; old CA archived (pki-archive/); services reloaded.
#   (state in pki/.rotation-state; each run performs exactly the next phase, --ca-phase asserts which one.)
#
# Reload strategy (Compose; only services that are running are touched), in this order:
#   opensearch               security-plugin hot reload (POST _plugins/_security/api/ssl/{transport,http}/reloadcerts
#                            with the opensearch-admin client cert); falls back to a restart — a single node is
#                            briefly unavailable in that case
#   opensearch-dashboards    restart
#   ollama-1-proxy, mock-ollama-proxy, prometheus, ollama-lb   docker compose kill -s HUP (HAProxy/Prometheus reload)
#   fluentd-2 → fluentd-1    rolling restart, waiting for healthy before the next (active-active, Fluent Bit
#                            fails over via upstream.conf; buffers are on disk)
#   fluent-bit               restart (filesystem storage keeps buffered chunks)
#   llm-gateway → ollama-lb  ollama-lb shares the gateway's network namespace (network_mode: service:llm-gateway),
#                            so it is ALWAYS restarted right after the gateway
#   errow-mcp, errow-feedback, errow, vendetta-manager   restart
# Kubernetes (--kubernetes): cert-manager renewal (cmctl renew --all) + `kubectl rollout restart` in order.
#
# Usage: scripts/rotate-certs.sh [options]   (see --help)
#
# Exit codes: 0 ok | 1 failure (certificates rolled back when possible) | 2 usage | 3 policy (CA rotation refused)
#             4 missing prerequisite | 5 certificates issued but a service did not become healthy

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/pki.sh
source "$SCRIPT_DIR/lib/pki.sh"

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
  cat <<'EOF'
rotate-certs.sh — re-issue service certificates with the existing CA and reload services.

Usage: scripts/rotate-certs.sh [options]

  --dry-run                  print the plan (certificates to issue, reload order); change nothing
  --services A,B             only these certificate names (default: all, incl. opensearch-admin)
  --only-expiring            re-issue only certificates with fewer than --threshold days left
  --threshold DAYS           renewal window for --only-expiring (default 30)
  --rotate-ca                perform the next CA-rotation phase (overlap → reissue → finalize); openssl mode only
  --ca-phase PHASE           assert the phase about to run (overlap|reissue|finalize); refuses to skip phases
  --no-reload                issue and verify only; do not touch running services
  --wait SECONDS             per-service health wait after a restart (default 180)
  --opensearch-url URL       default https://127.0.0.1:9200 (security-plugin cert reload endpoint)
  --kubernetes               Kubernetes mode (cert-manager renew + rollout restart); needs kubectl, cmctl
  --namespace NS             Kubernetes namespace (default vendetta-stack)
  --pki-days N | --pki-algo ec|rsa | --ca-passphrase-file FILE | --key-group GID | --dev-readable-keys
  --pki openssl|step-ca|mkcert   (+ step-ca options as in bootstrap.sh)
  --stack-dir DIR            stack root (default: parent of scripts/)
  -q, --quiet | -v, --verbose | -h, --help

Exit codes: 0 ok | 1 failure | 2 usage | 3 policy | 4 prerequisite | 5 issued but a service is unhealthy
EOF
}

ONLY_SERVICES=""
ONLY_EXPIRING=0
THRESHOLD=30
ROTATE_CA=0
CA_PHASE=""
NO_RELOAD=0
WAIT_SECS=180
OS_URL="${OPENSEARCH_URL:-https://127.0.0.1:9200}"
KUBE=0
NAMESPACE="${KUBE_NAMESPACE:-vendetta-stack}"
ARCHIVE_DIR=""
ROTATE_DONE=0
CREATED_FILES=()
UNHEALTHY=0

reroot() {
  [[ -d "$1" ]] || die "$EX_USAGE" "stack dir not found: $1"
  STACK_DIR="$(cd "$1" && pwd)"
  PKI_DIR="$STACK_DIR/pki"
  PKI_ARCHIVE_DIR="${VS_PKI_ARCHIVE_ENV:-$STACK_DIR/pki-archive}"
  ENV_FILE="$STACK_DIR/.env"
}

parse_args() {
  vs_normalize_args "$@"
  set -- "${NORM_ARGS[@]:-}"
  while (($#)); do
    if [[ -z "$1" ]]; then shift; continue; fi
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --dry-run) VS_DRY_RUN=1; shift ;;
      -q|--quiet) VS_QUIET=1; shift ;;
      -v|--verbose) VS_VERBOSE=1; shift ;;
      --services) vs_need "$@"; ONLY_SERVICES=$2; shift 2 ;;
      --only-expiring) ONLY_EXPIRING=1; shift ;;
      --threshold) vs_need "$@"; THRESHOLD=$2; shift 2 ;;
      --rotate-ca) ROTATE_CA=1; shift ;;
      --ca-phase) vs_need "$@"; CA_PHASE=$2; shift 2 ;;
      --no-reload) NO_RELOAD=1; shift ;;
      --wait) vs_need "$@"; WAIT_SECS=$2; shift 2 ;;
      --opensearch-url) vs_need "$@"; OS_URL=$2; shift 2 ;;
      --kubernetes) KUBE=1; shift ;;
      --namespace) vs_need "$@"; NAMESPACE=$2; shift 2 ;;
      --stack-dir) vs_need "$@"; reroot "$2"; shift 2 ;;
      --pki) vs_need "$@"; PKI_MODE=$2; shift 2 ;;
      --pki-algo) vs_need "$@"; PKI_ALGO=$2; shift 2 ;;
      --pki-days) vs_need "$@"; PKI_DAYS=$2; shift 2 ;;
      --ca-passphrase-file) vs_need "$@"; PKI_CA_PASSPHRASE_FILE=$2; shift 2 ;;
      --dev-readable-keys) PKI_DEV_READABLE_KEYS=1; shift ;;
      --key-group) vs_need "$@"; PKI_KEY_GROUP=$2; shift 2 ;;
      --step-ca-url) vs_need "$@"; PKI_STEP_URL=$2; shift 2 ;;
      --step-ca-root) vs_need "$@"; PKI_STEP_ROOT=$2; shift 2 ;;
      --step-ca-fingerprint) vs_need "$@"; PKI_STEP_FINGERPRINT=$2; shift 2 ;;
      --step-provisioner) vs_need "$@"; PKI_STEP_PROVISIONER=$2; shift 2 ;;
      --step-password-file) vs_need "$@"; PKI_STEP_PASSWORD_FILE=$2; shift 2 ;;
      *) die "$EX_USAGE" "unknown option: $1 (see --help)" ;;
    esac
  done
  vs_is_uint "$THRESHOLD" || die "$EX_USAGE" "--threshold must be a number of days"
  vs_is_uint "$WAIT_SECS" || die "$EX_USAGE" "--wait must be a number of seconds"
  case "$CA_PHASE" in ""|overlap|reissue|finalize) ;; *) die "$EX_USAGE" "--ca-phase must be overlap, reissue or finalize" ;; esac
  if [[ -n "$CA_PHASE" && $ROTATE_CA -eq 0 ]]; then die "$EX_USAGE" "--ca-phase requires --rotate-ca"; fi
  if ((ROTATE_CA)) && [[ -n "$ONLY_SERVICES" || $ONLY_EXPIRING -eq 1 ]]; then
    die "$EX_USAGE" "--rotate-ca re-issues every certificate; do not combine it with --services/--only-expiring"
  fi
}

# --- rollback ------------------------------------------------------------------------------------------
# shellcheck disable=SC2317  # runs from the EXIT trap, which shellcheck 0.9 does not follow
on_exit() {
  local rc=$? f dir=$ARCHIVE_DIR
  if ((ROTATE_DONE == 0 && VS_DRY_RUN == 0)) && [[ -n "$dir" && -d "$dir" ]]; then
    log_warn "rotation did not complete — restoring previous files from ${dir#"$STACK_DIR"/}"
    for f in "${CREATED_FILES[@]}"; do rm -f -- "$f"; done
    for f in "$dir"/*; do
      [[ -f "$f" ]] || continue
      cp -p -- "$f" "$PKI_DIR/$(basename "$f")"
    done
  fi
  vs_cleanup || true
  return "$rc"
}

archive_everything() { # archives CA material, rotation state and the affected leaf sets into $PKI_ARCHIVE_DIR/<ts>
  local ts=$1 f
  ARCHIVE_DIR="$PKI_ARCHIVE_DIR/$ts"
  pki_ensure_archive_root
  pki_archive_set "$ts" ca "${TARGETS[@]}"
  for f in ca-signer.crt ca-next.crt ca-next.key .rotation-state; do
    if [[ -f "$PKI_DIR/$f" ]]; then cp -p "$PKI_DIR/$f" "$ARCHIVE_DIR/$f"; fi
  done
}

# --- planning ------------------------------------------------------------------------------------------
TARGETS=()

select_targets() {
  local all=() svc want
  while IFS= read -r svc; do all+=("$svc"); done < <({ pki_all_services; printf '%s\n' "$PKI_ADMIN_SERVICE"; })
  if [[ -z "$ONLY_SERVICES" ]]; then TARGETS=("${all[@]}"); else
    IFS=, read -r -a want <<<"$ONLY_SERVICES"
    for svc in "${want[@]}"; do
      local found=0 a
      for a in "${all[@]}"; do if [[ "$a" == "$svc" ]]; then found=1; fi; done
      ((found)) || die "$EX_USAGE" "unknown certificate name '$svc' (known: $(vs_join ' ' "${all[@]}"))"
      TARGETS+=("$svc")
    done
  fi
  if ((ONLY_EXPIRING)); then
    local keep=() old=$PKI_RENEW_DAYS
    PKI_RENEW_DAYS=$THRESHOLD
    for svc in "${TARGETS[@]}"; do if ! pki_cert_check "$svc"; then keep+=("$svc"); fi; done
    PKI_RENEW_DAYS=$old
    TARGETS=("${keep[@]:-}")
    if [[ -z "${TARGETS[0]:-}" ]]; then TARGETS=(); fi
  fi
}

# --- reload --------------------------------------------------------------------------------------------
declare -A RELOAD_SET=()
RELOAD_ORDER=(opensearch opensearch-dashboards ollama-1-proxy mock-ollama-proxy prometheus fluentd-2 fluentd-1 fluent-bit llm-gateway ollama-lb errow-mcp errow-feedback errow vendetta-manager)

reload_targets_for() { # certificate name → compose service(s)
  case "$1" in
    "$PKI_ADMIN_SERVICE") ;;
    ollama-1) printf 'ollama-1-proxy\n' ;;
    mock-ollama) printf 'mock-ollama-proxy\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

action_for() {
  case "$1" in
    opensearch) printf 'osreload' ;;
    ollama-lb|ollama-1-proxy|mock-ollama-proxy|prometheus) printf 'hup' ;;
    *) printf 'restart' ;;
  esac
}

plan_reload() { # <everything:0|1> — fills RELOAD_SET
  local everything=$1 svc t
  RELOAD_SET=()
  if ((everything)); then
    for svc in "${RELOAD_ORDER[@]}"; do RELOAD_SET[$svc]=1; done
  else
    for svc in "${TARGETS[@]}"; do
      while IFS= read -r t; do
        if [[ -n "$t" ]]; then RELOAD_SET[$t]=1; fi
      done < <(reload_targets_for "$svc")
    done
  fi
  if [[ -n "${RELOAD_SET[llm-gateway]:-}" ]]; then RELOAD_SET[ollama-lb]=1; fi
}

service_running() {
  local running
  running="$(vs_compose_running_services)"
  grep -qx -- "$1" <<<"$running"
}

wait_healthy() { # <service> — healthy (or running when there is no healthcheck) within --wait seconds
  local svc=$1 cid st waited=0 steady=0
  cid="$("${COMPOSE[@]}" ps -q "$svc" 2>/dev/null | head -n 1)"
  [[ -n "$cid" ]] || return 1
  while ((waited <= WAIT_SECS)); do
    st="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
    case "$st" in
      healthy) return 0 ;;
      running) steady=$((steady + 1)); if ((steady >= 3)); then return 0; fi ;;
      *) steady=0 ;;
    esac
    vs_sleep 2
    waited=$((waited + 2))
  done
  return 1
}

opensearch_reload() {
  local kind rc=0
  [[ -s "$PKI_DIR/opensearch-admin.crt" && -s "$PKI_DIR/opensearch-admin.key" ]] || return 1
  for kind in transport http; do
    retry 3 2 vs_http PUT "$OS_URL/_plugins/_security/api/ssl/$kind/reloadcerts" \
      --ca "$PKI_DIR/ca.crt" --cert "$PKI_DIR/opensearch-admin.crt" --key "$PKI_DIR/opensearch-admin.key" || rc=1
  done
  return "$rc"
}

reload_service() {
  local svc=$1 act
  act="$(action_for "$svc")"
  if ((VS_DRY_RUN)); then log_dry "$act $svc"; return 0; fi
  if ! service_running "$svc"; then log_info "$svc: not running — nothing to reload"; return 0; fi
  case "$act" in
    osreload)
      if opensearch_reload; then log_ok "opensearch: certificates hot-reloaded (security plugin)"; return 0; fi
      log_warn "opensearch hot reload unavailable (needs plugins.security.ssl_cert_reload_enabled + admin DN) — restarting (brief outage on single-node)"
      "${COMPOSE[@]}" restart opensearch ;;
    hup)
      if ! "${COMPOSE[@]}" kill -s HUP "$svc" >/dev/null 2>&1; then
        log_warn "$svc: HUP failed — restarting"
        "${COMPOSE[@]}" restart "$svc"
      else
        vs_sleep 2
      fi ;;
    restart) "${COMPOSE[@]}" restart "$svc" ;;
  esac
  if wait_healthy "$svc"; then log_ok "$svc: reloaded and healthy"; else log_err "$svc: not healthy after reload (${WAIT_SECS}s)"; UNHEALTHY=1; fi
}

do_reload() {
  local svc
  if ((NO_RELOAD)); then log_info "--no-reload: services left untouched (reload them yourself)"; return 0; fi
  if ((KUBE)); then kube_reload; return 0; fi
  if ! vs_compose_init; then log_warn "Docker Compose v2 not found — services NOT reloaded (reload them manually)"; return 0; fi
  for svc in "${RELOAD_ORDER[@]}"; do
    [[ -n "${RELOAD_SET[$svc]:-}" ]] || continue
    reload_service "$svc"
  done
}

kube_reload() {
  local kind res
  vs_require kubectl
  if vs_have cmctl; then
    run cmctl renew --namespace "$NAMESPACE" --all
  elif kubectl cert-manager version >/dev/null 2>&1; then
    run kubectl cert-manager renew --namespace "$NAMESPACE" --all
  else
    die "$EX_PREREQ" "cmctl (cert-manager CLI) not found — install it or annotate the Certificates for renewal"
  fi
  for kind in statefulset deployment daemonset; do
    while IFS= read -r res; do
      [[ -n "$res" ]] || continue
      run kubectl -n "$NAMESPACE" rollout restart "$res"
      if ((VS_DRY_RUN == 0)); then
        if ! kubectl -n "$NAMESPACE" rollout status "$res" --timeout="${WAIT_SECS}s"; then UNHEALTHY=1; fi
      fi
    done < <(kubectl -n "$NAMESPACE" get "$kind" -l app.kubernetes.io/part-of=vendetta-stack -o name 2>/dev/null | LC_ALL=C sort)
  done
  if ((VS_DRY_RUN == 0)); then
    kubectl -n "$NAMESPACE" get certificates -o json | jq -r '.items[] | [.metadata.name, (.status.notAfter // "unknown")] | @tsv' || true
  fi
}

# --- verification --------------------------------------------------------------------------------------
verify_all() {
  local svc bad=0 fp
  printf '%-26s %-6s %-30s %s\n' "CERTIFICATE" "DAYS" "NOT AFTER" "SHA-256 (first 23 chars)" >&2
  for svc in "${TARGETS[@]}"; do
    if pki_cert_check "$svc"; then
      fp="$(pki_cert_fingerprint "$PKI_DIR/$svc.crt")"
      printf '%-26s %-6s %-30s %s\n' "$svc" "$PKI_DAYS_LEFT" "$(pki_cert_not_after "$PKI_DIR/$svc.crt")" "${fp:0:23}" >&2
    else
      log_err "$svc: $PKI_REASON"
      bad=1
    fi
  done
  return "$bad"
}

issue_targets() {
  local svc
  for svc in "${TARGETS[@]}"; do
    log_info "issuing $svc"
    pki_issue_service "$svc"
  done
}

# --- CA rotation ---------------------------------------------------------------------------------------
state_phase() { if [[ -f "$PKI_DIR/.rotation-state" ]]; then sed -n 's/^phase=//p' "$PKI_DIR/.rotation-state" | head -n 1; fi; }

write_state() {
  printf 'phase=%s\nupdated=%s\n' "$1" "$(vs_now_iso)" | vs_atomic_write "$PKI_DIR/.rotation-state" 0600
}

next_phase() {
  case "$(state_phase)" in
    "") printf 'overlap' ;;
    overlap) printf 'reissue' ;;
    reissue) printf 'finalize' ;;
    *) die "$EX_FAIL" "unknown state in pki/.rotation-state: '$(state_phase)'" ;;
  esac
}

ca_rotation() {
  local phase ts everything=1
  [[ "$PKI_MODE" == openssl ]] || die "$EX_USAGE" "--rotate-ca is only supported in openssl mode (step-ca/mkcert: rotate the CA on its own server, then re-run without --rotate-ca)"
  [[ -s "$PKI_DIR/ca.crt" && -s "$PKI_DIR/ca.key" ]] || die "$EX_PREREQ" "pki/ca.crt and pki/ca.key are required for CA rotation"
  phase="$(next_phase)"
  if [[ -n "$CA_PHASE" && "$CA_PHASE" != "$phase" ]]; then
    die "$EX_POLICY" "refusing --ca-phase $CA_PHASE: the next phase is '$phase' (state: '$(state_phase)'); phases cannot be skipped"
  fi
  log_step "CA rotation — phase: $phase"
  ts="$(vs_ts)"
  if ((VS_DRY_RUN)); then
    log_dry "phase $phase: would archive pki/ → pki-archive/$ts and update ca material"
    plan_reload "$everything"
    do_reload
    return 0
  fi
  archive_everything "$ts"
  case "$phase" in
    overlap)
      PKI_CA_CN="$PKI_CA_CN (rotation $(date -u +%Y%m%d))"
      pki_new_ca "$PKI_DIR/ca-next.key" "$PKI_DIR/ca-next.crt"
      CREATED_FILES+=("$PKI_DIR/ca-next.key" "$PKI_DIR/ca-next.crt" "$PKI_DIR/ca-signer.crt")
      cp -p "$PKI_DIR/ca.crt" "$PKI_DIR/ca-signer.crt"
      { cat "$PKI_DIR/ca-signer.crt"; cat "$PKI_DIR/ca-next.crt"; } | vs_atomic_write "$PKI_DIR/ca.crt" 0644
      write_state overlap
      log_ok "ca.crt is now a dual-trust bundle (old + new); leaf certificates are unchanged"
      log_info "NEXT: distribute pki/ca.crt to every verifier (edge agents, Ollama nodes, K8s), wait for them to reload, then run: rotate-certs.sh --rotate-ca"
      ;;
    reissue)
      [[ -s "$PKI_DIR/ca-next.key" && -s "$PKI_DIR/ca-next.crt" ]] || die "$EX_FAIL" "pki/ca-next.* missing — restart the rotation from the overlap phase"
      mv -f "$PKI_DIR/ca-next.key" "$PKI_DIR/ca.key"
      mv -f "$PKI_DIR/ca-next.crt" "$PKI_DIR/ca-signer.crt"
      chmod 0600 "$PKI_DIR/ca.key"
      issue_targets
      write_state reissue
      log_ok "all leaves re-issued by the new CA; ca.crt still trusts old + new"
      log_info "NEXT: once every service has reloaded and healthcheck.sh is green, run: rotate-certs.sh --rotate-ca  (finalize drops the old CA)"
      ;;
    finalize)
      local svc
      for svc in "${TARGETS[@]}"; do
        openssl verify -CAfile "$PKI_DIR/ca-signer.crt" "$PKI_DIR/$svc.crt" >/dev/null 2>&1 \
          || die "$EX_FAIL" "$svc.crt is not signed by the new CA — cannot finalize (re-run the reissue phase)"
      done
      cp -p "$PKI_DIR/ca-signer.crt" "$PKI_DIR/ca.crt.new"
      mv -f "$PKI_DIR/ca.crt.new" "$PKI_DIR/ca.crt"
      chmod 0644 "$PKI_DIR/ca.crt"
      rm -f "$PKI_DIR/ca-signer.crt" "$PKI_DIR/.rotation-state"
      log_ok "ca.crt now contains only the new CA; the old CA is archived in ${ARCHIVE_DIR#"$STACK_DIR"/}"
      ;;
  esac
  verify_all || die "$EX_FAIL" "verification failed after phase $phase"
  ROTATE_DONE=1
  plan_reload "$everything"
  do_reload
}

standard_rotation() {
  local ts
  if ((${#TARGETS[@]} == 0)); then log_ok "nothing to rotate (no certificate within ${THRESHOLD} days of expiry)"; return 0; fi
  [[ -s "$PKI_DIR/ca.crt" ]] || die "$EX_PREREQ" "pki/ca.crt missing — run scripts/bootstrap.sh first"
  if [[ "$PKI_MODE" == openssl ]]; then [[ -s "$PKI_DIR/ca.key" ]] || die "$EX_PREREQ" "pki/ca.key missing — cannot sign (restore it from backup, or use --pki step-ca)"; fi
  log_step "re-issuing ${#TARGETS[@]} certificate set(s): $(vs_join ' ' "${TARGETS[@]}")"
  if ((VS_DRY_RUN)); then
    local svc
    for svc in "${TARGETS[@]}"; do log_dry "issue $svc.crt/.key/.pem ($PKI_MODE/$PKI_ALGO, ${PKI_DAYS}d, previous set → pki-archive/)"; done
    plan_reload 0
    do_reload
    return 0
  fi
  ts="$(vs_ts)"
  archive_everything "$ts"
  issue_targets
  verify_all || die "$EX_FAIL" "verification failed — previous certificates restored from ${ARCHIVE_DIR#"$STACK_DIR"/}"
  ROTATE_DONE=1
  plan_reload 0
  do_reload
}

main() {
  parse_args "$@"
  vs_require openssl
  pki_validate_config
  if ((KUBE)); then
    log_step "Kubernetes rotation in namespace $NAMESPACE"
    ROTATE_DONE=1
    kube_reload
    if ((UNHEALTHY)); then exit "$EX_NOTREADY"; fi
    exit "$EX_OK"
  fi
  [[ -d "$PKI_DIR" ]] || die "$EX_PREREQ" "$PKI_DIR does not exist — run scripts/bootstrap.sh first"
  pki_migrate_legacy_archive
  select_targets
  if ((ROTATE_CA)); then ca_rotation; else standard_rotation; fi
  if ((UNHEALTHY)); then die "$EX_NOTREADY" "certificates were rotated but at least one service is not healthy — see above (previous set: ${ARCHIVE_DIR#"$STACK_DIR"/})"; fi
  if ((VS_DRY_RUN)); then log_dry "dry run complete — nothing was changed"; else log_ok "rotation complete"; fi
  exit "$EX_OK"
}

main "$@"
