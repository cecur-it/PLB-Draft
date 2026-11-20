#!/usr/bin/env bash
# Traces: PROMPT §4 Phase 4 (validation); CONTRACT §8.3 (legs on/off), §1 (pinned image)
# Validates the Fluent Bit tree on the exact pinned image, in two layers, because `fluent-bit -D` (dry run) in 3.2.10 only
# parses the files and does NOT reject unknown plugin properties or missing certificates:
#   1. `entrypoint.sh --validate` (renders legs/inputs, then `fluent-bit -D`), and
#   2. a bounded real boot (8 s) that must stay up and log no configuration-class [error] (egress connection errors to the
#      unreachable test hosts are expected and filtered).
# Cases: every leg on, every leg off, every optional input on, plus negative cases that must exit 3 (bad environment).
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
IMAGE="${FLB_IMAGE:-fluent/fluent-bit:3.2.10-debug@sha256:ddc7932ed69e1e7bc34a62c57525c49f3947dc5fcee8b92256a33ae1836f3cda}"
RUN_ID="$$"
SCRATCH="$ROOT/.scratch/validate-$RUN_ID"
BOOT_SECONDS="${BOOT_SECONDS:-8}"
PASS=0
FAIL=0
CONTAINER=""

usage() {
  cat <<EOF
Usage: validate.sh [-h|--help]
  Validates the Fluent Bit config tree on $IMAGE (override with FLB_IMAGE).
  Needs docker. BOOT_SECONDS (default $BOOT_SECONDS) bounds each real boot.
EOF
}
case "${1:-}" in -h | --help) usage; exit 0 ;; '') ;; *) usage >&2; exit 2 ;; esac

cleanup() {
  local rc=$?
  [[ -z "$CONTAINER" ]] || docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH"
  return "$rc"
}
trap cleanup EXIT

ok() { PASS=$((PASS + 1)); echo "  PASS  $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $*" >&2; }

retry() {
  local tries="$1" delay="$2" n=0
  shift 2
  until "$@"; do
    n=$((n + 1))
    ((n < tries)) && sleep "$delay" || return 1
  done
}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 3; }
mkdir -p "$SCRATCH/pki"
"$HERE/make-pki.sh" "$SCRATCH/pki" fluent-bit fluentd-1 fluentd-2 >/dev/null
: >"$SCRATCH/auth.log"
mkdir -p "$SCRATCH/audit"
: >"$SCRATCH/audit/audit.log"
docker image inspect "$IMAGE" >/dev/null 2>&1 || retry 3 5 docker pull "$IMAGE" >/dev/null

BASE_MOUNTS=(-v "$ROOT":/etc/fluent-bit:ro --tmpfs /etc/fluent-bit/enabled.d -v "$SCRATCH/pki":/pki:ro
  --tmpfs /var/log/fluent-bit --tmpfs /var/log/errow --tmpfs /var/vendetta/logs)
ALL_LEGS=(-e CS3_CONSOLE_ENABLED=true -e CS3_HOST=console.invalid -e CS3_PORT=443 -e CS3_INGEST_KEY=k
  -e CS3_ESOC_ENABLED=true -e CS3_ESOC_HOST=esoc.invalid -e CS3_ESOC_PORT=4317
  -e CS3_SIEM_ENABLED=true -e CS3_SIEM_HOST=siem.invalid -e CS3_SIEM_PORT=443 -e CS3_SIEM_TOKEN=t)
OPTIONAL=(--tmpfs /var/log/journal --tmpfs /var/log/errow/reports --tmpfs /var/log/errow/caido
  --tmpfs /var/log/cfgaudit -e CFGAUDIT_ENABLED=true
  -v "$SCRATCH/auth.log":/var/log/auth.log:ro -v "$SCRATCH/audit/audit.log":/var/log/audit/audit.log:ro
  -e FLB_SYSLOG_ENABLED=true)

# $1 name, $2 expected exit code, rest: extra docker args
dry_run() {
  local name="$1" want="$2" rc=0 out
  shift 2
  out="$(docker run --rm --entrypoint /etc/fluent-bit/entrypoint.sh "${BASE_MOUNTS[@]}" "$@" "$IMAGE" --validate 2>&1)" || rc=$?
  if [[ "$rc" -eq "$want" ]]; then ok "$name: entrypoint --validate exit $rc"; else
    bad "$name: entrypoint --validate exit $rc, wanted $want"
    printf '%s\n' "$out" | tail -15 >&2
  fi
  LAST_OUT="$out"
}

boot() {
  local name="$1" logs
  shift
  CONTAINER="flbval-$RUN_ID"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" --entrypoint /etc/fluent-bit/entrypoint.sh "${BASE_MOUNTS[@]}" "$@" -e FLB_LOG_LEVEL=info "$IMAGE" >/dev/null
  sleep "$BOOT_SECONDS"
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" == true ]]; then ok "$name: real boot stays up ${BOOT_SECONDS}s"; else bad "$name: container exited"; fi
  if docker exec "$CONTAINER" /etc/fluent-bit/entrypoint.sh --healthcheck >/dev/null 2>&1; then ok "$name: healthcheck"; else bad "$name: healthcheck"; fi
  logs="$(docker logs "$CONTAINER" 2>&1)"
  if grep -E '\[error\]' <<<"$logs" | grep -vE 'getaddrinfo|error initializing http request|no upstream connections|http_client|[Cc]onnection (refused|reset)|failed to flush|DNS' | grep -q .; then
    bad "$name: configuration-class [error] lines in the log"
    grep -E '\[error\]' <<<"$logs" | head -10 >&2
  else ok "$name: no configuration-class [error] lines"; fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  CONTAINER=""
}

echo "== help / usage"
if docker run --rm --entrypoint /etc/fluent-bit/entrypoint.sh "${BASE_MOUNTS[@]}" "$IMAGE" --help >/dev/null 2>&1; then ok "entrypoint --help exit 0"; else bad "entrypoint --help"; fi

echo "== all legs enabled"
dry_run all-legs 0 "${ALL_LEGS[@]}"
for frag in 10-console 20-esoc 30-siem; do
  if grep -q "enabled $frag.conf" <<<"$LAST_OUT"; then ok "all-legs: $frag rendered"; else bad "all-legs: $frag not rendered"; fi
done
boot all-legs "${ALL_LEGS[@]}"

echo "== all legs disabled"
dry_run no-legs 0
for frag in 10-console 20-esoc 30-siem; do
  if grep -q "enabled $frag.conf" <<<"$LAST_OUT"; then bad "no-legs: $frag rendered although disabled"; else ok "no-legs: $frag not rendered"; fi
done
boot no-legs

echo "== every optional input"
dry_run optional-inputs 0 "${ALL_LEGS[@]}" "${OPTIONAL[@]}"
for frag in systemd host-auth host-audit syslog errow-reports caido cfgaudit; do
  if grep -q "enabled $frag.conf" <<<"$LAST_OUT"; then ok "optional: $frag rendered"; else bad "optional: $frag not rendered"; fi
done
boot optional-inputs "${ALL_LEGS[@]}" "${OPTIONAL[@]}"
boot optional-inputs-journal-all "${ALL_LEGS[@]}" "${OPTIONAL[@]}" -e CS3_JOURNAL_ALL=true

echo "== forward-input TLS on"
dry_run forward-tls 0 "${ALL_LEGS[@]}" -e FLB_FORWARD_TLS=on
boot forward-tls "${ALL_LEGS[@]}" -e FLB_FORWARD_TLS=on

echo "== negative cases (must exit 3: bad environment)"
dry_run missing-console-host 3 -e CS3_CONSOLE_ENABLED=true -e CS3_INGEST_KEY=k
dry_run missing-siem-token 3 -e CS3_SIEM_ENABLED=true -e CS3_SIEM_HOST=siem.invalid
dry_run bad-eps-limit 3 -e CS3_EPS_LIMIT=abc
dry_run cfgaudit-directory-missing 3 -e CFGAUDIT_ENABLED=true
dry_run tui-port-collision 3 -e ERROW_TUI_PORT=24224
dry_run esoc-mtls-files-missing 3 -e CS3_ESOC_ENABLED=true -e CS3_ESOC_HOST=esoc.invalid -e CS3_ESOC_CA_FILE=/pki/none.crt

echo
echo "RESULT: $PASS passed, $FAIL failed"
((FAIL == 0))
