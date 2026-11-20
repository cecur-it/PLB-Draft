#!/usr/bin/env bash
#
# pin-manager-cert.sh — pin the TLS certificate the Vendetta manager API actually presents.
#
# Traces: CONTRACT §6 (G9 offensive safety), errow/feedback-loop/APPROVALS.md, vendetta/API-CONTRACT.md,
#         CS3 deployment/operations/mtls-certificate-pinning.md.
#
# Why: the live legs (`errow-to-vendetta.sh`, `/approved-action`) verify the manager against
# `VENDETTA_API_CA_FILE` and now FAIL CLOSED when that file is missing or unusable — a private CA that silently
# degrades to the system trust store widens trust scope without anyone noticing. The bundled manager (a Wazuh
# stand-in, vendetta/API-CONTRACT.md) creates `/var/ossec` on first boot and lets authd generate its own
# self-signed certificate, so its leaf chains to nothing until it is pinned.
#
# What: connects read-only, extracts the leaf certificate, checks that it chains to the stack CA and carries the
# caller's name in its SAN, then writes a trust bundle = CA + any intermediates + the leaf to
# pki/manager-ca-bundle.crt (0644, inside the pki/ tree that errow-feedback already mounts). The bundle is
# additive: the private CA is never replaced, so every other verifier keeps working when the manager is swapped
# for a real, pki-issued one.
#
# A certificate that does not chain, or that lacks the SAN, is the stand-in case. Pinning then makes the gate
# trust exactly that one certificate, so it is refused without --yes (or an interactive confirmation).
#
# Usage: scripts/pin-manager-cert.sh [options]
#
# Exit codes: 0 ok | 1 failure (probe/write) | 2 usage | 3 policy (untrusted or mismatched certificate not
#             confirmed, or an existing pin changed without --force) | 4 missing prerequisite (openssl, no listener)

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat <<'EOF'
Pin the manager API certificate into a trust bundle for the live feedback legs.

Options:
  --connect HOST:PORT   TCP endpoint to probe (default: $VENDETTA_BIND:$VENDETTA_API_PORT, i.e. 127.0.0.1:55000)
  --server-name NAME    name the caller uses, checked against the SAN and sent as SNI (default: vendetta-manager)
  --ca-file FILE        stack CA to build the bundle from (default: pki/ca.crt)
  --out FILE            bundle to write (default: pki/manager-ca-bundle.crt)
  --force               overwrite an existing, different pin
  --yes                 accept a certificate that does not chain to the CA or lacks the SAN (stand-in manager)
  --dry-run             probe and report, write nothing
  --help                this text

After pinning, set VENDETTA_API_CA_FILE=/pki/manager-ca-bundle.crt for errow-feedback and restart it.
Verify with scripts/verify-manager.sh.
EOF
}

CONNECT=""
SERVER_NAME="vendetta-manager"
CA_FILE=""
OUT=""
FORCE=0
ASSUME_YES=0

parse_args() {
  local a
  vs_normalize_args "$@"
  set -- ${NORM_ARGS[@]+"${NORM_ARGS[@]}"}
  while (($#)); do
    a=$1
    case "$a" in
      --connect) vs_need "$@"; CONNECT=$2; shift 2 ;;
      --server-name) vs_need "$@"; SERVER_NAME=$2; shift 2 ;;
      --ca-file) vs_need "$@"; CA_FILE=$2; shift 2 ;;
      --out) vs_need "$@"; OUT=$2; shift 2 ;;
      --force) FORCE=1; shift ;;
      --yes) ASSUME_YES=1; shift ;;
      --dry-run) VS_DRY_RUN=1; shift ;;
      -h|--help) usage; exit "$EX_OK" ;;
      --stack-dir) vs_need "$@"; STACK_DIR="$(cd "$2" && pwd)"; PKI_DIR="$STACK_DIR/pki"; ENV_FILE="$STACK_DIR/.env"; shift 2 ;;
      *) usage >&2; die "$EX_USAGE" "unknown argument: $a" ;;
    esac
  done
}

confirm() { # <question> <policy-message>
  if ((ASSUME_YES)); then return 0; fi
  if [[ ! -t 0 ]]; then die "$EX_POLICY" "$2"; fi
  local answer=""
  read -r -p "$1 [y/N] " answer || true
  case "${answer:-n}" in y|Y|yes|YES) return 0 ;; *) die "$EX_POLICY" "$2" ;; esac
}

# probe <dir> — write every PEM block the endpoint presents as <dir>/blk.N (blk.1 = leaf, rest = chain).
probe() {
  local dir=$1 raw="$1/s_client.txt"
  set +e
  openssl s_client -connect "$CONNECT_HOST:$CONNECT_PORT" -servername "$SERVER_NAME" -showcerts </dev/null >"$raw" 2>&1
  set -e
  grep -q 'BEGIN CERTIFICATE' "$raw" \
    || die "$EX_PREREQ" "no certificate from $CONNECT_HOST:$CONNECT_PORT — is vendetta-manager running (docker compose --profile manager ps)?"
  awk -v d="$dir" '
    /^-----BEGIN CERTIFICATE-----/ { on = 1; n++ }
    on { print > (d "/blk." n) }
    on && /^-----END CERTIFICATE-----/ { on = 0 }
  ' "$raw"
  [[ -s "$dir/blk.1" ]] || die "$EX_FAIL" "could not extract the leaf certificate"
  openssl x509 -in "$dir/blk.1" -noout >/dev/null 2>&1 || die "$EX_FAIL" "the endpoint did not present a parseable certificate"
}

# chain_files <dir> — the presented chain (everything after the leaf), one path per line.
chain_files() {
  local f
  for f in "$1"/blk.*; do
    case "$f" in */blk.1) continue ;; esac
    [[ -f "$f" ]] && printf '%s\n' "$f"
  done
}

main() {
  parse_args "$@"

  if [[ -z "$CONNECT" ]]; then
    CONNECT="$(vs_cfg VENDETTA_BIND 127.0.0.1):$(vs_cfg VENDETTA_API_PORT 55000)"
  fi
  [[ "$CONNECT" == *:* ]] || die "$EX_USAGE" "--connect needs HOST:PORT (got '$CONNECT')"
  CONNECT_HOST=${CONNECT%:*}
  CONNECT_PORT=${CONNECT##*:}
  vs_valid_port "$CONNECT_PORT" || die "$EX_USAGE" "--connect port must be 1..65535 (got '$CONNECT_PORT')"
  [[ -n "$CONNECT_HOST" ]] || die "$EX_USAGE" "--connect needs a host"
  [[ "$SERVER_NAME" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] || die "$EX_USAGE" "--server-name is not a host name: '$SERVER_NAME'"
  CA_FILE="${CA_FILE:-$PKI_DIR/ca.crt}"
  OUT="${OUT:-$PKI_DIR/manager-ca-bundle.crt}"

  vs_require openssl awk grep cmp
  trap 'vs_cleanup' EXIT
  vs_mkwork pin-manager-cert
  [[ -s "$CA_FILE" ]] || die "$EX_USAGE" "stack CA missing or empty: $CA_FILE (run scripts/bootstrap.sh first)"

  log_info "probing $CONNECT_HOST:$CONNECT_PORT for '$SERVER_NAME'"
  probe "$VS_WORK"
  LEAF="$VS_WORK/blk.1"

  local fp san verified=1
  fp="$(openssl x509 -in "$LEAF" -noout -fingerprint -sha256 | sed 's/^.*=//')"
  san="$(openssl x509 -in "$LEAF" -noout -ext subjectAltName 2>/dev/null | sed -n '2,$p' | tr -d ' \n' || true)"
  log_info "presented SHA-256 $fp"
  log_info "presented SAN(s): ${san:-<none>}"
  case ",${san}," in
    *",DNS:$SERVER_NAME,"*|*",DNS:*.$SERVER_NAME,"*) ;;
    *) verified=0; log_warn "the certificate has no SAN for '$SERVER_NAME' — callers verifying that name will fail" ;;
  esac

  local -a untrusted=() vargs=()
  while IFS= read -r f; do [[ -n "$f" ]] && untrusted+=("$f"); done < <(chain_files "$VS_WORK")
  for f in ${untrusted[@]+"${untrusted[@]}"}; do vargs+=(-untrusted "$f"); done
  if { ((${#vargs[@]})) && openssl verify -CAfile "$CA_FILE" ${vargs[@]+"${vargs[@]}"} "$LEAF"; } >/dev/null 2>&1 \
    || openssl verify -CAfile "$CA_FILE" "$LEAF" >/dev/null 2>&1; then
    log_ok "chains to $CA_FILE — issued by the stack CA"
  else
    verified=0
    log_warn "does NOT chain to $CA_FILE — this is the stand-in / self-signed manager certificate"
  fi

  if ((verified == 0)); then
    log_warn "pinning trusts exactly the certificate above; a swapped manager needs a re-pin"
    confirm "pin the presented certificate anyway?" "certificate not pinned — re-run with --yes to pin unattended"
  fi

  # bundle: CA, presented intermediates, leaf — deduplicated
  local bundle="$VS_WORK/bundle.crt" h seen="" f dir
  : >"$bundle"
  for f in "$CA_FILE" ${untrusted[@]+"${untrusted[@]}"} "$LEAF"; do
    h="$(vs_sha256 "$f")"
    case ",$seen," in *",$h,"*) continue ;; esac
    seen="$seen,$h"
    cat "$f" >>"$bundle"
  done

  if [[ -s "$OUT" ]]; then
    if cmp -s "$bundle" "$OUT"; then log_ok "already pinned at $OUT (unchanged)"; return 0; fi
    if ((FORCE == 0)); then
      die "$EX_POLICY" "$OUT holds a different pin — the manager certificate changed; re-run with --force once confirmed"
    fi
    log_warn "$OUT changes"
  fi
  if ((VS_DRY_RUN)); then
    log_dry "would write $OUT (leaf SHA-256 $fp, $(grep -c 'BEGIN CERTIFICATE' "$bundle") certificate(s))"
    return 0
  fi

  dir="$(dirname "$OUT")"
  (umask 022; mkdir -p "$dir")
  (umask 022; cat "$bundle" >"$OUT.tmp.$$")
  chmod 0644 "$OUT.tmp.$$"
  mv -f "$OUT.tmp.$$" "$OUT"
  log_ok "pinned $fp to $OUT"
  log_info "next: set VENDETTA_API_CA_FILE=/pki/manager-ca-bundle.crt on errow-feedback and restart it"
}

main "$@"
