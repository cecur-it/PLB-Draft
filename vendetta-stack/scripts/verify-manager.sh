#!/usr/bin/env bash
#
# verify-manager.sh — assert that the manager API still presents the pinned, trusted certificate.
#
# Traces: CONTRACT §6 (G9 offensive safety), vendetta/API-CONTRACT.md, scripts/healthcheck.sh.
# Counterpart of scripts/pin-manager-cert.sh and the pre-flight for anything that runs `ERROW_FEEDBACK_LIVE=true`.
#
# Checks, in order, and stops at the first failure:
#   1. something answers on the endpoint and presents a certificate;
#   2. the presented chain verifies against the trust bundle (pki/manager-ca-bundle.crt, else pki/ca.crt);
#   3. the presented leaf is byte-identical to the leaf in the bundle — a new certificate means a rotation that
#      nobody re-pinned, which would otherwise only show up as a 503 from the gate;
#   4. the leaf's SAN covers the name the callers verify ($VENDETTA_API_URL host, default vendetta-manager).
#
# Usage: scripts/verify-manager.sh [--connect HOST:PORT] [--server-name NAME] [--bundle FILE] [--quiet]
# Exit codes: 0 ok | 1 the manager or its certificate does not match the pin | 2 usage | 4 prerequisite missing

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat <<'EOF'
Verify the manager API certificate against the pinned trust bundle.

Options:
  --connect HOST:PORT   TCP endpoint to probe (default: $VENDETTA_BIND:$VENDETTA_API_PORT, i.e. 127.0.0.1:55000)
  --server-name NAME    name the callers verify (default: vendetta-manager)
  --bundle FILE         trust bundle (default: pki/manager-ca-bundle.crt, else pki/ca.crt)
  --quiet               only print the verdict word
  --help                this text

Exit: 0 ok | 1 the certificate is missing, untrusted, rotated or lacks the SAN | 2 usage | 4 no openssl
EOF
}

CONNECT=""
SERVER_NAME="vendetta-manager"
BUNDLE=""
QUIET=0

parse_args() {
  local a
  vs_normalize_args "$@"
  set -- ${NORM_ARGS[@]+"${NORM_ARGS[@]}"}
  while (($#)); do
    a=$1
    case "$a" in
      --connect) vs_need "$@"; CONNECT=$2; shift 2 ;;
      --server-name) vs_need "$@"; SERVER_NAME=$2; shift 2 ;;
      --bundle) vs_need "$@"; BUNDLE=$2; shift 2 ;;
      --quiet|-q) QUIET=1; shift ;;
      -h|--help) usage; exit "$EX_OK" ;;
      --stack-dir) vs_need "$@"; STACK_DIR="$(cd "$2" && pwd)"; PKI_DIR="$STACK_DIR/pki"; ENV_FILE="$STACK_DIR/.env"; shift 2 ;;
      *) usage >&2; die "$EX_USAGE" "unknown argument: $a" ;;
    esac
  done
}

verdict() { # <exit-code> <message>
  if ((QUIET)); then
    case "$1" in 0) printf 'ok\n' ;; *) printf 'fail: %s\n' "$2" ;; esac
  elif (($1 == 0)); then log_ok "$2"; else log_err "$2"; fi
  exit "$1"
}

main() {
  parse_args "$@"
  vs_require openssl awk grep cmp

  if [[ -z "$CONNECT" ]]; then
    CONNECT="$(vs_cfg VENDETTA_BIND 127.0.0.1):$(vs_cfg VENDETTA_API_PORT 55000)"
  fi
  [[ "$CONNECT" == *:* ]] || die "$EX_USAGE" "--connect needs HOST:PORT (got '$CONNECT')"
  local host=${CONNECT%:*} port=${CONNECT##*:}
  vs_valid_port "$port" || die "$EX_USAGE" "--connect port must be 1..65535 (got '$port')"
  [[ -n "$host" ]] || die "$EX_USAGE" "--connect needs a host"

  if [[ -z "$BUNDLE" ]]; then
    if [[ -s "$PKI_DIR/manager-ca-bundle.crt" ]]; then BUNDLE="$PKI_DIR/manager-ca-bundle.crt"
    elif [[ -s "$PKI_DIR/ca.crt" ]]; then BUNDLE="$PKI_DIR/ca.crt"
    else verdict "$EX_FAIL" "no trust bundle ($PKI_DIR/manager-ca-bundle.crt) and no $PKI_DIR/ca.crt — run scripts/pin-manager-cert.sh"
    fi
  fi
  [[ -s "$BUNDLE" ]] || verdict "$EX_FAIL" "trust bundle missing or empty: $BUNDLE — run scripts/pin-manager-cert.sh"

  trap 'vs_cleanup' EXIT
  vs_mkwork verify-manager
  local raw="$VS_WORK/s_client.txt"
  set +e
  openssl s_client -connect "$host:$port" -servername "$SERVER_NAME" -showcerts </dev/null >"$raw" 2>&1
  set -e
  grep -q 'BEGIN CERTIFICATE' "$raw" || verdict "$EX_FAIL" "no certificate from $host:$port (is the manager running?)"
  awk -v d="$VS_WORK" '
    /^-----BEGIN CERTIFICATE-----/ { on = 1; n++ }
    on { print > (d "/blk." n) }
    on && /^-----END CERTIFICATE-----/ { on = 0 }
  ' "$raw"
  local leaf="$VS_WORK/blk.1" f
  openssl x509 -in "$leaf" -noout >/dev/null 2>&1 || verdict "$EX_FAIL" "$host:$port did not present a parseable certificate"

  local fp
  fp="$(openssl x509 -in "$leaf" -noout -fingerprint -sha256 | sed 's/^.*=//')"

  # 2. chain: bundle minus the pinned leaf, plus the presented chain as untrusted material
  local -a vargs=()
  for f in "$VS_WORK"/blk.*; do case "$f" in */blk.1) continue ;; esac; vargs+=(-untrusted "$f"); done
  if ! openssl verify -CAfile "$BUNDLE" ${vargs[@]+"${vargs[@]}"} "$leaf" >/dev/null 2>&1; then
    verdict "$EX_FAIL" "certificate $fp does not verify against $BUNDLE (pinned? rotated CA?)"
  fi

  # 3. pin equality — the last certificate in a pin bundle is the pinned leaf
  if [[ "$(basename "$BUNDLE")" == manager-ca-bundle.crt ]]; then
    awk -v d="$VS_WORK" '
      /^-----BEGIN CERTIFICATE-----/ { on = 1; n++ }
      on { print > (d "/pin." n) }
      on && /^-----END CERTIFICATE-----/ { on = 0 }
    ' "$BUNDLE"
    local pinned_fp="" b
    for b in "$VS_WORK"/pin.*; do
      [[ -f "$b" ]] || continue
      pinned_fp="$(openssl x509 -in "$b" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
    done
    if [[ -z "$pinned_fp" ]]; then
      verdict "$EX_FAIL" "$BUNDLE carries no parseable certificate — re-run scripts/pin-manager-cert.sh"
    elif [[ "$pinned_fp" != "$fp" ]]; then
      verdict "$EX_FAIL" "manager certificate rotated (pinned $pinned_fp, presented $fp) — re-pin with scripts/pin-manager-cert.sh --force"
    fi
  fi

  # 4. name check
  local san
  san="$(openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null | sed -n '2,$p' | tr -d ' \n' || true)"
  case ",${san}," in
    *",DNS:$SERVER_NAME,"*|*",DNS:*.$SERVER_NAME,"*) ;;
    *) verdict "$EX_FAIL" "certificate $fp has no SAN for '$SERVER_NAME' (SANs: ${san:-none})" ;;
  esac

  verdict "$EX_OK" "manager certificate $fp verified against $(basename "$BUNDLE"), SAN covers $SERVER_NAME"
}

main "$@"
