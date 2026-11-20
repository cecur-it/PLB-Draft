#!/usr/bin/env bash
# Traces: PROMPT §4 Phase 4 (validation); CONTRACT §2 (PKI file names)
# Generates a THROWAWAY test PKI (never used outside the tests): ca.crt and <svc>.crt/.key for fluent-bit, fluentd-1,
# fluentd-2, esoc-sink. EC P-256, 2-day validity, SAN = service DNS + localhost + 127.0.0.1, EKU serverAuth+clientAuth.
# Idempotent: re-running leaves existing files alone.
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

usage() { echo "Usage: make-pki.sh <output-dir> [service...]   (default services: fluent-bit fluentd-1 fluentd-2 esoc-sink)"; }
case "${1:-}" in -h | --help | '') usage; exit 0 ;; *) ;; esac

out="$1"
shift
services=("$@")
((${#services[@]} > 0)) || services=(fluent-bit fluentd-1 fluentd-2 esoc-sink)
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 3; }
mkdir -p "$out"

if [[ ! -s "$out/ca.crt" || ! -s "$out/ca.key" ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$out/ca.key"
  openssl req -new -x509 -key "$out/ca.key" -sha256 -days 2 -subj "/CN=vendetta-stack-test-ca" -out "$out/ca.crt"
fi

for svc in "${services[@]}"; do
  if [[ -s "$out/$svc.crt" && -s "$out/$svc.key" ]]; then continue; fi
  openssl ecparam -name prime256v1 -genkey -noout -out "$out/$svc.key"
  openssl req -new -key "$out/$svc.key" -subj "/CN=$svc" -out "$out/$svc.csr"
  printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\n' "$svc" >"$out/$svc.ext"
  openssl x509 -req -in "$out/$svc.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" -CAcreateserial -days 2 -sha256 -extfile "$out/$svc.ext" -out "$out/$svc.crt" 2>/dev/null
  rm -f "$out/$svc.csr" "$out/$svc.ext"
done
chmod 0644 "$out"/*.crt "$out"/*.key
