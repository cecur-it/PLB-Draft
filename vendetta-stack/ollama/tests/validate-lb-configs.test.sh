#!/usr/bin/env bash
#
# validate-lb-configs.test.sh — real validation of ollama/ollama-lb/{haproxy.cfg,worker-proxy.cfg,nginx.conf}
# with the pinned HAProxy / NGINX images (CONTRACT §1), throw-away openssl PKI and --add-host:
#   1. haproxy -c on the LB and on the worker proxy; nginx -t (with and without DNS for ollama-workers)
#   2. negative control: a broken HAProxy config must be rejected
#   3. end-to-end (skipped with --no-e2e): mock-ollama <- worker-proxy (mTLS) <- ollama-lb; asserts proxying,
#      403 on /api/pull|delete|create|push and admin paths, 503 pass-through for a down model, and that a
#      client without a certificate cannot reach the worker proxy. Everything is removed on exit.
#
# Traces: PROMPT §1 Tier 4 / §3 (mTLS, no admin surface), CONTRACT §8.1 (worker topology), §1 (pinned images).
# Usage: ollama/tests/validate-lb-configs.test.sh [--no-e2e] [--help]     Requires: docker, openssl.
# shellcheck disable=SC2015  # `cond && ok || bad` is intentional: ok/bad always return 0
set -euo pipefail
set -o errtrace
IFS=$'\n\t'
trap 'echo "TEST HARNESS ERROR at line $LINENO" >&2' ERR

readonly HAPROXY_IMAGE="haproxy:3.0-alpine@sha256:d2b3567d836f3b7d174edb6d6f611ed5308e7966e53a9cd9a597e0415a298efd"
readonly NGINX_IMAGE="nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"
readonly PYTHON_IMAGE="python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"

E2E=true
case "${1:-}" in
  -h|--help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' -e '/^#$/s/^#//'; exit 0 ;;
  --no-e2e) E2E=false ;;
  "") ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OLLAMA_DIR="$(cd "$HERE/.." && pwd)"
LB_DIR="$OLLAMA_DIR/ollama-lb"
for dep in docker openssl; do
  command -v "$dep" >/dev/null 2>&1 || { echo "missing dependency: $dep" >&2; exit 2; }
done

mkdir -p "${TMPDIR:-/var/tmp}"
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cs3-lb-test.XXXXXX")"
SUFFIX="$$"
NET="cs3-lbtest-net-$SUFFIX"
MOCK="cs3-lbtest-mock-$SUFFIX"
WPROXY="cs3-lbtest-wproxy-$SUFFIX"
LB="cs3-lbtest-lb-$SUFFIX"
cleanup() {
  docker rm -f "$LB" "$WPROXY" "$MOCK" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
check_not() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }

echo "== throw-away PKI (CA, ollama-1 worker, ollama-lb client)"
mkdir -p "$T/pki"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/pki/ca.key" -out "$T/pki/ca.crt" -days 2 -subj "/CN=cs3-lbtest-ca" 2>/dev/null
for svc in ollama-1 ollama-lb; do
  openssl req -newkey rsa:2048 -nodes -keyout "$T/pki/$svc.key" -out "$T/pki/$svc.csr" -subj "/CN=$svc" 2>/dev/null
  printf 'subjectAltName=DNS:%s,DNS:localhost\nextendedKeyUsage=serverAuth,clientAuth\n' "$svc" >"$T/pki/$svc.ext"
  openssl x509 -req -in "$T/pki/$svc.csr" -CA "$T/pki/ca.crt" -CAkey "$T/pki/ca.key" -CAcreateserial -out "$T/pki/$svc.crt" -days 2 -extfile "$T/pki/$svc.ext" 2>/dev/null
  cat "$T/pki/$svc.crt" "$T/pki/$svc.key" >"$T/pki/$svc.pem"
done
chmod 0644 "$T"/pki/*

haproxy_check() { docker run --rm --add-host ollama-workers:127.0.0.1 -v "$1:/usr/local/etc/haproxy/haproxy.cfg:ro" -v "$T/pki:/pki:ro" "$HAPROXY_IMAGE" haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg; }
nginx_check() { docker run --rm "$@" -v "$LB_DIR/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$T/pki:/pki:ro" "$NGINX_IMAGE" nginx -t; }

echo "== static validation"
check "haproxy -c haproxy.cfg" haproxy_check "$LB_DIR/haproxy.cfg"
check "haproxy -c worker-proxy.cfg" haproxy_check "$LB_DIR/worker-proxy.cfg"
check "nginx -t nginx.conf (ollama-workers resolvable)" nginx_check --add-host ollama-workers:127.0.0.1
check "nginx -t nginx.conf (no DNS entry: starts without workers)" nginx_check
sed 's/^  balance leastconn/  balance nonsense/' "$LB_DIR/haproxy.cfg" >"$T/broken.cfg"
check_not "negative control: broken haproxy.cfg is rejected" haproxy_check "$T/broken.cfg"
for f in haproxy.cfg worker-proxy.cfg; do
  check "$f denies pull/push/create/delete/copy/blobs with 403" grep -qF 'http-request deny deny_status 403 if p_mutating' "$LB_DIR/$f"
done
check "nginx.conf denies pull/push/create/delete/copy/blobs with 403" grep -qE '\^/api/\(pull\|push\|create\|delete\|copy\|blobs\).*return 403' "$LB_DIR/nginx.conf"
check "haproxy.cfg: per-server maxconn 4 and 30s queue timeout" grep -qE 'maxconn 4 slowstart' "$LB_DIR/haproxy.cfg"
check "haproxy.cfg: queue timeout 30s" grep -qx '  timeout queue 30s' "$LB_DIR/haproxy.cfg"

if [[ "$E2E" == "true" ]]; then
  echo "== end-to-end: mock <- worker-proxy (mTLS) <- ollama-lb"
  docker network create "$NET" >/dev/null
  harden=(--read-only --cap-drop ALL --security-opt no-new-privileges:true)
  docker run -d --name "$MOCK" --network "$NET" --network-alias ollama-workers --user 65534:65534 "${harden[@]}" \
    -v "$OLLAMA_DIR/mock/mock_ollama.py:/app/mock_ollama.py:ro" "$PYTHON_IMAGE" python /app/mock_ollama.py >/dev/null
  docker run -d --name "$WPROXY" --network "container:$MOCK" "${harden[@]}" -v "$LB_DIR/worker-proxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "$T/pki:/pki:ro" "$HAPROXY_IMAGE" >/dev/null
  docker run -d --name "$LB" --network "$NET" "${harden[@]}" -v "$LB_DIR/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "$T/pki:/pki:ro" "$HAPROXY_IMAGE" >/dev/null

  lb_get() { docker exec "$LB" wget -qO- "http://127.0.0.1:$1"; }
  lb_status() { docker exec "$LB" sh -c "wget -S -qO /dev/null '$1' 2>&1 | grep -m1 -o 'HTTP/1.1 [0-9]*'" || true; }
  lb_chat() {
    docker exec -e BODY="$1" "$LB" sh -c 'wget -S -qO- --header "Content-Type: application/json" --post-data "$BODY" http://127.0.0.1:11434/v1/chat/completions 2>&1' || true
  }
  ready=false
  for _ in $(seq 1 60); do
    if lb_get 8404/ready >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
  done
  [[ "$ready" == "true" ]] && ok "LB reports a healthy worker on /ready (mTLS check succeeded)" || bad "LB never became ready"

  check "mock container healthcheck command" docker exec "$MOCK" python /app/mock_ollama.py --healthcheck
  # /ready only proves nbsrv >= 1, which is true before the first check completes: wait for the proxy's own verdict.
  healthy=false
  for _ in $(seq 1 60); do
    if docker exec "$WPROXY" wget -qO /dev/null http://127.0.0.1:8405/healthz >/dev/null 2>&1; then healthy=true; break; fi
    sleep 1
  done
  [[ "$healthy" == "true" ]] && ok "worker-proxy loopback /healthz (mock reachable)" || bad "worker-proxy never became healthy"
  check "LB /healthz on the ops listener" lb_get 8404/healthz
  # The LB check needs two successes (rise 2, inter 5s) after the proxy's own backend came up: poll the chain.
  chain=""
  for _ in $(seq 1 60); do
    chain="$(lb_get 11434/api/version 2>/dev/null || true)"
    [[ "$chain" == '{"version":"0.40.5"}' ]] && break
    sleep 1
  done
  [[ "$chain" == '{"version":"0.40.5"}' ]] && ok "/api/version through LB -> mTLS -> mock" || bad "/api/version through the chain"
  lb_get 11434/api/tags | grep -q 'gemma4:31b' && ok "/api/tags lists the models" || bad "/api/tags through the chain"
  for p in /api/pull /api//delete /api/./create /api/push /__control /metrics /admin/x /nope; do
    [[ "$(lb_status "http://127.0.0.1:11434$p")" == "HTTP/1.1 403" ]] && ok "LB answers 403 for $p" || bad "LB must answer 403 for $p"
  done
  reply="$(lb_chat '{"model":"nemotron-3-nano:30b","messages":[{"role":"user","content":"brute force on ssh"}]}')"
  grep -q 'Credential Access' <<<"$reply" && ok "chat completion proxied end to end" || bad "chat completion through the chain"
  docker exec "$MOCK" python -c "import json,urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:11434/__control', json.dumps({'down_models':['gemma4:26b']}).encode(), {'Content-Type':'application/json'}))"
  reply="$(lb_chat '{"model":"gemma4:26b","messages":[{"role":"user","content":"x"}]}')"
  grep -q 'HTTP/1.1 503' <<<"$reply" && ok "a down model's 503 passes through the LB" || bad "503 pass-through"
  check_not "a client without a certificate cannot use the worker proxy" docker exec "$LB" wget --no-check-certificate -qO- https://ollama-workers:11443/api/tags
  check "LB exposes Prometheus metrics on the ops listener" lb_get 8404/metrics
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
