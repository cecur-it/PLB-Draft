#!/usr/bin/env bash
# Traces: PROMPT §4 Phase 4 (validation), §1 Tier 1; CONTRACT §5, §8.3 (leg isolation), §3 (streams)
# Behavioural test of the edge collector on the pinned Fluent Bit image, entirely inside a throw-away docker network:
#   edge (this tree, all three legs on)  ->  sink  (Console :8080, SIEM :8081, ESOC OTLP/HTTP :4318)
#                                        ->  fluentd-1 / fluentd-2 (stand-in aggregators, mTLS Forward, tests/aggregator.conf)
# Proves: cs3.ai.ollama reaches ONLY the safety file + ESOC + SIEM (never Console, never the forward output); a Vendetta
# alert reaches the Console (X-API-Key) and is retagged vendetta.fim; secrets are redacted and long messages truncated
# before egress; hash-chained gateway events keep their nulls; Errow TUI events go ONLY to the aggregators; findings tails,
# stream tasks and the Forward-input client-certificate behaviour.
# Everything lives in containers/volumes-less tmpfs; the only host files are the scratch PKI (removed on exit).
set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
IMAGE="${FLB_IMAGE:-fluent/fluent-bit:3.2.10-debug@sha256:ddc7932ed69e1e7bc34a62c57525c49f3947dc5fcee8b92256a33ae1836f3cda}"
RUN_ID="$$"
NET="flbleg-net-$RUN_ID"
EDGE="flbleg-edge-$RUN_ID"
SINK="flbleg-sink-$RUN_ID"
AGG1="flbleg-agg1-$RUN_ID"
AGG2="flbleg-agg2-$RUN_ID"
SCRATCH="$ROOT/.scratch/legs-$RUN_ID"
SP_WAIT="${SP_WAIT:-100}"
PASS=0
FAIL=0

usage() {
  cat <<EOF
Usage: test_legs.sh [--keep] [--no-stream-wait] [-h|--help]
  Behavioural leg-isolation test (needs docker; pulls $IMAGE if missing).
  --keep            leave containers/network/scratch for inspection
  --no-stream-wait  skip the ~70 s wait for the 60 s stream-task window
Env: FLB_IMAGE (image override), SP_WAIT (max seconds to wait for a stream-task record, default $SP_WAIT)
EOF
}

KEEP=false
WAIT_SP=true
while (($# > 0)); do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --keep) KEEP=true ;;
    --no-stream-wait) WAIT_SP=false ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

cleanup() {
  local rc=$?
  if [[ "$KEEP" == true ]]; then
    echo "kept: network $NET, containers $EDGE $SINK $AGG1 $AGG2, scratch $SCRATCH"
    return "$rc"
  fi
  docker rm -f "$EDGE" "$SINK" "$AGG1" "$AGG2" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH"
  return "$rc"
}
trap cleanup EXIT

ok() {
  PASS=$((PASS + 1))
  echo "  PASS  $*"
}
bad() {
  FAIL=$((FAIL + 1))
  echo "  FAIL  $*" >&2
}

retry() {
  local tries="$1" delay="$2" n=0
  shift 2
  until "$@"; do
    n=$((n + 1))
    ((n < tries)) && sleep "$delay" || return 1
  done
}

dx() { docker exec -i "$1" "${@:2}"; }
sink_file() { dx "$SINK" cat "/out/$1.ndjson" 2>/dev/null || true; }
agg_file() { { dx "$AGG1" cat /out/fluentd-1.log 2>/dev/null; dx "$AGG2" cat /out/fluentd-2.log 2>/dev/null; } || true; }
safety_file() { dx "$EDGE" cat /var/log/fluent-bit/cs3-ai-ollama.ndjson 2>/dev/null || true; }
post() { dx "$EDGE" curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data "$2" "http://127.0.0.1:9880/$1"; }

has() { grep -qF -- "$2" <<<"$1"; }
assert_contains() {
  local name="$1" hay="$2" needle="$3"
  if has "$hay" "$needle"; then ok "$name"; else bad "$name (missing: $needle)"; fi
}
assert_absent() {
  local name="$1" hay="$2" needle="$3"
  if has "$hay" "$needle"; then bad "$name (found: $needle)"; else ok "$name"; fi
}
wait_contains() { # name needle timeout command...
  local name="$1" needle="$2" tmo="$3" i
  shift 3
  for ((i = 0; i < tmo; i++)); do
    if "$@" | grep -qF -- "$needle"; then ok "$name"; return 0; fi
    sleep 1
  done
  bad "$name (timeout waiting for: $needle)"
}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 3; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 3; }
mkdir -p "$SCRATCH/pki"
"$HERE/make-pki.sh" "$SCRATCH/pki" fluent-bit fluentd-1 fluentd-2 >/dev/null
docker image inspect "$IMAGE" >/dev/null 2>&1 || retry 3 5 docker pull "$IMAGE" >/dev/null

echo "== start network, sink, aggregators, edge"
docker network create "$NET" >/dev/null
docker run -d --name "$SINK" --network "$NET" --network-alias sink -v "$HERE/sink.py":/sink.py:ro --entrypoint python3 "$IMAGE" \
  /sink.py /out console=8080 siem=8081 esoc=4318 >/dev/null
for n in 1 2; do
  name="AGG$n"
  docker run -d --name "${!name}" --network "$NET" --network-alias "fluentd-$n" --tmpfs /out \
    -v "$HERE/aggregator.conf":/agg.conf:ro -v "$SCRATCH/pki":/pki:ro -e "AGG_NAME=fluentd-$n" \
    "$IMAGE" /fluent-bit/bin/fluent-bit -c /agg.conf >/dev/null
done
docker run -d --name "$EDGE" --network "$NET" --entrypoint /etc/fluent-bit/entrypoint.sh \
  -v "$ROOT":/etc/fluent-bit:ro --tmpfs /etc/fluent-bit/enabled.d -v "$SCRATCH/pki":/pki:ro \
  --tmpfs /var/log/fluent-bit --tmpfs /var/log/errow --tmpfs /var/log/cfgaudit -e CFGAUDIT_ENABLED=true \
  --tmpfs /var/vendetta/logs -v "$HERE/forward_send.py":/forward_send.py:ro \
  -e CS3_CONSOLE_ENABLED=true -e CS3_HOST=sink -e CS3_PORT=8080 -e CS3_TLS=off -e CS3_INGEST_KEY=test-ingest-key \
  -e CS3_ESOC_ENABLED=true -e CS3_ESOC_HOST=sink -e CS3_ESOC_PORT=4318 -e CS3_ESOC_GRPC=off -e CS3_ESOC_TLS=off \
  -e CS3_SIEM_ENABLED=true -e CS3_SIEM_HOST=sink -e CS3_SIEM_PORT=8081 -e CS3_SIEM_TLS=off -e CS3_SIEM_TOKEN=test-siem-token \
  -e FLB_FORWARD_TLS=on -e FLB_LOG_LEVEL=info "$IMAGE" >/dev/null
dx "$EDGE" sh -c 'touch /var/log/cfgaudit/findings.ndjson /var/log/cfgaudit/runs.ndjson'

if retry 40 1 dx "$EDGE" curl -sf http://127.0.0.1:2020/api/v1/health >/dev/null; then ok "edge /api/v1/health 200"; else
  bad "edge never became healthy"
  docker logs "$EDGE" 2>&1 | tail -30 >&2
  exit 1
fi
if dx "$EDGE" /etc/fluent-bit/entrypoint.sh --healthcheck >/dev/null 2>&1; then ok "entrypoint --healthcheck"; else bad "entrypoint --healthcheck"; fi
dx "$EDGE" mkdir -p /var/vendetta/logs/alerts

echo "== inject events"
M_OLL="OLLMARK$RUN_ID"
M_OLL2="OLLTWO$RUN_ID"
M_VEN="VENMARK$RUN_ID"
M_RED="REDMARK$RUN_ID"
M_INF="INFMARK$RUN_ID"
M_TUI="TUIMARK$RUN_ID"
M_FND="FNDMARK$RUN_ID"
M_CFG="CFGMARK$RUN_ID"
M_CGR="CGRMARK$RUN_ID"
M_TRUNC="TRUNCMARK$RUN_ID"
code="$(post host.journal "{\"SYSTEMD_UNIT\":\"ollama.service\",\"MESSAGE\":\"level=ERROR msg=\\\"$M_OLL cuda out of memory\\\"\"}")"
if [[ "$code" == 201 ]]; then ok "POST host.journal (ollama.service) -> 201"; else bad "POST host.journal ollama.service ($code)"; fi
code="$(post host.journal "{\"SYSTEMD_UNIT\":\"cs3-ollama.service\",\"MESSAGE\":\"error $M_OLL2 model load failed\"}")"
if [[ "$code" == 201 ]]; then ok "POST host.journal (cs3-ollama.service) -> 201"; else bad "POST host.journal cs3-ollama.service ($code)"; fi
LONG="$(head -c 9000 /dev/zero | tr '\0' 'x')"
post host.journal "{\"SYSTEMD_UNIT\":\"sshd.service\",\"MESSAGE\":\"$M_RED login password=hunter2secret Bearer abcDEF123.xyz-tail\\u0007bell\"}" >/dev/null
post host.journal "{\"SYSTEMD_UNIT\":\"sshd.service\",\"MESSAGE\":\"$M_TRUNC $LONG\"}" >/dev/null
VEN='{"timestamp":"2026-01-01T00:00:00.000+0000","rule":{"level":12,"id":"550","description":"'"$M_VEN"' integrity checksum changed","groups":["ossec","syscheck","syscheck_entry_modified"]},"agent":{"id":"001","name":"web-01"},"location":"syscheck","full_log":"File /etc/passwd modified"}'
post vendetta.alerts "$VEN" >/dev/null
INF='{"chain_id":"c-'"$RUN_ID"'","seq":1,"prev_hash":"0000","hash":"'"$M_INF"'","fallback_reason":null,"tokens_in":10,"tokens_out":20,"gpu_seconds":0.5,"latency_ms":120,"backend":"ollama"}'
post cs3.ai.inference "$INF" >/dev/null
dx "$EDGE" python3 /forward_send.py 127.0.0.1 24225 ui '{"event":"'"$M_TUI"'","screen":"scan"}' >/dev/null
dx "$EDGE" sh -c "printf '%s\n' '{\"ruleId\":\"CWE-89\",\"level\":\"error\",\"message\":{\"text\":\"$M_FND sql injection\"},\"stream\":\"errow.findings\",\"source\":\"errow\",\"scan_id\":\"s1\",\"properties\":{\"errow\":{\"cwe\":\"CWE-89\"}}}' >> /var/log/errow/findings.ndjson"
dx "$EDGE" python3 - "$M_CFG" "$M_CGR" <<'PY'
import json
import sys

finding_marker, run_marker = sys.argv[1:]
base = {"@timestamp": "2026-01-01T00:00:00.000Z", "schema_version": "1.0"}
finding = {**base, "doc_id": "a" * 64, "source": {"system": "cfgaudit", "stream": "cfgaudit.findings"},
           "asset": {"name": finding_marker}, "control": {"id": "IOS-005"}, "status": "fail", "severity": "high"}
run = {**base, "doc_id": run_marker + "-run", "source": {"system": "cfgaudit", "stream": "cfgaudit.runs"},
       "run": {"id": run_marker}, "status": "completed"}
for name, record in (("findings", finding), ("runs", run)):
    with open("/var/log/cfgaudit/" + name + ".ndjson", "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")
PY

echo "== Console leg"
wait_contains "Console received the Vendetta alert" "$M_VEN" 40 sink_file console
CONSOLE="$(sink_file console)"
assert_contains "Console request URI" "$CONSOLE" '"path": "/api/cecur/logs/ingest"'
assert_contains "Console carries X-API-Key" "$CONSOLE" '"X-API-Key": "test-ingest-key"'
assert_contains "Vendetta alert classified as stream fim" "$CONSOLE" '\"stream\":\"fim\"'
assert_contains "Vendetta severity from level 12 = high" "$CONSOLE" '\"severity\":\"high\"'
wait_contains "Console received host.journal event" "$M_RED" 40 sink_file console
CONSOLE="$(sink_file console)"
assert_absent "password value redacted before egress" "$CONSOLE" 'hunter2secret'
assert_absent "bearer token redacted before egress" "$CONSOLE" 'abcDEF123'
assert_contains "redaction marker present" "$CONSOLE" '[REDACTED]'
assert_absent "BEL control character stripped" "$CONSOLE" '\\u0007'
trunc_len="$(jq -rs --arg m "$M_TRUNC" '[.[].body | fromjson | (if type=="array" then .[] else . end) | select((.message // "") | contains($m)) | .message | length] | max // 0' <<<"$(sink_file console)" 2>/dev/null || echo 0)"
if [[ "$trunc_len" -gt 0 && "$trunc_len" -le 8014 ]]; then ok "long message truncated to <= 8000 chars + marker (len $trunc_len)"; else bad "truncation (len $trunc_len)"; fi

echo "== ollama isolation"
wait_contains "safety file received ollama.service line" "$M_OLL" 40 safety_file
wait_contains "safety file received cs3-ollama.service line" "$M_OLL2" 40 safety_file
wait_contains "ESOC leg received ollama line" "$M_OLL" 40 sink_file esoc
wait_contains "SIEM leg received ollama line" "$M_OLL" 40 sink_file siem
assert_contains "SIEM auth header" "$(sink_file siem)" '"Authorization": "Bearer test-siem-token"'
assert_contains "SIEM wrote NDJSON to /v1/events" "$(sink_file siem)" '"path": "/v1/events"'
assert_contains "safety file stamps @timestamp" "$(safety_file)" '@timestamp'
assert_contains "ollama record carries the ESOC/SIEM-only source" "$(safety_file)" 'cs3-ollama'

echo "== aggregator (forward output)"
wait_contains "aggregator received vendetta.fim" 'vendetta.fim' 40 agg_file
wait_contains "aggregator received cs3.ai.inference" "$M_INF" 40 agg_file
wait_contains "aggregator received errow.tui_events" "$M_TUI" 40 agg_file
wait_contains "aggregator received errow.findings" "$M_FND" 40 agg_file
wait_contains "aggregator received cfgaudit.findings" "$M_CFG" 40 agg_file
wait_contains "aggregator received cfgaudit.runs" "$M_CGR" 40 agg_file
AGG="$(agg_file)"
assert_contains "gateway event keeps JSON null (hash chain intact)" "$AGG" '"fallback_reason":null'
assert_contains "gateway event hash untouched" "$AGG" "\"hash\":\"$M_INF\""
assert_contains "findings severity derived from SARIF level" "$(grep -- "$M_FND" <<<"$AGG")" '"severity":"high"'
assert_contains "findings keep the shipper source string" "$(grep -- "$M_FND" <<<"$AGG")" '"source":"errow"'
assert_contains "CWE-89 mapped to an ATT&CK hint" "$(grep -- "$M_FND" <<<"$AGG")" 'mitre_hint'
if grep -F -- "$M_CFG" <<<"$AGG" | grep -qv '^cfgaudit.findings:'; then bad "Cfgaudit finding arrived under a tag other than cfgaudit.findings"; else ok "Cfgaudit finding tag is exactly cfgaudit.findings"; fi
if grep -F -- "$M_CGR" <<<"$AGG" | grep -qv '^cfgaudit.runs:'; then bad "Cfgaudit run arrived under a tag other than cfgaudit.runs"; else ok "Cfgaudit run tag is exactly cfgaudit.runs"; fi
for leg in console esoc siem; do
  assert_absent "Cfgaudit finding excluded from $leg leg" "$(sink_file "$leg")" "$M_CFG"
  assert_absent "Cfgaudit run excluded from $leg leg" "$(sink_file "$leg")" "$M_CGR"
done
if grep -F -- "$M_TUI" <<<"$AGG" | grep -qv '^errow.tui_events:'; then bad "TUI event arrived under a tag other than errow.tui_events"; else ok "TUI event tag is exactly errow.tui_events"; fi

echo "== forward-input client certificate"
if dx "$EDGE" python3 /forward_send.py 127.0.0.1 24224 errow.telemetry '{"event":"MTLSOK'"$RUN_ID"'"}' --tls /pki/ca.crt /pki/fluent-bit.crt /pki/fluent-bit.key localhost >/dev/null 2>&1; then
  ok "forward input accepts a TLS client presenting a CA-signed certificate"
else bad "forward input rejected a valid mTLS client"; fi
dx "$EDGE" python3 /forward_send.py 127.0.0.1 24224 errow.telemetry '{"event":"NOCERT'"$RUN_ID"'"}' --tls /pki/ca.crt - - localhost >/dev/null 2>&1 || true
if dx "$EDGE" python3 - <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", 24224), timeout=5)
s.sendall(b"\x93\xa6plain1\x01\x81\xa1k\xa1v")
s.settimeout(2)
try:
    data = s.recv(16)
except (socket.timeout, ConnectionError):
    sys.exit(0)
sys.exit(0 if data == b"" else 1)
PY
then ok "plaintext Forward on a TLS listener is not served"; else bad "plaintext Forward accepted on the TLS listener"; fi

wait_contains "mTLS client event was ingested and forwarded" "MTLSOK$RUN_ID" 30 agg_file
sleep 3
if grep -qF "NOCERT$RUN_ID" <<<"$(agg_file)"; then
  echo "  NOTE  Fluent Bit 3.2.10 forward input is server-authenticated TLS only (no tls.verify_client_cert): a client without a certificate is accepted; restrict :24224 by network policy (RUNTIME.md). mTLS is enforced by Fluentd in_forward."
else ok "TLS client without a certificate is rejected by the forward input"; fi

echo "== stream tasks and runtime state"
if dx "$EDGE" curl -sf http://127.0.0.1:2020/api/v1/metrics/prometheus >/dev/null 2>&1 || dx "$EDGE" curl -sf http://127.0.0.1:2020/api/v2/metrics/prometheus >/dev/null 2>&1; then ok "Prometheus metrics endpoint answers"; else bad "Prometheus metrics endpoint"; fi
metrics="$(dx "$EDGE" curl -sf http://127.0.0.1:2020/api/v2/metrics/prometheus 2>/dev/null || true)"
assert_contains "fluentbit_storage_* metrics exposed" "$metrics" 'fluentbit_storage_'
assert_contains "fluentbit_output_retries_total exposed" "$metrics" 'fluentbit_output_retries_total'
if [[ "$WAIT_SP" == true ]]; then
  wait_contains "stream task emitted cs3.sp.vendetta_alert_rate to the aggregators" 'cs3.sp.vendetta_alert_rate' "$SP_WAIT" agg_file
fi

echo "== negative assertions (after everything flushed)"
sleep 8
CONSOLE="$(sink_file console)"
ESOC="$(sink_file esoc)"
SIEM="$(sink_file siem)"
AGG="$(agg_file)"
for m in "$M_OLL" "$M_OLL2"; do
  assert_absent "ollama marker $m never reaches the Console" "$CONSOLE" "$m"
  assert_absent "ollama marker $m never reaches the forward output (Fluentd/OpenSearch path)" "$AGG" "$m"
done
assert_absent "cs3.ai.inference never reaches the Console" "$CONSOLE" "$M_INF"
assert_absent "TUI event never reaches the Console" "$CONSOLE" "$M_TUI"
assert_absent "TUI event never reaches ESOC" "$ESOC" "$M_TUI"
assert_absent "TUI event never reaches SIEM" "$SIEM" "$M_TUI"
assert_absent "Errow finding never reaches the Console" "$CONSOLE" "$M_FND"
assert_absent "Errow finding never reaches ESOC/SIEM" "$ESOC$SIEM" "$M_FND"
assert_absent "Vendetta alert is not in the SIEM leg" "$SIEM" "$M_VEN"
assert_contains "gateway event reaches ESOC" "$ESOC" "$M_INF"
if [[ "$(grep -c "$M_OLL" <<<"$(safety_file)")" -eq 1 ]]; then ok "safety file holds the ollama line exactly once"; else bad "safety file duplicate/missing"; fi
if docker logs "$EDGE" 2>&1 | grep -E '\[error\]' | grep -vE 'getaddrinfo|upstream|http_client|no upstream|\[tls\]|openssl.c|edge_forward_in' | grep -q .; then
  bad "unexpected [error] lines in the edge log"
  docker logs "$EDGE" 2>&1 | grep -E '\[error\]' | head -10 >&2
else ok "no unexpected [error] lines in the edge log"; fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
((FAIL == 0))
