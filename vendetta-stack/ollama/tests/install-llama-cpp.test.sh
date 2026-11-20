#!/usr/bin/env bash
#
# install-llama-cpp.test.sh — behavioural tests for ollama/install-llama.cpp.sh.
# Everything runs in --destdir staging mode inside a throw-away directory: no account, service,
# compiler or network side effects. A `cmake` shim stands in for the real build, a local
# http.server plays the source mirror, and a stub plays llama-server's /health and /v1/models.
#
# Traces: PROMPT §1 Tier 4 (llama.cpp CPU fallback), PROMPT §3 (integrity, air-gap),
#         CONTRACT §10 (models.json digests, sentinel refused in --release).
# Usage: ollama/tests/install-llama-cpp.test.sh [--help]
set -euo pipefail
set -o errtrace
IFS=$'\n\t'
trap 'echo "TEST HARNESS ERROR at line $LINENO" >&2' ERR

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' -e '/^#$/s/^#//'
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OLLAMA_DIR="$(cd "$HERE/.." && pwd)"
INSTALLER="$OLLAMA_DIR/install-llama.cpp.sh"
for dep in python3 tar sha256sum curl jq cc c++ make; do
  command -v "$dep" >/dev/null 2>&1 || { echo "missing dependency: $dep" >&2; exit 2; }
done

mkdir -p "${TMPDIR:-/var/tmp}"
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cs3-llama-test.XXXXXX")"
PIDS=()
cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true
  done
  rm -rf "$T"
}
trap cleanup EXIT

PASS=0
FAIL=0
OUT=""
RC=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
run_installer() { OUT="$("$@" 2>&1)" && RC=0 || RC=$?; }
expect_rc() {
  local name="$1" want="$2"; shift 2
  run_installer "$@"
  if [[ "$RC" -eq "$want" ]]; then ok "$name (rc=$RC)"; else bad "$name (wanted rc=$want, got $RC)"; printf '%s\n' "$OUT" | sed 's/^/       | /'; fi
}
out_has() { if grep -qF -- "$2" <<<"$OUT"; then ok "$1"; else bad "$1 (output lacks: $2)"; printf '%s\n' "$OUT" | sed 's/^/       | /'; fi; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_http() {
  local url="$1" _
  for _ in $(seq 1 50); do
    if curl --silent --fail --max-time 1 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  return 1
}
zeros() { printf '0%.0s' $(seq 1 64); }

# --- fixtures --------------------------------------------------------------------------------
MODEL="gemma4:26b"
mkdir -p "$T/in"
printf 'GGUF fake weights for tests\n' >"$T/in/gemma4_26b.gguf"
GGUF_SHA="$(sha256sum "$T/in/gemma4_26b.gguf" | awk '{print $1}')"
jq --arg sha "$GGUF_SHA" '(.models[] | select(.id == "gemma4:26b")).sha256 = $sha' "$OLLAMA_DIR/models.json" >"$T/models.pinned.json"
cp "$OLLAMA_DIR/models.json" "$T/models.sentinel.json"
printf 'not the weights\n' >"$T/in/corrupt.gguf"

mkdir -p "$T/srcpkg/llama.cpp-b4000"
printf 'cmake_minimum_required(VERSION 3.14)\n' >"$T/srcpkg/llama.cpp-b4000/CMakeLists.txt"
tar -czf "$T/in/llama.cpp-b4000.tar.gz" -C "$T/srcpkg" llama.cpp-b4000
SRC_SHA="$(sha256sum "$T/in/llama.cpp-b4000.tar.gz" | awk '{print $1}')"
mkdir -p "$T/mirror"
cp "$T/in/llama.cpp-b4000.tar.gz" "$T/mirror/llama.tar.gz"
{ cat "$T/in/llama.cpp-b4000.tar.gz"; echo tampered; } >"$T/mirror/tampered.tar.gz"
MIRROR_PORT="$(free_port)"
python3 -m http.server "$MIRROR_PORT" --bind 127.0.0.1 --directory "$T/mirror" >/dev/null 2>&1 &
PIDS+=("$!")
wait_http "http://127.0.0.1:$MIRROR_PORT/llama.tar.gz" || { echo "mirror did not start" >&2; exit 2; }

printf '#!/bin/sh\necho fake llama-server\n' >"$T/in/llama-server"
chmod +x "$T/in/llama-server"
BIN_SHA="$(sha256sum "$T/in/llama-server" | awk '{print $1}')"

# shims: cmake records its arguments and fabricates build/bin/llama-server; curl/ss/uname for policy tests
mkdir -p "$T/shim" "$T/shim-nocurl" "$T/shim-ss" "$T/shim-darwin"
cat >"$T/shim/cmake" <<'EOF'
#!/bin/sh
echo "$*" >>"$CMAKE_LOG"
if [ "$1" = "--build" ]; then
  mkdir -p "$2/bin"
  printf '#!/bin/sh\necho fake llama-server\n' >"$2/bin/llama-server"
  chmod +x "$2/bin/llama-server"
fi
EOF
printf '#!/bin/sh\necho called >"%s/curl-called"\nexit 1\n' "$T" >"$T/shim-nocurl/curl"
# shellcheck disable=SC2016
printf '#!/bin/sh\nprintf "%%s\\n" "${FAKE_SS_OUT:-}"\n' >"$T/shim-ss/ss"
# shellcheck disable=SC2016
printf '#!/bin/sh\nif [ "$1" = "-s" ]; then echo Darwin; else exec /usr/bin/uname "$@"; fi\n' >"$T/shim-darwin/uname"
chmod +x "$T/shim/cmake" "$T/shim-nocurl/curl" "$T/shim-ss/ss" "$T/shim-darwin/uname"
export CMAKE_LOG="$T/cmake.log"
: >"$CMAKE_LOG"
export CS3_DOWNLOAD_BACKOFF=0 CS3_HEALTH_TIMEOUT=2

llama_stub() { # llama_stub <port> <model-id>
  python3 -c '
import http.server, sys
port, model = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b"{\"status\":\"ok\"}"
        elif self.path == "/v1/models":
            body = ("{\"object\":\"list\",\"data\":[{\"id\":\"%s\",\"object\":\"model\"}]}" % model).encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
' "$1" "$2" >/dev/null 2>&1 &
  PIDS+=("$!")
  wait_http "http://127.0.0.1:$1/health"
}

new_dest() { local d="$T/dest-$1"; rm -rf "$d"; printf '%s' "$d"; }
BASE=(--models-json "$T/models.pinned.json")
CMAKE_PATH="$T/shim:$PATH"

echo "== usage and argument validation"
expect_rc "--help exits 0" 0 "$INSTALLER" --help
out_has "--help documents the verified source archive" "--source-sha256"
expect_rc "unknown flag is a usage error" 2 "$INSTALLER" --bogus
expect_rc "bad profile is a usage error" 2 "$INSTALLER" --profile cloudy
expect_rc "--parallel 0 is rejected" 2 "$INSTALLER" --parallel 0 --destdir "$T/none"
expect_rc "malformed --gguf-sha256 is rejected" 2 "$INSTALLER" --gguf-sha256 abc --destdir "$T/none"
expect_rc "non-loopback OLLAMA_BIND_ADDR is rejected" 2 env OLLAMA_BIND_ADDR=0.0.0.0:11434 "$INSTALLER" --destdir "$T/none"
expect_rc "overridden tag without a digest is a usage error" 2 env LLAMA_CPP_PINNED_TAG=b4001 "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --destdir "$T/none"

echo "== digest policy (models.json)"
expect_rc "sentinel is refused under --release" 3 "$INSTALLER" --release --models-json "$T/models.sentinel.json" --gguf "$T/in/gemma4_26b.gguf" --destdir "$T/none"
out_has "refusal names the sentinel" "<pinned-per-release>"
expect_rc "sentinel is refused in the airgap profile" 3 "$INSTALLER" --profile airgap --models-json "$T/models.sentinel.json" --gguf "$T/in/gemma4_26b.gguf" --destdir "$T/none"
expect_rc "operator digest cannot replace models.json under --release" 3 "$INSTALLER" --release --gguf-sha256 "$GGUF_SHA" --models-json "$T/models.sentinel.json" --destdir "$T/none"
expect_rc "unapproved model is refused" 3 "$INSTALLER" "${BASE[@]}" --model llama3:8b --gguf "$T/in/gemma4_26b.gguf" --destdir "$T/none"
D="$(new_dest sentinel-dev)"
expect_rc "sentinel outside release is allowed with a warning" 0 env PATH="$CMAKE_PATH" "$INSTALLER" --models-json "$T/models.sentinel.json" --gguf "$T/in/gemma4_26b.gguf" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$D"
out_has "unverified GGUF is called out" "NOT integrity-checked"
D="$(new_dest sentinel-override)"
expect_rc "operator digest enforced for an unpinned model" 3 env PATH="$CMAKE_PATH" "$INSTALLER" --models-json "$T/models.sentinel.json" --gguf "$T/in/corrupt.gguf" --gguf-sha256 "$GGUF_SHA" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$D"

echo "== dry-run changes nothing"
D="$(new_dest dry)"
expect_rc "dry-run succeeds" 0 "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --dry-run --destdir "$D"
out_has "dry-run announces its actions" "[dry-run]"
check "dry-run created no files" test ! -e "$D"

echo "== integrity failures"
D="$(new_dest bad-gguf)"
expect_rc "GGUF with the wrong digest is refused" 3 env PATH="$CMAKE_PATH" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/corrupt.gguf" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$D"
check "no GGUF installed after a mismatch" test ! -e "$D/var/lib/cs3-llama-cpp/models/gemma4_26b.gguf"
D="$(new_dest bad-src)"
expect_rc "source archive with the wrong digest is refused" 3 env PATH="$CMAKE_PATH" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$(zeros)" --destdir "$D"
check "nothing built after a source mismatch" test ! -e "$D/opt/cs3-llama-cpp/bin/llama-server"
expect_rc "missing GGUF is a failure" 1 env PATH="$CMAKE_PATH" "$INSTALLER" "${BASE[@]}" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$(new_dest no-gguf)"

echo "== build from a verified source archive"
D="$(new_dest main)"
: >"$CMAKE_LOG"
expect_rc "first install" 0 env PATH="$CMAKE_PATH" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$D"
check "llama-server installed and executable" test -x "$D/opt/cs3-llama-cpp/bin/llama-server"
check "marker records tag and source digest" grep -qx "b4000 $SRC_SHA" "$D/opt/cs3-llama-cpp/.cs3-installed"
check "build is CPU-only" grep -q -- '-DGGML_CUDA=OFF' "$CMAKE_LOG"
check "build is static" grep -q -- '-DBUILD_SHARED_LIBS=OFF' "$CMAKE_LOG"
check "build has no libcurl" grep -q -- '-DLLAMA_CURL=OFF' "$CMAKE_LOG"
check "only llama-server is built" grep -q -- '--target llama-server' "$CMAKE_LOG"
check "GGUF installed" cmp -s "$T/in/gemma4_26b.gguf" "$D/var/lib/cs3-llama-cpp/models/gemma4_26b.gguf"
check "GGUF is mode 640" test "$(stat -c '%a' "$D/var/lib/cs3-llama-cpp/models/gemma4_26b.gguf")" = "640"
check "service home is mode 750" test "$(stat -c '%a' "$D/var/lib/cs3-llama-cpp")" = "750"
check "unit is a byte-for-byte render of the packaged unit" cmp -s "$OLLAMA_DIR/cs3-llama-cpp.service" "$D/etc/systemd/system/cs3-llama-cpp.service"
ENVF="$D/etc/cs3/llama-cpp.env"
check "env carries the model alias" grep -qx 'LLAMA_MODEL_ID=gemma4:26b' "$ENVF"
check "env carries the runtime GGUF path" grep -qx 'LLAMA_MODEL_PATH=/var/lib/cs3-llama-cpp/models/gemma4_26b.gguf' "$ENVF"
check "env file is mode 640" test "$(stat -c '%a' "$ENVF")" = "640"
check "unit pins the loopback listener" grep -q -- '--host 127.0.0.1 --port 11434' "$D/etc/systemd/system/cs3-llama-cpp.service"

echo "== idempotence"
BUILDS_BEFORE="$(grep -c -- '--build' "$CMAKE_LOG")"
expect_rc "second run" 0 env PATH="$CMAKE_PATH" "$INSTALLER" "${BASE[@]}" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$D"
out_has "binary skipped when already current" "already installed"
out_has "GGUF skipped when already verified (no --gguf needed)" "already verified"
out_has "unit skipped when unchanged" "cs3-llama-cpp.service already up to date"
out_has "env skipped when unchanged" "llama-cpp.env already up to date"
check "no rebuild on re-run" test "$(grep -c -- '--build' "$CMAKE_LOG")" = "$BUILDS_BEFORE"
expect_rc "sizing flags change only the env file" 0 env PATH="$CMAKE_PATH" "$INSTALLER" "${BASE[@]}" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --threads 3 --ctx-size 8192 --parallel 1 --destdir "$D"
check "threads rendered" grep -qx 'LLAMA_THREADS=3' "$ENVF"
check "context rendered" grep -qx 'LLAMA_CTX_SIZE=8192' "$ENVF"
check "slots rendered" grep -qx 'LLAMA_PARALLEL=1' "$ENVF"
check "unit untouched by sizing flags" cmp -s "$OLLAMA_DIR/cs3-llama-cpp.service" "$D/etc/systemd/system/cs3-llama-cpp.service"
D2="$(new_dest prefix)"
expect_rc "custom prefix and bind port" 0 env PATH="$CMAKE_PATH" OLLAMA_BIND_ADDR=127.0.0.1:18434 "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --prefix /srv/llama --destdir "$D2"
check "binary under the custom prefix" test -x "$D2/srv/llama/bin/llama-server"
check "ExecStart follows the prefix" grep -q '^ExecStart=/srv/llama/bin/llama-server ' "$D2/etc/systemd/system/cs3-llama-cpp.service"
check "port follows OLLAMA_BIND_ADDR" grep -q -- '--host 127.0.0.1 --port 18434' "$D2/etc/systemd/system/cs3-llama-cpp.service"

echo "== connected download of the source archive"
D="$(new_dest dl)"
: >"$CMAKE_LOG"
expect_rc "download verified against the pinned digest" 0 env PATH="$CMAKE_PATH" LLAMA_CPP_SOURCE_URL="http://127.0.0.1:$MIRROR_PORT/llama.tar.gz" LLAMA_CPP_SOURCE_SHA256="$SRC_SHA" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --destdir "$D"
check "downloaded build installed" test -x "$D/opt/cs3-llama-cpp/bin/llama-server"
D="$(new_dest dl-bad)"
expect_rc "tampered download is refused" 3 env PATH="$CMAKE_PATH" LLAMA_CPP_SOURCE_URL="http://127.0.0.1:$MIRROR_PORT/tampered.tar.gz" LLAMA_CPP_SOURCE_SHA256="$SRC_SHA" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --destdir "$D"
check "nothing installed after a bad download" test ! -e "$D/opt/cs3-llama-cpp/bin/llama-server"
expect_rc "non-HTTPS remote source is refused" 3 env PATH="$CMAKE_PATH" LLAMA_CPP_SOURCE_URL="http://mirror.invalid/llama.tar.gz" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --destdir "$(new_dest dl-http)"
expect_rc "unreachable mirror fails after retries" 1 env PATH="$CMAKE_PATH" CS3_DOWNLOAD_RETRIES=3 LLAMA_CPP_SOURCE_URL="http://127.0.0.1:1/llama.tar.gz" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --destdir "$(new_dest dl-dead)"
out_has "backoff retry is logged" "attempt 2/3"

echo "== offline binary and air-gap"
D="$(new_dest off)"
: >"$CMAKE_LOG"
rm -f "$T/curl-called"
expect_rc "offline binary + sha256 (no build, no network)" 0 env PATH="$T/shim-nocurl:$T/shim:$PATH" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --offline-binary "$T/in/llama-server" --offline-sha256 "$BIN_SHA" --destdir "$D"
check "offline binary installed" cmp -s "$T/in/llama-server" "$D/opt/cs3-llama-cpp/bin/llama-server"
check "offline install did not build" test ! -s "$CMAKE_LOG"
check "offline install never invoked curl" test ! -e "$T/curl-called"
expect_rc "offline binary with the wrong digest is refused" 3 "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --offline-binary "$T/in/llama-server" --offline-sha256 "$(zeros)" --destdir "$(new_dest off-bad)"
expect_rc "offline binary without a digest is refused" 3 "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --offline-binary "$T/in/llama-server" --destdir "$(new_dest off-nosha)"
D="$(new_dest airgap-refuse)"
rm -f "$T/curl-called"
expect_rc "airgap without a source archive or binary is refused" 3 env PATH="$T/shim-nocurl:$PATH" "$INSTALLER" --profile airgap "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --destdir "$D"
out_has "refusal names the profile" "airgap"
check "airgap refusal never touched the network" test ! -e "$T/curl-called"
mkdir -p "$T/bundle"
cp "$T/in/gemma4_26b.gguf" "$T/bundle/gemma4_26b.gguf"
D="$(new_dest airgap-ok)"
expect_rc "airgap install from the bundle dir" 0 env PATH="$T/shim-nocurl:$T/shim:$PATH" OLLAMA_AIRGAP_BUNDLE_DIR="$T/bundle" "$INSTALLER" --profile airgap "${BASE[@]}" --offline-binary "$T/in/llama-server" --offline-sha256 "$BIN_SHA" --destdir "$D"
check "bundle GGUF installed" cmp -s "$T/in/gemma4_26b.gguf" "$D/var/lib/cs3-llama-cpp/models/gemma4_26b.gguf"
check "airgap install never invoked curl" test ! -e "$T/curl-called"
D="$(new_dest airgap-src)"
expect_rc "airgap build from a verified source archive" 0 env PATH="$T/shim-nocurl:$T/shim:$PATH" OLLAMA_AIRGAP_BUNDLE_DIR="$T/bundle" "$INSTALLER" --profile airgap "${BASE[@]}" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$D"

echo "== --status, health check and loopback verification"
D="$T/dest-main"
STUB_PORT="$(free_port)"
llama_stub "$STUB_PORT" "$MODEL" || { echo "stub did not start" >&2; exit 2; }
OTHER_PORT="$(free_port)"
llama_stub "$OTHER_PORT" "other:model" || { echo "stub did not start" >&2; exit 2; }
DEAD_PORT="$(free_port)"
expect_rc "status healthy" 0 env OLLAMA_BIND_ADDR="127.0.0.1:$STUB_PORT" "$INSTALLER" "${BASE[@]}" --status --destdir "$D"
out_has "status reports the served model" "serves gemma4:26b"
expect_rc "status fails when /v1/models lacks the model" 4 env OLLAMA_BIND_ADDR="127.0.0.1:$OTHER_PORT" "$INSTALLER" "${BASE[@]}" --status --destdir "$D"
expect_rc "status fails when nothing answers" 4 env OLLAMA_BIND_ADDR="127.0.0.1:$DEAD_PORT" "$INSTALLER" "${BASE[@]}" --status --destdir "$D"
expect_rc "status without an install fails" 4 env OLLAMA_BIND_ADDR="127.0.0.1:$STUB_PORT" "$INSTALLER" "${BASE[@]}" --status --destdir "$T/dest-none"
LB=(env "PATH=$T/shim-ss:$PATH" "OLLAMA_BIND_ADDR=127.0.0.1:$STUB_PORT")
expect_rc "loopback-only listener passes" 0 "${LB[@]}" "FAKE_SS_OUT=LISTEN 0 4096 127.0.0.1:$STUB_PORT 0.0.0.0:*" "$INSTALLER" "${BASE[@]}" --status --verify-loopback --destdir "$D"
expect_rc "0.0.0.0 listener fails" 4 "${LB[@]}" "FAKE_SS_OUT=LISTEN 0 4096 0.0.0.0:$STUB_PORT 0.0.0.0:*" "$INSTALLER" "${BASE[@]}" --status --verify-loopback --destdir "$D"
expect_rc "IPv6 wildcard listener fails" 4 "${LB[@]}" "FAKE_SS_OUT=LISTEN 0 4096 [::]:$STUB_PORT [::]:*" "$INSTALLER" "${BASE[@]}" --status --verify-loopback --destdir "$D"
expect_rc "no listener at all fails" 4 "${LB[@]}" "FAKE_SS_OUT=" "$INSTALLER" "${BASE[@]}" --status --verify-loopback --destdir "$D"

echo "== macOS prefix build (uname shim)"
D="$(new_dest darwin)"
: >"$CMAKE_LOG"
expect_rc "darwin staged install" 0 env PATH="$T/shim-darwin:$T/shim:$PATH" HOME="$T/home" "$INSTALLER" "${BASE[@]}" --gguf "$T/in/gemma4_26b.gguf" --source-archive "$T/in/llama.cpp-b4000.tar.gz" --source-sha256 "$SRC_SHA" --destdir "$D"
check "darwin build uses Metal" grep -q -- '-DGGML_METAL=ON' "$CMAKE_LOG"
check "darwin binary under the home prefix" test -x "$D$T/home/.cs3/llama.cpp/bin/llama-server"
check "darwin ships no systemd unit" test ! -e "$D/etc/systemd/system/cs3-llama-cpp.service"

echo "== uninstall keeps weights unless --purge --yes"
D="$T/dest-main"
expect_rc "uninstall dry-run" 0 "$INSTALLER" --uninstall --dry-run --destdir "$D"
check "dry-run uninstall removed nothing" test -x "$D/opt/cs3-llama-cpp/bin/llama-server"
expect_rc "uninstall" 0 "$INSTALLER" --uninstall --destdir "$D"
check "binary removed" test ! -e "$D/opt/cs3-llama-cpp/bin/llama-server"
check "unit removed" test ! -e "$D/etc/systemd/system/cs3-llama-cpp.service"
check "env file removed" test ! -e "$D/etc/cs3/llama-cpp.env"
check "GGUF preserved" test -f "$D/var/lib/cs3-llama-cpp/models/gemma4_26b.gguf"
expect_rc "--purge needs --yes" 2 "$INSTALLER" --uninstall --purge --destdir "$D"
expect_rc "purge with --yes" 0 "$INSTALLER" --uninstall --purge --yes --destdir "$D"
check "GGUF removed by purge" test ! -e "$D/var/lib/cs3-llama-cpp"

echo
echo "install-llama.cpp tests: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
