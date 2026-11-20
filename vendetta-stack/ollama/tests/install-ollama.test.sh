#!/usr/bin/env bash
#
# install-ollama.test.sh — behavioural tests for ollama/install-ollama.sh.
# Everything runs in --destdir staging mode inside a throw-away directory: no account, service
# or network side effects. A local http.server plays the release mirror and a tiny stub plays
# /api/version; `ss`, `curl` and `uname` shims are injected through PATH.
#
# Traces: PROMPT §1 Tier 4 (pinned Ollama 0.40.5, loopback-only), PROMPT §3 (air-gap, integrity).
# Usage: ollama/tests/install-ollama.test.sh [--help]
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
INSTALLER="$OLLAMA_DIR/install-ollama.sh"
for dep in python3 tar sha256sum curl; do
  command -v "$dep" >/dev/null 2>&1 || { echo "missing dependency: $dep" >&2; exit 2; }
done

mkdir -p "${TMPDIR:-/var/tmp}"
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cs3-ollama-test.XXXXXX")"
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
check() { # check <name> <command...>
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
run_installer() { OUT="$("$@" 2>&1)" && RC=0 || RC=$?; }
expect_rc() { # expect_rc <name> <rc> <command...>
  local name="$1" want="$2"; shift 2
  run_installer "$@"
  if [[ "$RC" -eq "$want" ]]; then ok "$name (rc=$RC)"; else bad "$name (wanted rc=$want, got $RC)"; printf '%s\n' "$OUT" | sed 's/^/       | /'; fi
}
out_has() { # out_has <name> <fixed string>
  if grep -qF -- "$2" <<<"$OUT"; then ok "$1"; else bad "$1 (output lacks: $2)"; printf '%s\n' "$OUT" | sed 's/^/       | /'; fi
}

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_http() {
  local url="$1" _
  for _ in $(seq 1 50); do
    if curl --silent --fail --max-time 1 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  return 1
}

case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "unsupported arch" >&2; exit 2 ;; esac
case "$(uname -s)" in
  Darwin) ASSET="ollama-darwin.tgz"
          SERVICE_SUBPATH="Library/LaunchDaemons/com.cecur-it.cs3-ollama.plist"
          SERVICE_SRC="$OLLAMA_DIR/com.cecur-it.cs3-ollama.plist"
          LOG_SUBPATH="etc/newsyslog.d/cs3-ollama.conf"
          LOG_SRC="$OLLAMA_DIR/cs3-ollama.newsyslog.conf" ;;
  *)      ASSET="ollama-linux-${ARCH}.tgz"
          SERVICE_SUBPATH="etc/systemd/system/cs3-ollama.service"
          SERVICE_SRC="$OLLAMA_DIR/cs3-ollama.service"
          LOG_SUBPATH="etc/logrotate.d/cs3-ollama"
          LOG_SRC="$OLLAMA_DIR/cs3-ollama.logrotate" ;;
esac
VER="0.40.5"

file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
file_inode() { stat -c '%i' "$1" 2>/dev/null || stat -f '%i' "$1"; }
env_is() { # env_is <KEY> <value> — matches the service definition for this platform
  if [[ "$SERVICE_SUBPATH" == Library/* ]]; then
    grep -A1 -x "    <key>$1</key>" "$UNIT" | sed -n 2p | grep -qx "    <string>$2</string>"
  else
    grep -qx "Environment=$1=$2" "$UNIT"
  fi
}

# --- fixtures --------------------------------------------------------------------------------
make_fake_binary() { # make_fake_binary <path> <version>
  printf '#!/bin/sh\necho "ollama version is %s"\n' "$2" >"$1"
  chmod 0755 "$1"
}
make_payload() { # make_payload <dir> <version>
  mkdir -p "$1/bin" "$1/lib/ollama"
  make_fake_binary "$1/bin/ollama" "$2"
  echo "fake-runner" >"$1/lib/ollama/libggml-fake.so"
}

make_payload "$T/payload" "$VER"
mkdir -p "$T/mirror/good/v$VER" "$T/mirror/bad/v$VER"
tar -czf "$T/mirror/good/v$VER/$ASSET" -C "$T/payload" bin lib
GOOD_SHA="$(sha256sum "$T/mirror/good/v$VER/$ASSET" | awk '{print $1}')"
printf '%s  %s\n' "$GOOD_SHA" "$ASSET" >"$T/mirror/good/v$VER/sha256sum.txt"
cp "$T/mirror/good/v$VER/sha256sum.txt" "$T/mirror/bad/v$VER/sha256sum.txt"
{ cat "$T/mirror/good/v$VER/$ASSET"; echo tampered; } >"$T/mirror/bad/v$VER/$ASSET"

MIRROR_PORT="$(free_port)"
python3 -m http.server "$MIRROR_PORT" --bind 127.0.0.1 --directory "$T/mirror" >/dev/null 2>&1 &
PIDS+=("$!")
wait_http "http://127.0.0.1:$MIRROR_PORT/good/v$VER/sha256sum.txt" || { echo "mirror did not start" >&2; exit 2; }
GOOD_BASE="http://127.0.0.1:$MIRROR_PORT/good"
BAD_BASE="http://127.0.0.1:$MIRROR_PORT/bad"

# offline artifacts
mkdir -p "$T/offline"
make_fake_binary "$T/offline/ollama" "$VER"
make_fake_binary "$T/offline/ollama-old" "0.40.4"
cp "$T/mirror/good/v$VER/$ASSET" "$T/offline/ollama-linux.tgz"
OFFLINE_SHA="$(sha256sum "$T/offline/ollama" | awk '{print $1}')"
OLD_SHA="$(sha256sum "$T/offline/ollama-old" | awk '{print $1}')"
printf '%s  ollama\n' "$OFFLINE_SHA" >"$T/offline/ollama.sha256"

# shims
mkdir -p "$T/shim"
# shellcheck disable=SC2016
printf '#!/bin/sh\nprintf "%%s\\n" "${FAKE_SS_OUT:-}"\n' >"$T/shim/ss"
chmod +x "$T/shim/ss"
mkdir -p "$T/shim-nocurl" "$T/shim-darwin"
printf '#!/bin/sh\necho called >"%s/curl-called"\nexit 1\n' "$T" >"$T/shim-nocurl/curl"
# shellcheck disable=SC2016
printf '#!/bin/sh\nif [ "$1" = "-s" ]; then echo Darwin; else exec /usr/bin/uname "$@"; fi\n' >"$T/shim-darwin/uname"
chmod +x "$T/shim-nocurl/curl" "$T/shim-darwin/uname"

version_stub() { # version_stub <port> <version>
  python3 -c '
import http.server, sys
port, version = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("{\"version\":\"%s\"}" % version).encode()
        self.send_response(200 if self.path == "/api/version" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
' "$1" "$2" >/dev/null 2>&1 &
  PIDS+=("$!")
  wait_http "http://127.0.0.1:$1/api/version"
}

new_dest() { local d="$T/dest-$1"; rm -rf "$d"; printf '%s' "$d"; }
export CS3_DOWNLOAD_BACKOFF=0 CS3_HEALTH_TIMEOUT=2

echo "== usage and argument validation"
expect_rc "--help exits 0" 0 "$INSTALLER" --help
out_has "--help documents offline verification" "--offline-sha256"
expect_rc "unknown flag is a usage error" 2 "$INSTALLER" --bogus
expect_rc "bad profile is a usage error" 2 "$INSTALLER" --profile cloudy
expect_rc "non-numeric --num-parallel is rejected" 2 "$INSTALLER" --num-parallel x --destdir "$T/none"
expect_rc "--keep-alive injection attempt is rejected" 2 "$INSTALLER" --keep-alive '1m|x' --destdir "$T/none"
expect_rc "--purge without --uninstall is rejected" 2 "$INSTALLER" --purge --destdir "$T/none"
expect_rc "non-loopback OLLAMA_BIND_ADDR is rejected" 2 env OLLAMA_BIND_ADDR=0.0.0.0:11434 "$INSTALLER" --destdir "$T/none"
expect_rc "--offline-binary without a path is rejected" 2 "$INSTALLER" --offline-binary

echo "== dry-run changes nothing"
D="$(new_dest dry)"
expect_rc "dry-run succeeds" 0 env OLLAMA_DOWNLOAD_BASE="$GOOD_BASE" "$INSTALLER" --dry-run --destdir "$D"
out_has "dry-run announces its actions" "[dry-run]"
check "dry-run created no files" test ! -e "$D"

echo "== connected install from a mirror (sha256sum.txt verified)"
D="$(new_dest main)"
expect_rc "first install" 0 env OLLAMA_DOWNLOAD_BASE="$GOOD_BASE" "$INSTALLER" --destdir "$D"
out_has "release archive checksum verified" "SHA-256 verified"
check "binary installed and executable" test -x "$D/usr/local/bin/ollama"
check "runner libraries installed" test -f "$D/usr/local/lib/ollama/libggml-fake.so"
check "unit is a byte-for-byte render of the packaged unit" cmp -s "$SERVICE_SRC" "$D/$SERVICE_SUBPATH"
check "log rotation snippet installed" cmp -s "$LOG_SRC" "$D/$LOG_SUBPATH"
check "service home is mode 750" test "$(file_mode "$D/var/lib/cs3-ollama")" = "750"
check "models directory exists" test -d "$D/var/lib/cs3-ollama/.ollama/models"
INODE_BIN="$(file_inode "$D/usr/local/bin/ollama")"
expect_rc "second run is idempotent" 0 env OLLAMA_DOWNLOAD_BASE=http://127.0.0.1:1 "$INSTALLER" --destdir "$D"
out_has "binary skipped when already pinned" "already installed"
out_has "unit skipped when unchanged" "$(basename "$SERVICE_SUBPATH") already up to date"
out_has "log rotation skipped when unchanged" "$(basename "$LOG_SUBPATH") already up to date"
check "binary not rewritten on re-run" test "$(file_inode "$D/usr/local/bin/ollama")" = "$INODE_BIN"

echo "== tunables are rendered from the packaged unit"
expect_rc "install with tunables" 0 "$INSTALLER" --destdir "$D" --num-parallel 8 --keep-alive 1h --max-loaded-models 1
UNIT="$D/$SERVICE_SUBPATH"
check "OLLAMA_NUM_PARALLEL rendered" env_is OLLAMA_NUM_PARALLEL 8
check "OLLAMA_KEEP_ALIVE rendered" env_is OLLAMA_KEEP_ALIVE 1h
check "OLLAMA_MAX_LOADED_MODELS rendered" env_is OLLAMA_MAX_LOADED_MODELS 1
check "only the three tunable lines differ from the packaged unit" test "$({ diff "$SERVICE_SRC" "$UNIT" || true; } | grep -c '^<')" = "3"
expect_rc "same tunables again" 0 "$INSTALLER" --destdir "$D" --num-parallel 8 --keep-alive 1h --max-loaded-models 1
out_has "unchanged render is not rewritten" "$(basename "$SERVICE_SUBPATH") already up to date"
expect_rc "dropping the tunables reverts to the packaged unit" 0 "$INSTALLER" --destdir "$D"
check "unit is the packaged unit again" cmp -s "$SERVICE_SRC" "$UNIT"
expect_rc "bind override stays on loopback" 0 env OLLAMA_BIND_ADDR=127.0.0.1:18434 "$INSTALLER" --destdir "$D"
check "OLLAMA_HOST rendered from OLLAMA_BIND_ADDR" env_is OLLAMA_HOST 127.0.0.1:18434
expect_rc "restore default bind" 0 "$INSTALLER" --destdir "$D"

echo "== integrity and network policy"
D="$(new_dest tamper)"
expect_rc "tampered archive is refused" 3 env OLLAMA_DOWNLOAD_BASE="$BAD_BASE" "$INSTALLER" --destdir "$D"
out_has "mismatch is reported" "SHA-256 mismatch"
check "nothing installed after a checksum failure" test ! -e "$D/usr/local/bin/ollama"
D="$(new_dest http)"
expect_rc "non-HTTPS remote mirror is refused" 3 env OLLAMA_DOWNLOAD_BASE=http://mirror.invalid/ollama "$INSTALLER" --destdir "$D"
D="$(new_dest retry)"
expect_rc "unreachable mirror fails after retries" 1 env OLLAMA_DOWNLOAD_BASE=http://127.0.0.1:1 CS3_DOWNLOAD_RETRIES=3 "$INSTALLER" --destdir "$D"
out_has "backoff retry is logged" "attempt 2/3"
out_has "failure names the attempt budget" "after 3 attempts"

echo "== offline / air-gap installs"
D="$(new_dest off-ok)"
rm -f "$T/curl-called"
expect_rc "offline binary + sha256" 0 env PATH="$T/shim-nocurl:$PATH" "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama" --offline-sha256 "$OFFLINE_SHA"
check "offline install never invoked curl" test ! -e "$T/curl-called"
check "offline binary installed" test -x "$D/usr/local/bin/ollama"
D="$(new_dest off-file)"
expect_rc "offline sha256 from a sha256sum file" 0 "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama" --offline-sha256 "$T/offline/ollama.sha256"
D="$(new_dest off-tgz)"
OFF_TGZ_SHA="$(sha256sum "$T/offline/ollama-linux.tgz" | awk '{print $1}')"
expect_rc "offline release archive" 0 "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama-linux.tgz" --offline-sha256 "$OFF_TGZ_SHA"
check "archive runner libraries installed" test -f "$D/usr/local/lib/ollama/libggml-fake.so"
D="$(new_dest off-bad)"
expect_rc "wrong offline sha256 is refused" 3 "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama" --offline-sha256 "$(printf '0%.0s' $(seq 1 64))"
check "nothing installed after offline mismatch" test ! -e "$D/usr/local/bin/ollama"
expect_rc "offline binary without sha256 is refused" 3 "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama"
expect_rc "malformed offline sha256 is a usage error" 2 "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama" --offline-sha256 abc123
expect_rc "offline binary with the wrong version is refused" 3 "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama-old" --offline-sha256 "$OLD_SHA"
D="$(new_dest airgap)"
rm -f "$T/curl-called"
expect_rc "airgap without an offline binary is refused" 3 env PATH="$T/shim-nocurl:$PATH" "$INSTALLER" --profile airgap --destdir "$D"
out_has "refusal names the profile" "airgap"
check "airgap refusal never touched the network" test ! -e "$T/curl-called"
expect_rc "airgap with a verified offline binary" 0 env PATH="$T/shim-nocurl:$PATH" "$INSTALLER" --profile airgap --destdir "$D" --offline-binary "$T/offline/ollama" --offline-sha256 "$OFFLINE_SHA"
check "airgap install never invoked curl" test ! -e "$T/curl-called"
expect_rc "airgap re-run with a stale pin is still network-free" 0 env PATH="$T/shim-nocurl:$PATH" "$INSTALLER" --profile airgap --destdir "$D" --offline-binary "$T/offline/ollama" --offline-sha256 "$OFFLINE_SHA"

echo "== --status, health check and loopback verification"
D="$T/dest-main"
STUB_PORT="$(free_port)"
version_stub "$STUB_PORT" "$VER" || { echo "stub did not start" >&2; exit 2; }
BAD_STUB_PORT="$(free_port)"
version_stub "$BAD_STUB_PORT" "0.40.4" || { echo "stub did not start" >&2; exit 2; }
DEAD_PORT="$(free_port)"
expect_rc "status healthy" 0 env OLLAMA_BIND_ADDR="127.0.0.1:$STUB_PORT" "$INSTALLER" --status --destdir "$D"
out_has "status reports the pinned version" "matches pin"
out_has "status reports a healthy endpoint" "Health check passed"
expect_rc "status fails on a wrong server version" 4 env OLLAMA_BIND_ADDR="127.0.0.1:$BAD_STUB_PORT" "$INSTALLER" --status --destdir "$D"
expect_rc "status fails when nothing answers" 4 env OLLAMA_BIND_ADDR="127.0.0.1:$DEAD_PORT" "$INSTALLER" --status --destdir "$D"
cp "$UNIT" "$T/unit.bak"
printf '# local edit\n' >>"$UNIT"
expect_rc "status flags unit drift" 0 env OLLAMA_BIND_ADDR="127.0.0.1:$STUB_PORT" "$INSTALLER" --status --destdir "$D"
out_has "drift is reported" "differs from the packaged"
cp "$T/unit.bak" "$UNIT"
expect_rc "status without a binary fails" 4 env OLLAMA_BIND_ADDR="127.0.0.1:$STUB_PORT" "$INSTALLER" --status --destdir "$T/dest-none"

LB_ENV=(env "PATH=$T/shim:$PATH" "OLLAMA_BIND_ADDR=127.0.0.1:$STUB_PORT")
expect_rc "loopback-only listener passes" 0 "${LB_ENV[@]}" "FAKE_SS_OUT=LISTEN 0 4096 127.0.0.1:$STUB_PORT 0.0.0.0:*" "$INSTALLER" --status --verify-loopback --destdir "$D"
out_has "loopback pass is logged" "is loopback-only"
expect_rc "IPv6 loopback listener passes" 0 "${LB_ENV[@]}" "FAKE_SS_OUT=LISTEN 0 4096 [::1]:$STUB_PORT [::]:*" "$INSTALLER" --status --verify-loopback --destdir "$D"
expect_rc "0.0.0.0 listener fails" 4 "${LB_ENV[@]}" "FAKE_SS_OUT=LISTEN 0 4096 0.0.0.0:$STUB_PORT 0.0.0.0:*" "$INSTALLER" --status --verify-loopback --destdir "$D"
expect_rc "wildcard listener fails" 4 "${LB_ENV[@]}" "FAKE_SS_OUT=LISTEN 0 4096 *:$STUB_PORT *:*" "$INSTALLER" --status --verify-loopback --destdir "$D"
expect_rc "IPv6 wildcard listener fails" 4 "${LB_ENV[@]}" "FAKE_SS_OUT=LISTEN 0 4096 [::]:$STUB_PORT [::]:*" "$INSTALLER" --status --verify-loopback --destdir "$D"
expect_rc "loopback plus wildcard fails" 4 "${LB_ENV[@]}" "FAKE_SS_OUT=LISTEN 0 4096 127.0.0.1:$STUB_PORT 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:$STUB_PORT 0.0.0.0:*" "$INSTALLER" --status --verify-loopback --destdir "$D"
expect_rc "no listener at all fails" 4 "${LB_ENV[@]}" "FAKE_SS_OUT=" "$INSTALLER" --status --verify-loopback --destdir "$D"
expect_rc "unrelated wildcard listener on another port is ignored" 0 "${LB_ENV[@]}" "FAKE_SS_OUT=LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 4096 127.0.0.1:$STUB_PORT 0.0.0.0:*" "$INSTALLER" --status --verify-loopback --destdir "$D"

echo "== macOS launchd rendering (uname shim)"
D="$(new_dest darwin)"
expect_rc "darwin staged install" 0 env PATH="$T/shim-darwin:$PATH" "$INSTALLER" --destdir "$D" --offline-binary "$T/offline/ollama" --offline-sha256 "$OFFLINE_SHA" --num-parallel 6
PLIST="$D/Library/LaunchDaemons/com.cecur-it.cs3-ollama.plist"
check "plist installed" test -f "$PLIST"
check "plist parses and carries the tunable" python3 -c '
import plistlib, sys
d = plistlib.load(open(sys.argv[1], "rb"))
env = d["EnvironmentVariables"]
assert env["OLLAMA_NUM_PARALLEL"] == "6", env
assert env["OLLAMA_HOST"] == "127.0.0.1:11434", env
assert d["UserName"] == "_cs3-ollama", d
' "$PLIST"
check "newsyslog snippet installed" cmp -s "$OLLAMA_DIR/cs3-ollama.newsyslog.conf" "$D/etc/newsyslog.d/cs3-ollama.conf"

echo "== uninstall keeps weights unless --purge --yes"
D="$(new_dest main)"
expect_rc "reinstall for uninstall tests" 0 env OLLAMA_DOWNLOAD_BASE="$GOOD_BASE" "$INSTALLER" --destdir "$D"
echo weights >"$D/var/lib/cs3-ollama/.ollama/models/keep.blob"
expect_rc "uninstall dry-run" 0 "$INSTALLER" --uninstall --dry-run --destdir "$D"
check "dry-run uninstall removed nothing" test -x "$D/usr/local/bin/ollama"
expect_rc "uninstall" 0 "$INSTALLER" --uninstall --destdir "$D"
check "binary removed" test ! -e "$D/usr/local/bin/ollama"
check "runner libraries removed" test ! -e "$D/usr/local/lib/ollama"
check "unit removed" test ! -e "$D/etc/systemd/system/cs3-ollama.service"
check "logrotate snippet removed" test ! -e "$D/etc/logrotate.d/cs3-ollama"
check "model weights preserved" test -f "$D/var/lib/cs3-ollama/.ollama/models/keep.blob"
expect_rc "uninstall is repeatable" 0 "$INSTALLER" --uninstall --destdir "$D"
expect_rc "--purge needs --yes" 2 "$INSTALLER" --uninstall --purge --destdir "$D"
check "weights still present after refused purge" test -f "$D/var/lib/cs3-ollama/.ollama/models/keep.blob"
expect_rc "purge with --yes" 0 "$INSTALLER" --uninstall --purge --yes --destdir "$D"
check "weights removed by purge" test ! -e "$D/var/lib/cs3-ollama"

echo
echo "install-ollama tests: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
