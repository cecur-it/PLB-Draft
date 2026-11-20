#!/usr/bin/env bash
# tests/test_manager_patch.sh — the manager ossec.conf patch must be idempotent, must refuse to reuse a rule ID that is
# already taken, and must leave ossec.conf untouched when it refuses.
#
# Runs inside a throwaway container against a fabricated /var/ossec tree (no manager needed):
#   docker run --rm -v "$PWD:/w" -w /w debian:bookworm-slim \
#     bash -c 'apt-get update -qq && apt-get install -y -qq python3 >/dev/null && bash tests/test_manager_patch.sh'
set -uo pipefail

STACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCHER="$STACK/vendetta/manager/patch-ossec-conf.sh"
CONF=/var/ossec/etc/ossec.conf
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() {
  printf 'FAIL %s\n' "$1" >&2
  fail=1
}

[[ -f "$PATCHER" ]] || {
  bad "patcher missing: $PATCHER"
  exit 1
}

reset() {
  rm -rf /var/ossec
  mkdir -p /var/ossec/etc/rules
  cat >"$CONF" <<'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
</ossec_config>
EOF
}

run() { bash "$PATCHER" >/tmp/patch.out 2>&1; }

# 1. first run splices, second run is a no-op ---------------------------------------------------------------
reset
before=$(wc -l <"$CONF")
if run; then ok "first run exits 0"; else
  bad "first run failed"
  cat /tmp/patch.out >&2
fi
grep -q '<connection>syslog</connection>' "$CONF" && ok "receiver spliced" || bad "receiver not spliced"
grep -q 'cs3:manager-integration' "$CONF" && ok "marker written" || bad "marker missing"
grep -q '<jsonout_output>yes</jsonout_output>' "$CONF" && ok "existing configuration kept" || bad "existing configuration lost"

spliced=$(wc -l <"$CONF")
run && ok "second run exits 0" || bad "second run failed"
[[ "$(wc -l <"$CONF")" == "$spliced" ]] && ok "second run is a no-op" || bad "second run changed the file"
[[ "$(grep -c '<connection>syslog</connection>' "$CONF")" == 1 ]] && ok "exactly one receiver" || bad "duplicate receiver"
((spliced > before)) && ok "splice actually added lines" || bad "splice added nothing"

# 2. an already-spliced config survives a rewrite of the block ----------------------------------------------
reset
run
cp "$CONF" /tmp/expected.conf
run
diff -q "$CONF" /tmp/expected.conf >/dev/null && ok "repeat run is byte-identical" || bad "repeat run drifted"

# 2b. the installer's own copy in ruleset/rules is not a collision -------------------------------------------
# 05-cs3-manager-integration.sh installs the block as ruleset/rules/9999-cs3-rules.xml *before* the patch runs, so the
# scan sees a file that carries every CS3 ID and must not report the block as colliding with itself.
reset
mkdir -p /var/ossec/ruleset/rules
cp "$STACK/vendetta/manager/cs3-rules.xml" /var/ossec/ruleset/rules/9999-cs3-rules.xml
if run; then ok "own installed copy is not a collision"; else
  bad "own installed copy treated as a collision"
  head -3 /tmp/patch.out >&2
fi
grep -q '<connection>syslog</connection>' "$CONF" && ok "receiver spliced next to the installed rules" || bad "receiver not spliced"
rm -rf /var/ossec/ruleset

# 3. a colliding test rule ID is refused, and the file is left alone -----------------------------------------
reset
cat >/var/ossec/etc/rules/local_rules.xml <<'EOF'
<group name="local,">
  <rule id="10130" level="3">
    <description>squatter</description>
  </rule>
</group>
EOF
if run; then bad "collision not detected"; else ok "collision detected"; fi
grep -q 'already defined' /tmp/patch.out && ok "collision names the file" || bad "collision message unhelpful"
grep -q '<connection>syslog</connection>' "$CONF" && bad "file modified despite collision" || ok "file untouched on collision"

# 4. a rule outside the reserved block is refused ------------------------------------------------------------
reset
work=$(mktemp -d)
cp "$STACK/vendetta/manager/"*.xml "$STACK/vendetta/manager/cs3-manager.conf" "$work/"
cp "$PATCHER" "$work/"
sed -i 's/rule id="10135"/rule id="120035"/' "$work/cs3-rules.xml"
if bash "$work/patch-ossec-conf.sh" >/tmp/patch.out 2>&1; then bad "out-of-block ID accepted"; else ok "out-of-block ID refused"; fi
grep -q 'outside the reserved CS3 block' /tmp/patch.out && ok "range message correct" || bad "range message missing"
rm -rf "$work"

# 5. the rules file really only uses the reserved block -------------------------------------------------------
out=$(grep -o 'rule id="[0-9]*"' "$STACK/vendetta/manager/cs3-rules.xml" | grep -o '[0-9]*')
stray=0
for id in $out; do
  if ((id < 10120 || id > 10199)); then
    bad "cs3-rules.xml uses out-of-block ID $id"
    stray=1
  fi
done
((stray == 0)) && ok "cs3-rules.xml stays inside 10120-10199 ($(wc -w <<<"$out") rules)"

# 6. the shipped block is well-formed XML ---------------------------------------------------------------------
# Wazuh decoder files are bare fragments (top-level <decoder> elements, no wrapper), so parse them inside a root.
if command -v python3 >/dev/null; then
  for f in cs3-rules.xml cs3-decoder.xml; do
    python3 -c 'import sys, xml.etree.ElementTree as ET
ET.fromstring("<root>" + open(sys.argv[1]).read() + "</root>")' "$STACK/vendetta/manager/$f" &&
      ok "$f is well-formed" || bad "$f is not well-formed XML"
  done
fi

exit "$fail"
