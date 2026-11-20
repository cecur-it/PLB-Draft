#!/usr/bin/env bash
# tests/test_manager_feeds.sh — configure-feeds.sh must own the manager's CTI/vulnerability-feed settings: disable the
# updater in `off` mode, point it at a mirror in `mirror` mode, leave the file byte-identical when it has nothing to do,
# and never touch anything outside the <vulnerability-detection> block.
#
# Pure shell against a fabricated ossec.conf (CS3_MANAGER_CONF), so it needs no manager and no containers.
set -uo pipefail

STACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FEEDS="$STACK/vendetta/manager/configure-feeds.sh"
WORK=$(mktemp -d)
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() {
  printf 'FAIL %s\n' "$1" >&2
  fail=1
}

base() {
  cat >"$WORK/ossec.conf" <<'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
  </global>
  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>
  <indexer>
    <enabled>yes</enabled>
  </indexer>
</ossec_config>
EOF
}

run() { CS3_MANAGER_CONF="$WORK/ossec.conf" bash "$FEEDS" >"$WORK/out" 2>&1; }

enabled_value() { awk -F'</?enabled>' '/<vulnerability-detection>/ { f = 1 } f && /<enabled>/ { print $2; exit }' "$WORK/ossec.conf"; }
cti_value() { awk -F'</?cti-url>' '/<cti-url>/ { print $2; exit }' "$WORK/ossec.conf"; }

[[ -f "$FEEDS" ]] || {
  bad "configure-feeds.sh missing: $FEEDS"
  exit 1
}

# 1. off disables the updater and leaves the rest of the file alone -----------------------------------------------------
base
cp "$WORK/ossec.conf" "$WORK/orig.conf"
if CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_FEED_MODE=off bash "$FEEDS" >"$WORK/out" 2>&1; then
  ok "off mode exits 0"
else
  bad "off mode failed"
  cat "$WORK/out" >&2
fi
[[ "$(enabled_value)" == "no" ]] && ok "off disables vulnerability detection" || bad "off did not disable it: $(enabled_value)"
# Everything outside the block must be untouched, and the block must keep its other keys.
grep -q '<feed-update-interval>60m</feed-update-interval>' "$WORK/ossec.conf" && ok "feed interval preserved" || bad "feed interval lost"
grep -q '<index-status>yes</index-status>' "$WORK/ossec.conf" && ok "index-status preserved" || bad "index-status lost"
diff <(sed '/<vulnerability-detection>/,/<\/vulnerability-detection>/d' "$WORK/orig.conf") \
  <(sed '/<vulnerability-detection>/,/<\/vulnerability-detection>/d' "$WORK/ossec.conf") >/dev/null &&
  ok "nothing outside the block changed" || bad "edit escaped the vulnerability-detection block"

# 2. a second run is a no-op ------------------------------------------------------------------------------------------
cp "$WORK/ossec.conf" "$WORK/after-off.conf"
CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_FEED_MODE=off bash "$FEEDS" >"$WORK/out" 2>&1
if grep -q 'already applied' "$WORK/out"; then ok "second off run reports nothing to do"; else bad "second off run re-edited the file"; fi
diff -q "$WORK/ossec.conf" "$WORK/after-off.conf" >/dev/null && ok "second off run is byte-identical" || bad "second off run drifted"

# 3. mirror keeps it enabled and sets cti-url ------------------------------------------------------------------------
base
if CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_FEED_MODE=mirror CS3_MANAGER_CTI_URL=https://cti.internal.example bash "$FEEDS" >"$WORK/out" 2>&1; then
  ok "mirror mode exits 0"
else
  bad "mirror mode failed"
  cat "$WORK/out" >&2
fi
[[ "$(enabled_value)" == "yes" ]] && ok "mirror keeps vulnerability detection enabled" || bad "mirror disabled it"
[[ "$(cti_value)" == "https://cti.internal.example" ]] && ok "mirror sets cti-url" || bad "cti-url not set: $(cti_value)"
grep -q '<cti-url>' "$WORK/ossec.conf" && (( $(grep -c '<cti-url>' "$WORK/ossec.conf") == 1 )) &&
  ok "exactly one cti-url" || bad "duplicate cti-url"

# 4. an existing cti-url is replaced, not duplicated -----------------------------------------------------------------
base
sed -i.bak 's#<feed-update-interval>60m</feed-update-interval>#<feed-update-interval>60m</feed-update-interval>\n    <cti-url>https://old.example</cti-url>#' "$WORK/ossec.conf"
rm -f "$WORK/ossec.conf.bak"
CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_FEED_MODE=mirror CS3_MANAGER_CTI_URL=https://new.example bash "$FEEDS" >"$WORK/out" 2>&1
[[ "$(cti_value)" == "https://new.example" ]] && ok "existing cti-url is replaced" || bad "cti-url not replaced: $(cti_value)"
(( $(grep -c '<cti-url>' "$WORK/ossec.conf") == 1 )) && ok "replacement does not duplicate" || bad "cti-url duplicated"

# 5. auto leaves the file untouched and explains the consequence ------------------------------------------------------
base
cp "$WORK/ossec.conf" "$WORK/orig.conf"
run
diff -q "$WORK/ossec.conf" "$WORK/orig.conf" >/dev/null && ok "auto mode does not edit the file" || bad "auto mode edited the file"
grep -q 'cti.wazuh.com' "$WORK/out" && ok "auto mode explains the default fetch" || bad "auto mode is silent"

# 6. auto with a mirror URL behaves as mirror ------------------------------------------------------------------------
base
CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_CTI_URL=https://cti.internal.example bash "$FEEDS" >"$WORK/out" 2>&1
[[ "$(cti_value)" == "https://cti.internal.example" ]] && ok "auto + CTI URL sets the mirror" || bad "auto ignored CS3_MANAGER_CTI_URL"

# 7. mirror without a URL is refused loudly --------------------------------------------------------------------------
base
cp "$WORK/ossec.conf" "$WORK/orig.conf"
CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_FEED_MODE=mirror bash "$FEEDS" >"$WORK/out" 2>&1
grep -q 'needs CS3_MANAGER_CTI_URL' "$WORK/out" && ok "mirror without URL is reported" || bad "mirror without URL is silent"
diff -q "$WORK/ossec.conf" "$WORK/orig.conf" >/dev/null && ok "mirror without URL leaves the file alone" || bad "file changed anyway"

# 8. an unknown mode is reported, not guessed ------------------------------------------------------------------------
base
CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_FEED_MODE=bogus bash "$FEEDS" >"$WORK/out" 2>&1
grep -q "not one of auto|off|mirror" "$WORK/out" && ok "unknown mode is rejected" || bad "unknown mode accepted"

# 9. a config without the block is a no-op, not a failure ------------------------------------------------------------
cat >"$WORK/ossec.conf" <<'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
</ossec_config>
EOF
cp "$WORK/ossec.conf" "$WORK/orig.conf"
if run; then ok "missing block exits 0"; else bad "missing block failed"; fi
diff -q "$WORK/ossec.conf" "$WORK/orig.conf" >/dev/null && ok "missing block leaves the file alone" || bad "file changed"

# 10. strict mode turns a refusal into a non-zero exit ---------------------------------------------------------------
base
if CS3_MANAGER_CONF="$WORK/ossec.conf" CS3_MANAGER_FEED_MODE=mirror CS3_MANAGER_STRICT=true bash "$FEEDS" >"$WORK/out" 2>&1; then
  bad "strict mode still exited 0"
else
  ok "strict mode fails closed"
fi

rm -rf "$WORK"
exit "$fail"
