#!/usr/bin/with-contenv bash
# 05-cs3-manager-integration.sh — s6 cont-init stage (mounted at /etc/cont-init.d/) that wires the manager into CS3.
#
# It has to be a cont-init stage, not an entrypoint wrapper: wazuh/wazuh-manager installs /var/ossec from its permanent
# data in stage 0-wazuh-init, so a wrapper running before /init finds no ossec.conf to patch and its work would be
# overwritten by the init copy. cont-init stages run in lexical order after 0-wazuh-init and before any service starts, so
# the patched configuration is in place when wazuh-analysisd reads it.
#
# 1. Installs the CS3 decoders/rules into /var/ossec (the mount is read-only, so they are copied). The two files go to
#    different trees on purpose, see the block below.
# 2. Either splices the syslog receiver into ossec.conf (default) or swaps in a full template.
# 3. Owns the CTI / vulnerability feed settings so a deployment without egress does not log a content-updater error forever.
#
# CS3_MANAGER_CONF_TEMPLATE is the override: point it at a complete ossec.conf and the splice is skipped entirely. Use it
# when the deployment owns its own manager configuration (config management, cluster join, extra remotes) and a patch
# would be the wrong shape.
#
# CS3_MANAGER_STRICT=true turns a failed patch into a fatal error; the default only warns, because the manager still
# reports agents without the receiver.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The stage is mounted under /etc/cont-init.d while its files live in the read-only integration mount.
DIR="${CS3_MANAGER_INTEGRATION_DIR:-/manager-integration}"
[[ -d "$DIR" ]] || DIR="$HERE"
log() { printf '[manager-integration] %s\n' "$*" >&2; }

[[ -d /var/ossec/etc ]] || {
  log "ERROR: /var/ossec/etc is missing; this script must run as a cont-init stage"
  exit 1
}

# The wazuh image owns everything as wazuh:wazuh (999) and has no 'ossec' group; take whatever /var/ossec/etc already uses
# so analysisd can read what we install.
GROUP="$(stat -c '%G' /var/ossec/etc)"
install -d -o root -g "$GROUP" -m 0750 /var/ossec/etc/decoders
if [[ -n "${CS3_MANAGER_RULES_DIR:-}" || -f "$DIR/cs3-rules.xml" ]]; then
  src="${CS3_MANAGER_RULES_DIR:-$DIR}"
  # Decoders: /var/ossec/etc/decoders/0001-*, the 0001- prefix is load-bearing, not cosmetic. Decoders are tried in
  # lexical file order and the stock ruleset ships broad `sshd`/`sudo`/`audit` decoders; without the prefix ours load
  # after them, the stock decoder claims the line, and the narrow CS3 decoders (the ones that supply srcuser/dstuser/
  # srcip) never run.
  #
  # Rules: /var/ossec/ruleset/rules/9999-*, a different tree, for two reasons. analysisd resolves the stock parent IDs the
  # CS3 rules hang off (5700, 5400, 80700, 40700, 5100) at load time, so the file has to load after those parents exist;
  # /var/ossec/etc/rules/ loads before the entire stock ruleset and every parent there is "not found". And `9999-` puts
  # the block last among the ruleset files, which is what keeps a future stock file from being shadowed by a same-named
  # CS3 rule.
  for pair in "cs3-rules.xml:ruleset/rules:9999-cs3-rules.xml" "cs3-decoder.xml:etc/decoders:0001-cs3-decoder.xml"; do
    file="${pair%%:*}"
    rest="${pair#*:}"
    dest="${rest%%:*}"
    name="${rest##*:}"
    [[ -f "$src/$file" ]] || {
      log "ERROR: $src/$file not found"
      exit 1
    }
    install -d -o root -g "$GROUP" -m 0750 "/var/ossec/$dest"
    install -o root -g "$GROUP" -m 0640 "$src/$file" "/var/ossec/$dest/$name"
  done
  log "installed CS3 decoders and rules"
fi

if [[ -n "${CS3_MANAGER_CONF_TEMPLATE:-}" ]]; then
  [[ -r "$CS3_MANAGER_CONF_TEMPLATE" ]] || {
    log "ERROR: CS3_MANAGER_CONF_TEMPLATE=$CS3_MANAGER_CONF_TEMPLATE not readable"
    exit 1
  }
  if grep -q '<connection>syslog</connection>' "$CS3_MANAGER_CONF_TEMPLATE" && grep -q 'cs3:manager-integration' "$CS3_MANAGER_CONF_TEMPLATE"; then
    install -o root -g "$GROUP" -m 0640 "$CS3_MANAGER_CONF_TEMPLATE" /var/ossec/etc/ossec.conf
    log "ossec.conf replaced from full template (splice skipped)"
  else
    log "WARN: template has no CS3 syslog receiver; host logs will not pass the rule engine"
    install -o root -g "$GROUP" -m 0640 "$CS3_MANAGER_CONF_TEMPLATE" /var/ossec/etc/ossec.conf
  fi
elif ! "$DIR/patch-ossec-conf.sh"; then
  # The manager stays usable without the receiver (agents keep reporting), so a failed patch is a warning by default.
  # CS3_MANAGER_STRICT=true aborts instead, for deployments where host logs bypassing the rule engine is a defect.
  if [[ "${CS3_MANAGER_STRICT:-false}" == "true" ]]; then
    log "ERROR: ossec.conf patch failed and CS3_MANAGER_STRICT=true"
    exit 1
  fi
  log "WARN: ossec.conf patch failed; host logs will reach CS3 as plain log lines, not manager alerts"
fi

# 3. CTI / vulnerability feed settings. The stock image enables the content updater against cti.wazuh.com; without egress
#    that fails every interval and fills ossec.log with ERROR. configure-feeds.sh can disable it (off) or point it at an
#    internal mirror, and warns when it is left enabled with no mirror.
if [[ -f "$DIR/configure-feeds.sh" ]]; then
  if ! bash "$DIR/configure-feeds.sh"; then
    log "ERROR: configure-feeds.sh failed"
    [[ "${CS3_MANAGER_STRICT:-false}" == "true" ]] && exit 1
    log "WARN: continuing with the vendor feed settings"
  fi
else
  log "WARN: $DIR/configure-feeds.sh not found; the CTI feed settings are left as the image ships them"
fi
