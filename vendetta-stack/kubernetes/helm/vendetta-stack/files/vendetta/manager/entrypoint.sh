#!/bin/bash
# entrypoint.sh — manager-side CS3 integration wrapper for images started without the s6 cont-init mount (the Helm chart).
#
# The work itself is 05-cs3-manager-integration.sh, the same stage docker-compose mounts at /etc/cont-init.d. This wrapper
# only installs it and execs /init, because a pre-init wrapper is the wrong place to patch /var/ossec: 0-wazuh-init
# restores /var/ossec from the image's permanent data, so anything written before /init is overwritten. Handing the work
# to a cont-init stage puts it after that restore and before any service starts.
#
# CS3_MANAGER_CONF_TEMPLATE is the override: point it at a complete ossec.conf and the splice is skipped entirely. Use it
# when the deployment owns its own manager configuration (config management, cluster join, extra remotes) and a patch
# would be the wrong shape. CS3_MANAGER_STRICT=true turns a failed patch into a fatal error.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log() { printf '[manager-integration] %s\n' "$*" >&2; }

stage="$HERE/05-cs3-manager-integration.sh"
[[ -f "$stage" ]] || {
  log "ERROR: $stage not found; the integration mount is incomplete"
  exit 1
}
# Compose bind-mounts the stage at this path, so it is already there and read-only (it cannot be replaced); the Helm
# deployment mounts only /manager-integration, so there it has to be copied. `cmp`/`diff` are not in the manager image.
target=/etc/cont-init.d/05-cs3-manager-integration.sh
if [[ -e "$target" ]]; then
  log "cont-init stage already present at $target (bind mount); the manager configuration is applied after /init"
elif install -o root -g root -m 0755 "$stage" "$target" 2>/dev/null; then
  log "installed the cont-init stage; the manager configuration is applied after /init"
else
  log "WARN: could not install $target and none is mounted; host logs will reach CS3 as plain log lines"
fi
export CS3_MANAGER_INTEGRATION_DIR="$HERE"

exec /init "$@"
