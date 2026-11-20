# Prometheus · Alertmanager · Grafana — RUNTIME

Three stock images, no custom build. Config is mounted read-only; every container runs `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, with tmpfs where noted (all verified with those flags by the `tests/validate.sh` scripts).

| Service | Image (pinned) | User | Port | Persistent volume |
|---|---|---|---|---|
| `prometheus` | `prom/prometheus:v2.55.1@sha256:2659f4c2…b0d3` | 65534 | 9090 | `/prometheus` |
| `alertmanager` | `prom/alertmanager:v0.27.0@sha256:e13b6ed5…eacf5` | 65534 | 9093 | `/alertmanager` |
| `grafana` | `grafana/grafana:10.4.19@sha256:a9043254…a1f4` | 472 | 3000 | `/var/lib/grafana` (SQLite; dashboards are provisioned, so it may be a tmpfs `uid=472,gid=0,mode=0770`) |

## Prometheus
- Command: `--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus --storage.tsdb.retention.time=15d --web.enable-lifecycle`. Reload without restart: `POST :9090/-/reload`.
- Mounts (ro): `prometheus/` → `/etc/prometheus` (`prometheus.yml`, `alerts.yml`); `/pki` (needs `ca.crt`, `prometheus.crt`, `prometheus.key`: mTLS client cert for the `llm-gateway` and `errow-mcp` scrapes); `/run/secrets/llm_gateway_token` (bearer for the gateway).
- Scrapes: `fluent-bit:2020` (`/api/v2/metrics/prometheus`), `fluentd-1|2:24231`, `llm-gateway:9101` (https), `errow-mcp:9103` (https, `up` only: the MCP server's metric names are not part of the contract), `prometheus`, `alertmanager:9093`. OpenSearch is **not** scraped: the pinned image has no Prometheus exporter plugin; cluster health is read through the Grafana OpenSearch datasources and the `opensearch/` healthcheck.
- Healthcheck: `wget -q -O- http://localhost:9090/-/healthy` (K8s: `httpGet /-/healthy` liveness, `/-/ready` readiness).

## Alertmanager
- Command: `--config.file=/etc/alertmanager/alertmanager.yml --storage.path=/alertmanager`. Mount `prometheus/alertmanager.yml` ro at `/etc/alertmanager/alertmanager.yml`. Reload: `POST :9093/-/reload`.
- Routing by `severity`: `critical` (page, repeat 1h) → `ops-critical`, `warning` → `ops-warning` (default, repeat 4h), `info` → `ops-info` (repeat 24h). Inhibit rules mute symptom alerts while their cause is firing (all Fluentd nodes down, Fluent Bit down, gateway down; critical over high latency; spool full over spool growing; buffer full over backlog; retries exhausted over retrying).
- The receivers are **intentionally empty** (no integration that would need a secret or an external endpoint). Alerts are visible in the Alertmanager UI and the Grafana `cs3-alertmanager` datasource. To notify, deploy a copy with integrations that read credentials from files (`*_file` keys), keep the route and inhibit tree, and run `amtool check-config`.
- Healthcheck: `wget -q -O- http://localhost:9093/-/healthy`.

## Grafana
- Mounts: `grafana/provisioning` → `/etc/grafana/provisioning` (ro) · `grafana/dashboards` → `/var/lib/grafana/dashboards` (ro) · `/pki/ca.crt` (ro, OpenSearch TLS) · `/run/secrets` (ro: `grafana_admin_password`, `opensearch_admin_password`).
- Env: `GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana_admin_password`, `GF_LOG_MODE=console` (**required with a read-only rootfs**), `GF_ANALYTICS_REPORTING_ENABLED=false`, `GF_ANALYTICS_CHECK_FOR_UPDATES=false`, `GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false`, `GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false`, `GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED=true` (air-gap: no grafana.com calls), `GF_USERS_ALLOW_SIGN_UP=false`, `GF_SECURITY_DISABLE_GRAVATAR=true`. Optional: `GF_SERVER_ROOT_URL`.
- Datasources (uid): `cs3-prometheus` (default), `cs3-alertmanager`, and OpenSearch through Grafana's **built-in** `elasticsearch` type (no plugin install): `cs3-os-vendetta-alerts|errow-findings|errow-runs|errow-llm|errow-mcp|ai-inference|ai-audit`, `https://opensearch:9200`, user `admin`, password via `$__file{/run/secrets/opensearch_admin_password}`, CA `$__file{/pki/ca.crt}`.
- Dashboards (folder "Vendetta Stack", uids `cs3-pipeline-health|vendetta-overview|errow-offense|llm-slo`) are provisioned and not editable in the UI (`allowUiUpdates: false`): change the JSON in git and `POST /api/admin/provisioning/dashboards/reload`. The empty `provisioning/{plugins,notifiers,alerting}/*.yml` files only keep Grafana's log free of missing-directory errors.
- Healthcheck: `wget -q -O- http://localhost:3000/api/health | grep -q '"database": "ok"'` (K8s: `httpGet /api/health`).

## Runbooks
Every alert carries `annotations.runbook: docs/runbooks.md#<anchor>`. The 25 anchors it uses are listed in `prometheus/runbook-anchors.txt`; `docs/runbooks.md` must define each one (`prometheus/tests/validate.sh --strict-docs` fails if one is missing).

## K8s
Prometheus: StatefulSet with a PVC on `/prometheus`, ConfigMaps for the two config files, scrape targets by the same service names (or swap `static_configs` for `kubernetes_sd_configs`). Grafana: Deployment, provisioning and dashboards as ConfigMaps, admin password from a Secret file.

## Tests
`prometheus/tests/validate.sh` (promtool check config/rules, unit tests `alerts.test.yml`, amtool check-config + route tests, real boot) · `grafana/tests/validate.sh` (yamllint, jq, dashboard structure/metric/field checks in `check_dashboards.py`, promtool over every dashboard PromQL expression, real boot of the pinned Grafana).
