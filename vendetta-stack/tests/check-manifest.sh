#!/usr/bin/env bash
# tests/check-manifest.sh — fail if a file promised by docs/PHASE2-TOPOLOGY.md is missing, if the policy copy has
# drifted, or if a forbidden placeholder / legacy brand string slipped in. Pure shell, no network, no containers.
set -euo pipefail

STACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STACK"
fail=0
miss() { printf 'MISSING  %s\n' "$1" >&2; fail=1; }
bad() { printf 'PROBLEM  %s\n' "$1" >&2; fail=1; }

required=(
  docker-compose.yml docker-compose.gpu.yml .env.example .env.smoke .gitignore
  fluent-bit/{fluent-bit.conf,parsers.conf,plugins.conf,streams.conf,upstream.conf,stream_processors.lua,entrypoint.sh}
  fluent-bit/conf.d/{10-vendetta-agents,20-errow-findings,30-errow-runs,40-errow-llm-logs,50-errow-mcp-events,60-ai-tier}.conf
  fluent-bit/legs/{10-console,20-esoc,30-siem,50-manager}.conf
  fluent-bit/inputs/cfgaudit.conf
  cfgaudit/{pyproject.toml,pytest.ini,README.md}
  cfgaudit/cfgaudit/{__init__,__main__,engine,adapter,shadow,batfish_bridge,gui}.py
  cfgaudit/cfgaudit/schemas/{finding,run}.schema.json
  cfgaudit/tests/{test_adapter,test_shadow}.py
  cfgaudit/samples/{asa-fw1.cfg,edge-rtr1.cfg,fgt-fw1.conf,nxos-sw1.cfg,pa-fw1.set}
  fluentd/{fluent.conf,Dockerfile,entrypoint.sh,plugins/Gemfile}
  fluentd/conf.d/{00-source-forward,10-filter-vendetta-alerts,11-filter-errow-findings,12-filter-ai-inference,15-routing,20-match-opensearch,21-match-opensearch-errow,22-match-opensearch-llm-audit,23-match-opensearch-cfgaudit,30-match-prometheus,40-out-http-feedback-loop}.conf
  ollama/{models.json,install-ollama.sh,cs3-ollama.service,com.cecur-it.cs3-ollama.plist,detect-hardware.mjs,install-llama.cpp.sh,Dockerfile.ollama}
  ollama/ollama-lb/{nginx.conf,haproxy.cfg}
  llm-gateway/{Dockerfile,server.py,failover.py,meter.py,mcp_policy.yaml}
  errow/{README.md,Dockerfile.errow,entrypoint.sh}
  errow/config/{errow-config.yaml,llm-providers.yaml,scan-target.nginx.conf}
  errow/viewer/{deployment.yaml,frontend-build.sh}
  errow/tui/sidecar-deployment.yaml
  errow/mcp/{mcp-server.yaml,policy.yaml}
  errow/feedback-loop/{vendetta-to-errow.sh,errow-to-vendetta.sh,schema-validate.py}
  opensearch/opensearch.yml
  opensearch/ism-policies/{hot-warm-cold,rollover-40gb,errow-findings-retention,cfgaudit-findings-retention,cfgaudit-runs-retention,cs3-ai-audit-retention}.json
  opensearch/index-templates/{vendetta-alerts,errow-findings,errow-runs,errow-transcripts,errow-threat-models,cfgaudit-findings,cfgaudit-runs,cs3-ai-inference,cs3-ai-audit}-template.json
  opensearch/ingest-pipelines/{sarif-to-vendetta-alert,errow-finding-enrichment,aiincident-to-vendetta-alert}.json
  prometheus/{prometheus.yml,alerts.yml}
  grafana/provisioning/datasources/datasources.yml grafana/provisioning/dashboards/dashboards.yml
  kubernetes/helm/vendetta-stack/{Chart.yaml,values.yaml,values-onprem.yaml,values-airgap.yaml}
  kubernetes/kustomize/overlays/{dev,onprem,airgap}/kustomization.yaml
  scripts/{bootstrap,check-allowlists,enroll-agent,enroll-errow,enroll-ollama,rotate-certs,backup-opensearch,build-airgap-bundle,verify-bundle,healthcheck}.sh
  vendetta/ossec-hooks.conf vendetta/active-response/host-isolate.sh
  vendetta/manager/{entrypoint.sh,patch-ossec-conf.sh,configure-feeds.sh,05-cs3-manager-integration.sh,cs3-rules.xml,cs3-decoder.xml,cs3-manager.conf}
  tests/{smoke-test.sh,flatten-networks.py,validate-pipeline.py,loadgen.py}
  tests/llm/{test_prompt_injection,test_json_schema,test_failover}.py
  tests/synthetic-logs/{vendetta-alert,vendetta-fim,errow-finding.sarif,errow-run,errow-llm-request,errow-threat-model,errow-mcp-tool-call,ai-incident-analysis}.json
  docs/{PHASE1-GAP-ANALYSIS,PHASE2-TOPOLOGY,runbooks,capacity}.md README.md
)
for f in "${required[@]}"; do [[ -e $f ]] || miss "$f"; done

# Helm templates promised by the spec (names are matched loosely: any file containing the keyword).
for kw in statefulset-indexer deployment-manager daemonset-fluent-bit deployment-errow deployment-errow-viewer deployment-ollama deployment-llm-gateway servicemonitor networkpolicy poddisruptionbudget hpa; do
  compgen -G "kubernetes/helm/vendetta-stack/templates/*${kw}*" >/dev/null || miss "helm template *${kw}*"
done

# The two MCP policy copies must be byte-identical (llm-gateway/ is authoritative).
cmp -s llm-gateway/mcp_policy.yaml errow/mcp/policy.yaml || bad "llm-gateway/mcp_policy.yaml and errow/mcp/policy.yaml differ (run scripts/sync-mcp-policy.sh)"

# The Errow target allow-lists (ERROW_ALLOWED_TARGETS / errow-mcp targets / ERROW_FEEDBACK_ALLOWED_TARGETS) must agree in the shipped env files.
for envf in .env.example .env.smoke; do
  scripts/check-allowlists.sh -q --env "$envf" >/dev/null 2>&1 || bad "target allow-list drift in $envf (run scripts/check-allowlists.sh --env $envf)"
done

# models.json: 8 mandatory keys on every model entry.
if command -v jq >/dev/null 2>&1; then
  jq -e '
    ( if type == "array" then . else (.models // []) end ) as $m
    | ($m | length) >= 3 and
      all($m[]; has("id") and has("family") and has("variant") and has("activeParams") and has("minVramGb")
                and has("functionCalling") and has("multimodal") and has("sha256"))' ollama/models.json >/dev/null \
    || bad "ollama/models.json: missing one of the 8 mandatory keys"
fi

# No placeholders (test suites and raw point-in-time change-record transcripts are excluded). The single allowed
# exception is the models.json sha256 sentinel '<pinned-per-release>' (CS3 convention), which this pattern does not match.
mapfile -t hits < <(grep -rIn -E 'TODO|FIXME|CHANGEME|YOUR_API_KEY|YOUR_[A-Z_]+_KEY|<your-' \
  --exclude-dir=.scratch --exclude-dir=.git --exclude-dir=node_modules --exclude-dir='.venv*' --exclude-dir=__pycache__ \
  --exclude-dir=.pytest_cache --exclude-dir=secrets --exclude-dir=pki --exclude-dir=tests --exclude-dir=change-records . || true)
((${#hits[@]} == 0)) || { printf '%s\n' "${hits[@]}" >&2; bad "placeholder strings found"; }

# Legacy brand: Strix references were globally renamed to Errow; only the documented alias sections may mention it.
mapfile -t strix < <({ grep -rIil 'strix' --exclude-dir=.scratch --exclude-dir=.git --exclude-dir=node_modules \
  --exclude-dir='.venv*' --exclude-dir=__pycache__ --exclude-dir=.pytest_cache --exclude-dir=change-records --exclude=check-manifest.sh . || true; } \
  | grep -v -x -e ./errow/README.md -e ./docs/PHASE1-GAP-ANALYSIS.md -e ./docs/PHASE2-TOPOLOGY.md || true)
((${#strix[@]} == 0)) || { printf '%s\n' "${strix[@]}" >&2; bad "legacy 'strix' strings found"; }

if ((fail)); then echo "manifest check FAILED" >&2; exit 1; fi
echo "manifest check OK (${#required[@]} entries + helm templates + policy sync + allow-list consistency + models.json keys + placeholders)"
