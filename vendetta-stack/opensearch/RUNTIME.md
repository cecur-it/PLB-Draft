# opensearch — RUNTIME (CONTRACT §11) — OpenSearch 2.17.1 + Dashboards + `opensearch-init`
Traces: CONTRACT §1 (images), §2 (ports/secrets/PKI), §3 (indices/ISM), §4 (schemas). No build: three services use the pinned images, with this dir mounted `:ro` at `/opensearch`.

## Services
| Service | Image | Command / entrypoint | Ports |
|---|---|---|---|
| `opensearch` | `${OPENSEARCH_IMAGE}` = `opensearchproject/opensearch:2.17.1@sha256:1193b7c2…bcc4c` | `entrypoint: ["/opensearch/entrypoint.sh"]`, no command | 9200 https (basic auth), 9300 transport |
| `opensearch-dashboards` | `${DASHBOARDS_IMAGE}` (§1 pin) | `entrypoint: ["/opensearch/dashboards/entrypoint.sh"]` (puts the password in the keystore, then execs the stock entrypoint) | 5601 http |
| `opensearch-init` (one-shot, `restart: "no"`) | `${OPENSEARCH_IMAGE}` (has bash+curl+python3; no jq) | `entrypoint: ["/opensearch/apply.sh"]`, `depends_on: opensearch` (healthy) | none |

`entrypoint.sh` renders `internal_users.yml` (bcrypt of the secret) and copies `security/*.yml`. The security index is initialised only on the FIRST start of a data volume: rotate the password by recreating the volume (the admin user is `reserved`; no admin-DN cert is issued by bootstrap).

## Env
| Name | Default | Meaning |
|---|---|---|
| `OPENSEARCH_JAVA_OPTS` | image default | prod: `-Xms<N>g -Xmx<N>g`, N = 50% of RAM, ≤ 31g, both equal. Dev on the 7 GB host: `-Xms1g -Xmx1g` (CI/tests: 512m) |
| `NODE_NAME` | `$HOSTNAME` | required in 3-node mode (K8s: `metadata.name` = `opensearch-0..2`) |
| `NODE_BOX_TYPE` | `hot` | `node.attr.box_type` = `hot\|warm\|cold` (allocation awareness; NOT `tier`). Warm/cold ISM states need ≥1 node of each type, else shards stay on hot |
| `OPENSEARCH_SEED_HOSTS`, `OPENSEARCH_INITIAL_MANAGERS` | `opensearch-{0,1,2}[.opensearch]` | 3-node discovery (`opensearch.yml`); single-node uses `opensearch.single-node.yml` |
| `OPENSEARCH_CLUSTER_NAME` | `vendetta-stack` | |
| `OPENSEARCH_MEMORY_LOCK` | `true` | single-node file only; `false` + `node.store.allow_mmap=false` when memlock/`vm.max_map_count` cannot be set (dev only) |
| `OPENSEARCH_PASSWORD_FILE` | `/run/secrets/opensearch_admin_password` | ≥ 12 chars; read by all three services |
| init: `OPENSEARCH_URL` `OPENSEARCH_USER` `OPENSEARCH_CA` | `https://opensearch:9200` `admin` `/pki/ca.crt` | `OPENSEARCH_EXPECTED_NODES=3`, `OPENSEARCH_WAIT_TIMEOUT=300`, `OPENSEARCH_APPLY_REPLICAS=auto\|keep\|N` |
| Dashboards: `OPENSEARCH_PASSWORD_FILE`, `OSD_HOME` | see above, `/usr/share/opensearch-dashboards` | host/CA/user are in `dashboards/opensearch_dashboards.yml` |

## Secrets / PKI / volumes
- Secret `opensearch_admin_password` at `/run/secrets/opensearch_admin_password` (ro) in all three; it must be readable by uid 1000 (OpenSearch) / the Dashboards user.
- PKI `$STACK/pki` → `/usr/share/opensearch/config/certs:ro` on `opensearch` (needs `opensearch.crt`, `opensearch.key`, `ca.crt`; the key MUST be unencrypted PKCS#8 `BEGIN PRIVATE KEY` and readable by uid 1000 — `openssl pkcs8 -topk8 -nocrypt`); `ca.crt` also at `/pki/ca.crt:ro` on init and Dashboards.
- `/opensearch:ro` ← `$STACK/opensearch` (all three; the init job needs `index-templates/`, `ism-policies/`, `ingest-pipelines/`, `cluster-settings.json`, `apply-helper.py`).
- `opensearch-data` → `/usr/share/opensearch/data` (rw, uid 1000). `opensearch-snapshots` → `/usr/share/opensearch/snapshots` (rw, shared by every node; `path.repo`, repository `vendetta-snapshots` is created by apply.sh). The image has no S3/GCS repository plugin: for cloud snapshots mount NFS/EFS here.
- Single node: mount `opensearch.single-node.yml` at `/usr/share/opensearch/config/opensearch.yml:ro`; 3 nodes: `opensearch.yml`. Dashboards: `dashboards/opensearch_dashboards.yml` → `/usr/share/opensearch-dashboards/config/opensearch_dashboards.yml:ro`.

## Host / container limits
`sysctl vm.max_map_count=262144` on the host (K8s: privileged initContainer or node tuning); `ulimits: memlock -1/-1, nofile 65536/65536`; `cap_add: [IPC_LOCK]` is not needed with the memlock ulimit. `read_only: true` rootfs is NOT supported (keystore, plugins state); keep `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`; run as the image user (uid 1000). Dashboards writes its keystore to `config/`.

## Healthchecks (container-internal; both images ship curl)
- opensearch: `curl -fsS --cacert /usr/share/opensearch/config/certs/ca.crt -u "admin:$(cat /run/secrets/opensearch_admin_password)" 'https://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=5s'` (interval 15s, start_period 120s, retries 10). Health is yellow on single nodes with replicas>0; `apply.sh` uses 0 replicas for one data node.
- dashboards: `curl -fsS -u "admin:$(cat /run/secrets/opensearch_admin_password)" http://localhost:5601/api/status` (start_period 90s).
- `opensearch-init` exit codes: 0 ok, 1 failed, 2 usage, 3 cluster not ready, 4 auth/TLS/credential. Re-running is idempotent (content hashes); `--force`, `--dry-run`, `--replicas` are available.
- Dashboards objects: after Dashboards is healthy run `/opensearch/dashboards/import.sh --url http://opensearch-dashboards:5601` (same image/mounts as init; exit 0 = imported + verified; idempotent via stable ids, `overwrite=true`). Regenerate the NDJSON with `dashboards/build_saved_objects.py`.

## Kubernetes
- `StatefulSet opensearch` (3 replicas, headless Service `opensearch`, Service `opensearch` for 9200), `podManagementPolicy: Parallel`, `fsGroup: 1000`, PVC per pod, PDB `maxUnavailable: 1`; separate pools with `NODE_BOX_TYPE=warm|cold` for tiering. Pod DNS names must match `OPENSEARCH_SEED_HOSTS`.
- Probes: `exec` curl as above (readiness `_cluster/health?local=true`); `tcpSocket 9200` for liveness (httpGet cannot authenticate: it would see 401). Startup probe `failureThreshold: 30`, `periodSeconds: 10`.
- `opensearch-init` = Job with Helm hook `post-install,post-upgrade` (`hook-delete-policy: before-hook-creation`), `restartPolicy: OnFailure`, `backoffLimit: 6`, `OPENSEARCH_EXPECTED_NODES=3`. ConfigMaps are flat: use one ConfigMap per sub-directory (`index-templates`, `ism-policies`, `ingest-pipelines`, `security`, plus root files) mounted at the same relative paths under `/opensearch`, or bake `COPY opensearch/ /opensearch` into a tiny image `FROM` the pinned one. cert-manager: put `tls.crt/tls.key/ca.crt` at the cert paths above (`tls.key` must be PKCS#8: `privateKey.encoding: PKCS8`).

## Behaviour the other components must know
- Writers: `vendetta-alerts` via the write alias, `_bulk` `update` + `doc_as_upsert`, `_id` = alert `id`. **OpenSearch 2.17 ignores `?pipeline=` / per-action `pipeline` on update+`doc_as_upsert`** (verified in `BulkRequestParser`; only the index default pipeline runs), so `vendetta-alerts-*` has `index.default_pipeline=vendetta-alerts-router`: a raw SARIF result (`ruleId`) → `sarif-to-vendetta-alert`, an AIIncidentAnalysis / `cs3.ai.inference` record (`severityAssessment`) → `aiincident-to-vendetta-alert`, native alerts and partial updates pass through. Writers just send the record. `?pipeline=` still works on `index`/`create` ops (and overrides the router). `errow-findings-*` writers (index op) pass `?pipeline=errow-finding-enrichment`. Failures keep the doc and set `ingest_error`. AI enrichment of an existing alert = update + `doc_as_upsert` with `_id` = `alert_id` (the pipeline emits only the AI fields, so the original alert is not clobbered).
- `cs3-ai-audit-*` is append-only: ISM write-blocks an index 1 day after creation (late events for older daily indices are rejected); 7-year retention with a `vendetta-snapshots` snapshot before delete.
- `cfgaudit-findings-*` and `cfgaudit-runs-*` use dedicated schemas, deterministic `doc_id` values, no ingest pipeline, and independent ISM: findings transition hot→warm at 90d, warm→cold at 365d, and delete at 2555d; runs transition at 30d/90d and delete at 365d. Cold states require a successful `vendetta-snapshots` snapshot. They never enter `errow-findings-*` or `vendetta-alerts-*`.
- At full retention, daily indices for `errow-findings`, `errow-sarif`, `cs3-ai-audit`, `cfgaudit-findings` (7 years each) and `cfgaudit-runs` (1 year) are ≈ 10.6k indices, ≈ 21k shards with 1 primary + 1 replica. `cluster-settings.json` sets `cluster.max_shards_per_node: 3000` (9k on 3 nodes): size ≥ 8 nodes, raise the limit, or merge old indices (shrink/reindex to monthly) before year 3. Cfgaudit indices are created only on days with records.
- Template priorities: specific `errow-*` templates beat `errow-generic`; `action.auto_create_index` allows only `vendetta-alerts-*`, `errow-*`, `cfgaudit-*`, `cs3-ai-*`, `security-auditlog-*`, `.*`.
