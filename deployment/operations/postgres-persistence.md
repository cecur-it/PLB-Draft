# PostgreSQL persistence SOP

CS3 can replace the demo Firestore path with PostgreSQL + JSONB by setting `CS3_PERSISTENCE=postgres` and a valid `DATABASE_URL`. The pool implementation is in `demo/demo-100226/server/pg/pool.ts`; table ownership and RLS come from `deployment/docker/postgres/init/*.sql`.

## Enablement

```bash
cat >> deployment/docker/.env <<'EOF'
CS3_PERSISTENCE=postgres
DATABASE_URL=postgres://cs3_app:${CS3_APP_PASSWORD}@postgres:5432/cs3
CS3_PG_POOL_MAX=20
EOF

docker compose up -d postgres console
curl -fsS http://localhost:3000/api/health | python3 -m json.tool
```

`CS3_PG_POOL_MAX` defaults to `20` per console replica. Keep `console_replicas * CS3_PG_POOL_MAX` below PostgreSQL `max_connections` with headroom for migrations, LISTEN, exporters, and superuser sessions.

## Firestore to PostgreSQL mapping

| Firestore collection | PostgreSQL table | Storage model | Notes |
|---|---|---|---|
| `users` | `cs3.users` | `id text`, `data jsonb` | unique index on `lower(data->>'username')` |
| `credentials` | `cs3.credentials` | `id text`, `data jsonb` | RBAC / demo profile metadata |
| `incidents` | `cs3.incidents` | `id text`, `data jsonb` | expression index on `data->>'status'` |
| `auditLogs` | `cs3.audit_logs` | append-only ledger | hash chain, RLS, mutation triggers |
| `sensors` | `cs3.sensors` | `id text`, `data jsonb` | `updated_at` index for dashboard reads |
| `transactions` | `cs3.transactions` | `id text`, `data jsonb` | trigger blocks changes once `status=COMPLETED` |
| `errowAllowlist` | `cs3.errow_allowlist` | `id text`, `data jsonb` | GIN on JSONB |
| `errowJobs` | `cs3.errow_jobs` | `id text`, `data jsonb` | GIN on JSONB |
| `wazuhAlerts` | `cs3.wazuh_alerts` | `id text`, `data jsonb` | index on `(data->>'ruleLevel')::int` |
| `activtrakSessions` | `cs3.activtrak_sessions` | `id text`, `data jsonb` | GIN on JSONB |

CS3-native fleet objects are additional tables, not Firestore imports:

- `cs3.agents` stores enrolled endpoint records.
- `cs3.enrollments` stores one-time enrollment token hashes and per-agent ingest key hashes.

## Role model

`deployment/docker/postgres/init/001_roles.sh` creates three least-privilege roles:

| Role | Capabilities | Must not be used for |
|---|---|---|
| `cs3_migrator` | schema owner, DDL, trigger/function changes | app runtime, dashboards |
| `cs3_app` | DML only, `NOBYPASSRLS` | migrations, maintenance, archival |
| `cs3_archiver` | read-only access to audit ledger, `NOBYPASSRLS` | writes, schema changes |

`cs3_app` never owns the tables it writes to. That separation is what keeps RLS and append-only protections meaningful in production.

## Audit ledger design (`cs3.audit_logs`)

The audit ledger in `003_audit_protection.sql` maps directly to NIST SP 800-53 Rev. 5 AU-9 and AU-10:

- `ALTER TABLE cs3.audit_logs ENABLE ROW LEVEL SECURITY;`
- `ALTER TABLE cs3.audit_logs FORCE ROW LEVEL SECURITY;`
- only `SELECT` and `INSERT` policies exist for non-superusers.
- `BEFORE UPDATE OR DELETE` trigger raises `insufficient_privilege`.
- `BEFORE TRUNCATE` trigger raises the same exception.
- `cs3.audit_chain()` assigns `chain_no`, `prev_hash`, and `chain_hash` using SHA-256 via `pgcrypto.digest()`.
- `cs3.verify_audit_chain()` returns the first broken `chain_no`, or `NULL` when the retained ledger is intact.

Validate the ledger at any time:

```bash
docker compose exec -T postgres psql -U postgres -d cs3 -c "select cs3.verify_audit_chain();"
```

A `NULL` result is the only acceptable production value.

### Two chains, and why

The trigger chain above is one chain. The console also maintains a second, independent chain over
the same entries in `demo/demo-100226/server/db.ts` (`AUDIT_HASH_VERSION = 2`), so that a ledger
tampered with by a party who can bypass the triggers still fails recomputation. Both chains cover a
canonical, fixed-order body of the record; neither is a substitute for the other, and
`GET /api/audit/verify-ledger` reports them separately (`localChain`, `durableLedger`). The in-memory
chain restarts its *sequence* from the persisted head at boot, but the oldest retained entry's
`prev_hash` is trusted exactly as `cs3.verify_audit_chain()` trusts its first retained row — which is
why the external checkpoints below exist.

### Append delivery

Audit appends are queued, retried with capped backoff, and drained one at a time in sequence order.
`CS3_AUDIT_STRICT` only bites when a durable sink exists: with `CS3_PERSISTENCE=memory` the console
has nowhere to persist to and every action stays `X-CS3-Audit: memory`.

| Variable | Default | Meaning |
|---|---|---|
| `CS3_AUDIT_STRICT` | off (on in shipped manifests) | Critical actions (containment, alert triage, incident mutation, auth) answer `503` when the append cannot be confirmed |
| `CS3_AUDIT_PERSIST_TIMEOUT_MS` | `2000` | How long a critical action waits before answering; the write keeps retrying either way |
| `CS3_AUDIT_QUEUE_MAX` | `5000` | Queued entries before the oldest are dropped; drops are counted as `droppedAppends` |
| `CS3_AUDIT_BACKLOG_ALERT` | `50` | Pending depth that raises `cs3_audit_persist_backlog` (and `...cleared` on drain) |
| `CS3_AUDIT_VERIFY_INTERVAL_MS` | `300000` | Re-verify the persisted chain on this interval; `0` disables. A break fails `/api/health` until restart |
| `CS3_AUDIT_REPAIR` | off | At boot, re-anchor the in-memory chain to the persisted head when the persisted chain is broken; without it the console only reports |

Every critical response carries `X-CS3-Audit: durable | degraded | memory`. `GET /api/health`
returns `503 degraded` when either chain is broken (periodically re-verified) or the ledger is
unreachable, so the readiness
probe pulls a replica that can no longer audit.

### External checkpoints (truncation evidence)

Nothing inside the database can prove the ledger was not truncated or rewritten wholesale. Anchor
the head outside it:

```bash
node scripts/audit-checkpoint.mjs --keygen                 # once; secrets/audit/checkpoint-ed25519.pem (0600)
node scripts/audit-checkpoint.mjs --append                 # periodic (cron); signed JSONL, exit 1 on tamper
node scripts/audit-checkpoint.mjs --verify                 # against the pinned .pub
```

The checkpoint key must not live on the database host. Move `checkpoint-ed25519.pem` offline and give the
running script only the signing key it needs, or run `--append` from a host that already holds it.
Anchors are monotonic in `chain_no`; a lower head than the last checkpoint, or a mismatch with a
previously anchored row, is a finding.

Known limits: the console chain cannot distinguish "entry dropped by queue overflow" from "entry
never written" (both appear as `droppedAppends`), and two consoles sharing one ledger allocate
`chain_no` from the trigger, so their in-memory sequences can interleave.

## LISTEN / NOTIFY replacing Firestore `onSnapshot`

`deployment/docker/postgres/init/004_notify.sql` creates `cs3.notify_change()` and publishes compact envelopes on channel `cs3_events`:

```json
{"collection":"incidents","op":"UPDATE","id":"inc-123","ts":"2026-10-19T03:14:15.123Z"}
```

The console's dedicated listener connection in `demo/demo-100226/server/pg/events.ts` forwards those events to Server-Sent Events at:

- `GET /api/events` (canonical)
- `GET /api/live/stream` (alias)

Smoke test:

```bash
curl -N -H 'Accept: text/event-stream' http://localhost:3000/api/events
docker compose exec -T postgres psql -U postgres -d cs3 -c "notify cs3_events, '{"collection":"incidents","op":"UPDATE","id":"smoke","ts":"2026-10-19T03:14:15.123Z"}';"
```

### PgBouncer note

`LISTEN` requires session affinity to one backend connection. If you insert PgBouncer:

- send normal app traffic through PgBouncer in **session mode** only, or keep the console on direct PostgreSQL connections.
- do **not** put the `cs3-console-listen` connection behind transaction pooling; notifications will be dropped.

## Migration procedure

1. Freeze writes to Firestore or put the console in a maintenance window.
2. Initialize PostgreSQL with `docker compose up -d postgres` or your HA control plane.
3. Convert each source collection into newline-delimited JSON (`*.jsonl`) where each line is one final document body and includes its `id` field.
4. Load each collection into a temp staging table, then upsert into the target table.
5. Switch the console to `CS3_PERSISTENCE=postgres`, verify health, and only then re-open writes.

Example import for `users` and `auditLogs`:

```bash
psql "$DATABASE_URL" <<'SQL'
CREATE TEMP TABLE stage_users (doc jsonb NOT NULL);
\copy stage_users(doc) FROM '/srv/cs3/firestore-export/users.jsonl';
INSERT INTO cs3.users (id, data)
SELECT doc->>'id', doc FROM stage_users
ON CONFLICT (id) DO UPDATE SET data = cs3.users.data || EXCLUDED.data;

CREATE TEMP TABLE stage_audit_logs (doc jsonb NOT NULL);
\copy stage_audit_logs(doc) FROM '/srv/cs3/firestore-export/auditLogs.jsonl';
INSERT INTO cs3.audit_logs (id, data)
SELECT doc->>'id', doc FROM stage_audit_logs
ON CONFLICT (id) DO NOTHING;
SQL
```

Load every other collection the same way using the table map above. `auditLogs` must remain append-only; use `DO NOTHING`, not merge-updates.

## HA deployment patterns

Choose one of these patterns for production:

- **Patroni**: use a dedicated replication role, etcd/Consul quorum, pgBackRest for backups, and one virtual IP or HAProxy writer endpoint.
- **CloudNativePG**: use `bootstrap.recovery`, `backup.barmanObjectStore` or pgBackRest-compatible storage, and keep the CS3 console pointed at the primary service.
- **Managed PostgreSQL**: use a single writer endpoint plus read replicas for analytics only. Keep `cs3.audit_logs`, `cs3.enrollments`, and the `LISTEN` connection on the primary.

In every pattern, preserve:

- `wal_level=replica`
- `archive_mode=on`
- `password_encryption=scram-sha-256`
- the existing `cs3_*` roles and RLS protections

## Optional Supabase self-hosted profile

The repo ships `deployment/docker/docker-compose.supabase.yml` for operators who want the Supabase Postgres image while keeping CS3 on direct PostgreSQL access:

```bash
docker compose -f deployment/docker/docker-compose.yml       -f deployment/docker/docker-compose.supabase.yml up -d postgres console
```

Notes:

- the CS3 console still uses `DATABASE_URL`; it does not depend on PostgREST.
- keep the `cs3` schema isolated from Supabase-auth or tenant schemas.
- if you add Studio / GoTrue / Kong, point them at the same database only after CS3 migrations succeed.

## AU-9 tamper test

Run the shipped proof test as a superuser; it uses `SET ROLE cs3_app` internally and exits non-zero on failure.

```bash
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d cs3       < deployment/docker/postgres/tests/audit_tamper_test.sql
```

Expected output ends with `NOTICE:  audit_logs tamper-protection: PASS` followed by a transaction rollback.
