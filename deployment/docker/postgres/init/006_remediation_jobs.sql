-- Durable, owner-scoped AI remediation jobs. Safe to run repeatedly as cs3_migrator.
-- The runtime role receives DML only; job documents retain their full lifecycle and results.

SET client_min_messages = warning;
SET ROLE cs3_migrator;
SET search_path = cs3, public;

CREATE TABLE IF NOT EXISTS cs3.remediation_jobs (
  id         text PRIMARY KEY,
  data       jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS remediation_jobs_data_gin
  ON cs3.remediation_jobs USING gin (data jsonb_path_ops);
CREATE INDEX IF NOT EXISTS remediation_jobs_updated_idx
  ON cs3.remediation_jobs (updated_at DESC);
CREATE INDEX IF NOT EXISTS remediation_jobs_queue_idx
  ON cs3.remediation_jobs (created_at, id)
  WHERE data->>'status' = 'queued';
CREATE INDEX IF NOT EXISTS remediation_jobs_vulnerability_idx
  ON cs3.remediation_jobs ((data->>'ownerId'), ((data->'vulnerability'->>'id')))
  WHERE data->>'status' IN ('queued', 'running');
CREATE UNIQUE INDEX IF NOT EXISTS remediation_jobs_active_owner_fingerprint_uq
  ON cs3.remediation_jobs ((data->>'ownerId'), (data->>'fingerprint'))
  WHERE data->>'status' IN ('queued', 'running');

DROP TRIGGER IF EXISTS remediation_jobs_touch ON cs3.remediation_jobs;
CREATE TRIGGER remediation_jobs_touch BEFORE UPDATE ON cs3.remediation_jobs
  FOR EACH ROW EXECUTE FUNCTION cs3.touch_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON cs3.remediation_jobs TO cs3_app;

RESET ROLE;
