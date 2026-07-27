ALTER TABLE outbox_jobs
  ADD COLUMN IF NOT EXISTS deduplication_key text,
  ADD COLUMN IF NOT EXISTS lease_token text,
  ADD COLUMN IF NOT EXISTS failure_class text,
  ADD COLUMN IF NOT EXISTS failure_code text,
  ADD COLUMN IF NOT EXISTS terminal_at timestamptz;

UPDATE outbox_jobs
SET deduplication_key = 'legacy:' || id
WHERE deduplication_key IS NULL OR deduplication_key = '';

UPDATE outbox_jobs
SET status = 'dead_letter',
    failure_class = COALESCE(NULLIF(failure_class, ''), 'permanent'),
    failure_code = COALESCE(NULLIF(failure_code, ''), 'legacy_failed'),
    last_error = COALESCE(NULLIF(failure_code, ''), 'legacy_failed'),
    terminal_at = COALESCE(terminal_at, updated_at)
WHERE status = 'failed';

-- Historical retry errors may contain driver, provider, or payload details. The
-- retry lifecycle exposes only stable failure codes, so replace those legacy
-- strings while retaining a coarse classification for operators.
UPDATE outbox_jobs
SET failure_class = COALESCE(NULLIF(failure_class, ''), 'transient'),
    failure_code = COALESCE(NULLIF(failure_code, ''), 'legacy_retry_failed'),
    last_error = COALESCE(NULLIF(failure_code, ''), 'legacy_retry_failed')
WHERE status = 'retrying'
  AND last_error IS NOT NULL
  AND last_error <> '';

ALTER TABLE outbox_jobs
  ALTER COLUMN deduplication_key SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS outbox_jobs_tenant_deduplication_key_idx
  ON outbox_jobs (tenant_id, deduplication_key);

CREATE INDEX IF NOT EXISTS outbox_jobs_reclaim_idx
  ON outbox_jobs (status, locked_at)
  WHERE status = 'running';

CREATE TABLE IF NOT EXISTS outbox_job_attempts (
  id bigserial PRIMARY KEY,
  job_id text NOT NULL REFERENCES outbox_jobs(id) ON DELETE CASCADE,
  attempt integer NOT NULL,
  outcome text NOT NULL,
  failure_class text,
  failure_code text,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS outbox_job_attempts_job_occurred_idx
  ON outbox_job_attempts (job_id, occurred_at);
