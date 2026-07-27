DROP TABLE IF EXISTS outbox_job_attempts;
DROP INDEX IF EXISTS outbox_jobs_reclaim_idx;
DROP INDEX IF EXISTS outbox_jobs_tenant_deduplication_key_idx;
ALTER TABLE outbox_jobs
  DROP COLUMN IF EXISTS terminal_at,
  DROP COLUMN IF EXISTS failure_code,
  DROP COLUMN IF EXISTS failure_class,
  DROP COLUMN IF EXISTS lease_token,
  DROP COLUMN IF EXISTS deduplication_key;
