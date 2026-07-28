ALTER TABLE object_payloads
  ADD COLUMN IF NOT EXISTS staging_key text,
  ADD COLUMN IF NOT EXISTS final_key text,
  ADD COLUMN IF NOT EXISTS status text,
  ADD COLUMN IF NOT EXISTS failure_code text,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz,
  ADD COLUMN IF NOT EXISTS finalized_at timestamptz,
  ADD COLUMN IF NOT EXISTS failed_at timestamptz,
  ADD COLUMN IF NOT EXISTS orphaned_at timestamptz;

-- Existing metadata was written before a durable staging/finalization
-- protocol existed. It is conservatively discoverable but not trusted until
-- reconciliation proves the backing object and digest.
UPDATE object_payloads
SET final_key = COALESCE(NULLIF(final_key, ''), object_key),
    staging_key = COALESCE(NULLIF(staging_key, ''), object_key),
    status = COALESCE(NULLIF(status, ''), 'orphaned'),
    updated_at = COALESCE(updated_at, created_at),
    orphaned_at = CASE
      WHEN COALESCE(NULLIF(status, ''), 'orphaned') = 'orphaned' THEN COALESCE(orphaned_at, created_at)
      ELSE orphaned_at
    END;

ALTER TABLE object_payloads
  ALTER COLUMN final_key SET NOT NULL,
  ALTER COLUMN staging_key SET NOT NULL,
  ALTER COLUMN status SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE object_payloads
  ADD CONSTRAINT object_payloads_status_check
  CHECK (status IN ('staged', 'finalized', 'failed', 'orphaned'));

ALTER TABLE object_payloads
  ADD CONSTRAINT object_payloads_tenant_final_key_check
  CHECK (final_key LIKE 'tenants/' || tenant_id || '/%');

ALTER TABLE object_payloads
  ADD CONSTRAINT object_payloads_tenant_staging_key_check
  CHECK (staging_key LIKE 'tenants/' || tenant_id || '/%');

CREATE UNIQUE INDEX object_payloads_active_tenant_digest_idx
  ON object_payloads (tenant_id, digest)
  WHERE status <> 'orphaned';

CREATE INDEX object_payloads_status_updated_idx
  ON object_payloads (status, updated_at);
