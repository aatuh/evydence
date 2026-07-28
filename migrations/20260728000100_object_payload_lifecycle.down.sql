DROP INDEX IF EXISTS object_payloads_status_updated_idx;
DROP INDEX IF EXISTS object_payloads_active_tenant_digest_idx;
ALTER TABLE object_payloads DROP CONSTRAINT IF EXISTS object_payloads_tenant_staging_key_check;
ALTER TABLE object_payloads DROP CONSTRAINT IF EXISTS object_payloads_tenant_final_key_check;
ALTER TABLE object_payloads DROP CONSTRAINT IF EXISTS object_payloads_status_check;
ALTER TABLE object_payloads
  DROP COLUMN IF EXISTS orphaned_at,
  DROP COLUMN IF EXISTS failed_at,
  DROP COLUMN IF EXISTS finalized_at,
  DROP COLUMN IF EXISTS updated_at,
  DROP COLUMN IF EXISTS failure_code,
  DROP COLUMN IF EXISTS status,
  DROP COLUMN IF EXISTS final_key,
  DROP COLUMN IF EXISTS staging_key;
