DROP INDEX IF EXISTS signing_operations_tenant_request_idx;

ALTER TABLE signing_operations
    DROP COLUMN IF EXISTS provider_request_id,
    DROP COLUMN IF EXISTS request_id,
    DROP COLUMN IF EXISTS canonical_payload_hash;
