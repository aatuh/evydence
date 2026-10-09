ALTER TABLE signing_operations
    ADD COLUMN IF NOT EXISTS canonical_payload_hash text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS request_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_request_id text;

CREATE INDEX IF NOT EXISTS signing_operations_tenant_request_idx
    ON signing_operations (tenant_id, request_id)
    WHERE request_id <> '';
