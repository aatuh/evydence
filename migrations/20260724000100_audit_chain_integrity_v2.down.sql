ALTER TABLE audit_chain_entries
    DROP COLUMN IF EXISTS idempotency_key,
    DROP COLUMN IF EXISTS request_id;
