DROP INDEX IF EXISTS idempotency_records_expiry_idx;
DROP INDEX IF EXISTS idempotency_records_pending_lease_idx;

ALTER TABLE idempotency_records
    DROP CONSTRAINT IF EXISTS idempotency_records_state_check;

UPDATE idempotency_records
SET actor_key_id = CASE
    WHEN actor_key_id LIKE 'api_key:%' THEN substring(actor_key_id FROM 9)
    WHEN actor_key_id LIKE 'user:%' THEN substring(actor_key_id FROM 6)
    WHEN actor_key_id LIKE 'collector:%' THEN substring(actor_key_id FROM 11)
    ELSE actor_key_id
END;

ALTER TABLE idempotency_records
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS failed_at,
    DROP COLUMN IF EXISTS completed_at,
    DROP COLUMN IF EXISTS lease_expires_at,
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS owner_token_hash,
    DROP COLUMN IF EXISTS state;
