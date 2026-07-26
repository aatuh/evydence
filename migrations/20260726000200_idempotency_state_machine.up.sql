ALTER TABLE idempotency_records
    ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT 'completed',
    ADD COLUMN IF NOT EXISTS owner_token_hash text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_at timestamptz,
    ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS completed_at timestamptz,
    ADD COLUMN IF NOT EXISTS failed_at timestamptz,
    ADD COLUMN IF NOT EXISTS expires_at timestamptz;

-- Rows written before the state machine were successful, replayable records.
-- Preserve their digest and response while giving them explicit terminal and
-- retention metadata.
UPDATE idempotency_records
SET state = 'completed',
    owner_token_hash = '',
    updated_at = COALESCE(updated_at, created_at),
    completed_at = COALESCE(completed_at, created_at),
    expires_at = COALESCE(expires_at, created_at + INTERVAL '24 hours')
WHERE state IS NULL
   OR state = ''
   OR updated_at IS NULL
   OR expires_at IS NULL;

ALTER TABLE idempotency_records
    ALTER COLUMN updated_at SET NOT NULL,
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN updated_at SET DEFAULT now(),
    ALTER COLUMN expires_at SET DEFAULT (now() + INTERVAL '24 hours');

-- Old records stored bare IDs. Current request actors are namespaced so API
-- keys, SSO users, and collectors cannot collide while retaining replay data.
UPDATE idempotency_records AS record
SET actor_key_id = CASE
    WHEN EXISTS (
        SELECT 1 FROM api_keys
        WHERE api_keys.id = record.actor_key_id AND api_keys.tenant_id = record.tenant_id
    ) THEN 'api_key:' || record.actor_key_id
    WHEN EXISTS (
        SELECT 1 FROM human_users
        WHERE human_users.id = record.actor_key_id AND human_users.tenant_id = record.tenant_id
    ) THEN 'user:' || record.actor_key_id
    WHEN EXISTS (
        SELECT 1 FROM collectors
        WHERE collectors.id = record.actor_key_id AND collectors.tenant_id = record.tenant_id
    ) THEN 'collector:' || record.actor_key_id
    ELSE record.actor_key_id
END
WHERE actor_key_id NOT LIKE 'api_key:%'
  AND actor_key_id NOT LIKE 'user:%'
  AND actor_key_id NOT LIKE 'collector:%';

ALTER TABLE idempotency_records
    DROP CONSTRAINT IF EXISTS idempotency_records_state_check,
    ADD CONSTRAINT idempotency_records_state_check
        CHECK (state IN ('pending', 'completed', 'failed'));

CREATE INDEX IF NOT EXISTS idempotency_records_pending_lease_idx
    ON idempotency_records (lease_expires_at)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idempotency_records_expiry_idx
    ON idempotency_records (expires_at);
