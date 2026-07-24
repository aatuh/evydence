ALTER TABLE audit_chain_entries
    ADD COLUMN IF NOT EXISTS request_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS idempotency_key text NOT NULL DEFAULT '';
