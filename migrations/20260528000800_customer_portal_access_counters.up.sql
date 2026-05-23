ALTER TABLE customer_portal_access
    ADD COLUMN IF NOT EXISTS failed_access_count integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_accessed_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_failed_at timestamptz;
