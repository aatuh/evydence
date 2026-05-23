ALTER TABLE customer_portal_access
    DROP COLUMN IF EXISTS last_failed_at,
    DROP COLUMN IF EXISTS last_accessed_at,
    DROP COLUMN IF EXISTS failed_access_count;
