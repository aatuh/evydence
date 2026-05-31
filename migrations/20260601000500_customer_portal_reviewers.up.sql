ALTER TABLE customer_portal_access
    ADD COLUMN IF NOT EXISTS reviewer_name text,
    ADD COLUMN IF NOT EXISTS reviewer_email text;

CREATE INDEX IF NOT EXISTS customer_portal_access_tenant_reviewer_idx
    ON customer_portal_access (tenant_id, reviewer_email, created_at);
