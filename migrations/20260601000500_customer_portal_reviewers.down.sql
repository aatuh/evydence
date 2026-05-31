DROP INDEX IF EXISTS customer_portal_access_tenant_reviewer_idx;

ALTER TABLE customer_portal_access
    DROP COLUMN IF EXISTS reviewer_email,
    DROP COLUMN IF EXISTS reviewer_name;
