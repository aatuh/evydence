DROP INDEX IF EXISTS object_retention_policies_tenant_legal_hold_idx;

ALTER TABLE object_retention_policies
    DROP COLUMN IF EXISTS require_legal_hold;
