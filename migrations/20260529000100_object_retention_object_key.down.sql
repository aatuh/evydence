DROP INDEX IF EXISTS object_retention_policies_tenant_object_key_idx;

ALTER TABLE object_retention_policies
    DROP COLUMN IF EXISTS object_key;
