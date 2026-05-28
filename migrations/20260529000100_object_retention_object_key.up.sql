ALTER TABLE object_retention_policies
    ADD COLUMN IF NOT EXISTS object_key text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS object_retention_policies_tenant_object_key_idx
    ON object_retention_policies (tenant_id, object_key)
    WHERE object_key <> '';
