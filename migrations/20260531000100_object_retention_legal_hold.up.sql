ALTER TABLE object_retention_policies
    ADD COLUMN IF NOT EXISTS require_legal_hold boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS object_retention_policies_tenant_legal_hold_idx
    ON object_retention_policies (tenant_id, require_legal_hold)
    WHERE require_legal_hold = true;
