CREATE INDEX IF NOT EXISTS signing_keys_tenant_created_id_idx
    ON signing_keys (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS signing_keys_tenant_id_idx
    ON signing_keys (tenant_id, id);
