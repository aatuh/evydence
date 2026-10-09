CREATE INDEX IF NOT EXISTS api_keys_tenant_created_id_idx
    ON api_keys (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS api_keys_tenant_id_idx
    ON api_keys (tenant_id, id);
