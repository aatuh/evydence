CREATE INDEX IF NOT EXISTS marketplace_collectors_tenant_created_id_idx
    ON marketplace_collectors (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS marketplace_collectors_tenant_id_idx
    ON marketplace_collectors (tenant_id, id);
