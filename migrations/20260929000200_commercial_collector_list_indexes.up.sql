CREATE INDEX IF NOT EXISTS commercial_collectors_tenant_created_id_idx
    ON commercial_collectors (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS commercial_collectors_tenant_id_idx
    ON commercial_collectors (tenant_id, id);
