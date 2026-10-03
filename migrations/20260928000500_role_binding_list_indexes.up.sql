CREATE INDEX IF NOT EXISTS role_bindings_tenant_created_id_idx
    ON role_bindings (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS role_bindings_tenant_id_idx
    ON role_bindings (tenant_id, id);
