CREATE INDEX IF NOT EXISTS products_tenant_created_id_idx
  ON products(tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS products_tenant_id_idx
  ON products(tenant_id, id);
