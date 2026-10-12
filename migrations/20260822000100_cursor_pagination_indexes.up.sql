CREATE INDEX IF NOT EXISTS evidence_items_tenant_created_id_idx
  ON evidence_items(tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS evidence_items_tenant_release_created_id_idx
  ON evidence_items(tenant_id, release_id, created_at, id)
  WHERE release_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS evidence_items_tenant_type_created_id_idx
  ON evidence_items(tenant_id, type, created_at, id);
