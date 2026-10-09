CREATE INDEX IF NOT EXISTS incidents_security_update_order_idx
  ON incidents(tenant_id, product_id, release_id, id);

CREATE INDEX IF NOT EXISTS remediation_tasks_security_update_order_idx
  ON remediation_tasks(tenant_id, release_id, id);
