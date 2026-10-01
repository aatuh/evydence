CREATE INDEX IF NOT EXISTS incident_timeline_events_report_order_idx
  ON incident_timeline_events(tenant_id, incident_id, occurred_at, id);

CREATE INDEX IF NOT EXISTS remediation_tasks_report_order_idx
  ON remediation_tasks(tenant_id, incident_id, created_at, id);
