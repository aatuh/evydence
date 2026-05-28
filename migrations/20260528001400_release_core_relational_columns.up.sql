ALTER TABLE evidence_items
  ADD COLUMN IF NOT EXISTS build_id text,
  ADD COLUMN IF NOT EXISTS deployment_id text,
  ADD COLUMN IF NOT EXISTS evidence_version integer NOT NULL DEFAULT 1;

ALTER TABLE vulnerability_scans
  ADD COLUMN IF NOT EXISTS release_id text;

ALTER TABLE openapi_contracts
  ADD COLUMN IF NOT EXISTS operations jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS vulnerability_scans_tenant_release_idx
  ON vulnerability_scans(tenant_id, release_id, created_at);

CREATE INDEX IF NOT EXISTS evidence_items_tenant_build_idx
  ON evidence_items(tenant_id, build_id)
  WHERE build_id IS NOT NULL;
