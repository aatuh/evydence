DROP INDEX IF EXISTS evidence_items_tenant_build_idx;
DROP INDEX IF EXISTS vulnerability_scans_tenant_release_idx;

ALTER TABLE openapi_contracts
  DROP COLUMN IF EXISTS operations;

ALTER TABLE vulnerability_scans
  DROP COLUMN IF EXISTS release_id;

ALTER TABLE evidence_items
  DROP COLUMN IF EXISTS evidence_version,
  DROP COLUMN IF EXISTS deployment_id,
  DROP COLUMN IF EXISTS build_id;
