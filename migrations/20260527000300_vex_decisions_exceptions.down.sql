DROP INDEX IF EXISTS exceptions_tenant_finding_idx;
DROP INDEX IF EXISTS exceptions_tenant_release_idx;

ALTER TABLE exceptions
  DROP COLUMN IF EXISTS approved_at,
  DROP COLUMN IF EXISTS approved_by,
  DROP COLUMN IF EXISTS control_id,
  DROP COLUMN IF EXISTS finding_id;

DROP TABLE IF EXISTS exceptions;

DROP INDEX IF EXISTS vulnerability_decisions_tenant_release_idx;
DROP INDEX IF EXISTS vulnerability_decisions_tenant_finding_idx;
DROP TABLE IF EXISTS vulnerability_decisions;

DROP INDEX IF EXISTS vex_documents_tenant_release_idx;
DROP TABLE IF EXISTS vex_documents;
