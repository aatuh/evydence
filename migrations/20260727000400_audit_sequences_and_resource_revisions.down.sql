ALTER TABLE release_candidates DROP COLUMN IF EXISTS revision;
ALTER TABLE releases DROP COLUMN IF EXISTS revision;
DROP TABLE IF EXISTS tenant_audit_sequences;
