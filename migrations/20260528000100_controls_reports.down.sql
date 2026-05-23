DROP INDEX IF EXISTS control_evidence_tenant_scope_idx;
DROP INDEX IF EXISTS control_evidence_tenant_control_idx;
DROP INDEX IF EXISTS control_evidence_unique_link_idx;
DROP TABLE IF EXISTS control_evidence;

DROP INDEX IF EXISTS security_controls_tenant_framework_idx;
DROP TABLE IF EXISTS security_controls;

DROP INDEX IF EXISTS control_frameworks_tenant_slug_idx;
DROP TABLE IF EXISTS control_frameworks;
