DROP INDEX IF EXISTS build_attestations_tenant_payload_hash_idx;
DROP INDEX IF EXISTS build_attestations_tenant_build_idx;
DROP TABLE IF EXISTS build_attestations;

DROP INDEX IF EXISTS build_runs_tenant_provider_run_idx;
DROP INDEX IF EXISTS build_runs_tenant_project_idx;
DROP INDEX IF EXISTS build_runs_tenant_release_idx;
DROP TABLE IF EXISTS build_runs;

DROP INDEX IF EXISTS collectors_tenant_type_idx;
DROP TABLE IF EXISTS collectors;
