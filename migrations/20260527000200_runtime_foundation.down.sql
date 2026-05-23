DROP INDEX IF EXISTS verification_results_tenant_subject_idx;
DROP INDEX IF EXISTS release_bundles_tenant_release_idx;
DROP INDEX IF EXISTS openapi_contracts_tenant_product_idx;
DROP INDEX IF EXISTS vulnerability_scans_tenant_created_idx;
DROP INDEX IF EXISTS sboms_tenant_release_idx;
DROP INDEX IF EXISTS artifacts_tenant_created_idx;
DROP INDEX IF EXISTS releases_tenant_product_idx;
DROP INDEX IF EXISTS projects_tenant_product_idx;
DROP INDEX IF EXISTS products_tenant_created_idx;

DROP TABLE IF EXISTS chain_checkpoints;
DROP TABLE IF EXISTS object_payloads;
DROP TABLE IF EXISTS outbox_jobs;
DROP TABLE IF EXISTS idempotency_records;
DROP TABLE IF EXISTS ledger_state;
