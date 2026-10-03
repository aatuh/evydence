-- Selected parser facts must not require scanning every record in a tenant.
CREATE INDEX IF NOT EXISTS sboms_tenant_evidence_id_idx ON sboms (tenant_id, evidence_id, id);
CREATE INDEX IF NOT EXISTS vulnerability_scans_tenant_evidence_id_idx ON vulnerability_scans (tenant_id, evidence_id, id);
CREATE INDEX IF NOT EXISTS openapi_contracts_tenant_evidence_id_idx ON openapi_contracts (tenant_id, evidence_id, id);
CREATE INDEX IF NOT EXISTS vex_documents_tenant_evidence_id_idx ON vex_documents (tenant_id, evidence_id, id);
CREATE INDEX IF NOT EXISTS build_attestations_tenant_evidence_id_idx ON build_attestations (tenant_id, evidence_id, id);
