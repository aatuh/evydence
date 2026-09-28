CREATE INDEX IF NOT EXISTS audit_chain_tenant_time_id_idx
    ON audit_chain_entries (tenant_id, occurred_at, id);

CREATE INDEX IF NOT EXISTS audit_chain_tenant_subject_time_id_idx
    ON audit_chain_entries (tenant_id, subject_type, subject_id, occurred_at, id);

CREATE INDEX IF NOT EXISTS audit_chain_tenant_id_idx
    ON audit_chain_entries (tenant_id, id);
