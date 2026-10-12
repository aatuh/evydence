CREATE INDEX IF NOT EXISTS control_evidence_tenant_created_id_idx
    ON control_evidence (tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS control_evidence_tenant_id_idx
    ON control_evidence (tenant_id, id);

CREATE INDEX IF NOT EXISTS evidence_items_subject_refs_gin_idx
    ON evidence_items USING gin (subject_refs);

CREATE INDEX IF NOT EXISTS vulnerability_scans_findings_gin_idx
    ON vulnerability_scans USING gin (findings);

CREATE INDEX IF NOT EXISTS build_runs_outputs_gin_idx
    ON build_runs USING gin (outputs);
