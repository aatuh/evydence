CREATE TABLE IF NOT EXISTS incidents (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    product_id text NOT NULL,
    release_id text,
    title text NOT NULL,
    severity text NOT NULL,
    status text NOT NULL,
    opened_at timestamptz NOT NULL,
    closed_at timestamptz,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_tenant_product_idx
    ON incidents (tenant_id, product_id, created_at);

CREATE TABLE IF NOT EXISTS incident_timeline_events (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    incident_id text NOT NULL,
    event_type text NOT NULL,
    summary text NOT NULL,
    evidence_id text,
    occurred_at timestamptz NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS incident_timeline_events_tenant_incident_idx
    ON incident_timeline_events (tenant_id, incident_id, occurred_at);

CREATE TABLE IF NOT EXISTS remediation_tasks (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    incident_id text,
    release_id text,
    title text NOT NULL,
    owner text NOT NULL,
    status text NOT NULL,
    due_at timestamptz,
    evidence_id text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS security_scans (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    product_id text,
    release_id text,
    artifact_id text,
    category text NOT NULL,
    format text NOT NULL,
    scanner text NOT NULL,
    target_ref text NOT NULL,
    evidence_id text NOT NULL,
    payload_ref text,
    payload_hash text NOT NULL,
    finding_count integer NOT NULL,
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    redacted boolean NOT NULL DEFAULT false,
    quarantined boolean NOT NULL DEFAULT false,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS security_scans_tenant_release_idx
    ON security_scans (tenant_id, release_id, category, created_at);

CREATE TABLE IF NOT EXISTS manual_security_documents (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    product_id text,
    release_id text,
    document_type text NOT NULL,
    title text NOT NULL,
    sensitivity text NOT NULL,
    evidence_id text NOT NULL,
    payload_ref text,
    payload_hash text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS sbom_diffs (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    base_sbom_id text NOT NULL,
    target_sbom_id text NOT NULL,
    release_id text,
    document jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS dependency_changes (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    sbom_diff_id text NOT NULL,
    change_type text NOT NULL,
    component jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_workflow_records (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    finding_id text NOT NULL,
    release_id text,
    action text NOT NULL,
    reason text NOT NULL,
    actor_id text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS contract_diffs (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    base_contract_id text NOT NULL,
    target_contract_id text NOT NULL,
    product_id text NOT NULL,
    release_id text,
    result text NOT NULL,
    document jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS custom_policies (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    description text,
    rules jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, name, version)
);

CREATE TABLE IF NOT EXISTS custom_policy_evaluations (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    policy_id text NOT NULL,
    release_id text NOT NULL,
    result text NOT NULL,
    checks jsonb NOT NULL,
    input_hash text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);
