CREATE TABLE IF NOT EXISTS waivers (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    scope_type text NOT NULL,
    scope_id text NOT NULL,
    control_id text,
    policy_id text,
    owner text NOT NULL,
    risk text NOT NULL,
    reason text NOT NULL,
    expires_at timestamptz NOT NULL,
    approved boolean NOT NULL DEFAULT false,
    approved_by text,
    approved_at timestamptz,
    supersedes text,
    superseded_by text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS waivers_tenant_scope_idx
    ON waivers (tenant_id, scope_type, scope_id, expires_at);

CREATE TABLE IF NOT EXISTS approval_records (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    decision text NOT NULL,
    reason text NOT NULL,
    approver_id text NOT NULL,
    evidence_id text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS approval_records_tenant_subject_idx
    ON approval_records (tenant_id, subject_type, subject_id, created_at);

CREATE TABLE IF NOT EXISTS redaction_profiles (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    description text,
    allowed_types text[] NOT NULL DEFAULT '{}',
    excluded_fields text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS customer_security_packages (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    product_id text NOT NULL,
    release_id text,
    redaction_profile_id text NOT NULL,
    title text NOT NULL,
    state text NOT NULL,
    manifest jsonb NOT NULL,
    manifest_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    access_count integer NOT NULL DEFAULT 0,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS customer_security_packages_tenant_release_idx
    ON customer_security_packages (tenant_id, release_id, expires_at);

CREATE TABLE IF NOT EXISTS html_report_packages (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    report_type text NOT NULL,
    product_id text NOT NULL,
    release_id text,
    html text NOT NULL,
    hash text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS report_templates (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    report_type text NOT NULL,
    allowed_fields text[] NOT NULL,
    template text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, name, version)
);

CREATE TABLE IF NOT EXISTS rendered_reports (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    template_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    output jsonb NOT NULL,
    hash text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_bundles (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    release_id text,
    evidence_ids text[] NOT NULL,
    manifest jsonb NOT NULL,
    manifest_hash text NOT NULL,
    signature_refs text[] NOT NULL DEFAULT '{}',
    verification_text text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_bundle_imports (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    bundle_hash text NOT NULL,
    result text NOT NULL,
    imported_count integer NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS dsse_trust_roots (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    key_id text NOT NULL,
    algorithm text NOT NULL,
    public_key text NOT NULL,
    status text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, key_id)
);
