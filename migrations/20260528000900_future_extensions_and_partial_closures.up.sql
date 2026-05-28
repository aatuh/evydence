ALTER TABLE object_retention_policies
    ADD COLUMN IF NOT EXISTS verification_hash text;

CREATE TABLE IF NOT EXISTS evidence_summaries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    evidence_ids text[] NOT NULL DEFAULT '{}',
    summary text NOT NULL,
    citations jsonb NOT NULL,
    assumptions text[] NOT NULL DEFAULT '{}',
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS questionnaire_drafts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    template_id text NOT NULL,
    product_id text,
    release_id text,
    responses jsonb NOT NULL,
    manifest_hash text NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_graph_snapshots (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    product_id text,
    release_id text,
    nodes jsonb NOT NULL,
    edges jsonb NOT NULL,
    graph_hash text NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS saas_edition_profiles (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    region text NOT NULL,
    admin_tenant_id text NOT NULL,
    isolation_model text NOT NULL,
    status text NOT NULL,
    config_hash text NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS public_transparency_logs (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    endpoint text NOT NULL,
    public_key text NOT NULL,
    state text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS public_transparency_log_entries (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    log_id text NOT NULL,
    checkpoint_id text NOT NULL,
    merkle_batch_id text NOT NULL,
    external_id text NOT NULL,
    entry_hash text NOT NULL,
    state text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS marketplace_collectors (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    version text NOT NULL,
    publisher text NOT NULL,
    manifest_hash text NOT NULL,
    signature_id text,
    sbom_id text,
    scan_id text,
    state text NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, provider, name, version)
);

CREATE TABLE IF NOT EXISTS pdf_report_packages (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    report_type text NOT NULL,
    product_id text,
    release_id text,
    title text NOT NULL,
    payload_ref text,
    payload_hash text NOT NULL,
    payload_size bigint NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS anomaly_reports (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    result text NOT NULL,
    signals jsonb NOT NULL,
    assumptions text[] NOT NULL DEFAULT '{}',
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_verifications (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    provider_type text NOT NULL,
    provider_id text NOT NULL,
    subject text NOT NULL,
    result text NOT NULL,
    checks jsonb NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS signing_operations (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    provider_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    payload_hash text NOT NULL,
    signature_ref text,
    result text NOT NULL,
    checks jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_summaries_tenant_subject_idx
    ON evidence_summaries (tenant_id, subject_type, subject_id, created_at);
CREATE INDEX IF NOT EXISTS questionnaire_drafts_tenant_release_idx
    ON questionnaire_drafts (tenant_id, release_id, created_at);
CREATE INDEX IF NOT EXISTS evidence_graph_snapshots_tenant_release_idx
    ON evidence_graph_snapshots (tenant_id, release_id, created_at);
CREATE INDEX IF NOT EXISTS saas_edition_profiles_tenant_status_idx
    ON saas_edition_profiles (tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS public_transparency_log_entries_tenant_log_idx
    ON public_transparency_log_entries (tenant_id, log_id, created_at);
CREATE INDEX IF NOT EXISTS marketplace_collectors_tenant_provider_idx
    ON marketplace_collectors (tenant_id, provider, created_at);
CREATE INDEX IF NOT EXISTS pdf_report_packages_tenant_release_idx
    ON pdf_report_packages (tenant_id, release_id, created_at);
CREATE INDEX IF NOT EXISTS anomaly_reports_tenant_subject_idx
    ON anomaly_reports (tenant_id, subject_type, subject_id, created_at);
CREATE INDEX IF NOT EXISTS provider_verifications_tenant_provider_idx
    ON provider_verifications (tenant_id, provider_type, provider_id, created_at);
CREATE INDEX IF NOT EXISTS signing_operations_tenant_subject_idx
    ON signing_operations (tenant_id, subject_type, subject_id, created_at);
