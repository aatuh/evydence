CREATE TABLE IF NOT EXISTS collector_releases (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    collector_id text NOT NULL,
    version text NOT NULL,
    artifact_digest text NOT NULL,
    signature_id text,
    sbom_id text,
    scan_id text,
    pinned boolean NOT NULL DEFAULT false,
    verification_status text NOT NULL,
    health_status text NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS collector_releases_tenant_collector_idx
    ON collector_releases (tenant_id, collector_id, created_at);
