CREATE TABLE IF NOT EXISTS provider_signature_receipts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id),
    provider_id text NOT NULL REFERENCES signing_providers(id),
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    algorithm text NOT NULL,
    value text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS provider_signature_receipts_tenant_provider_idx
    ON provider_signature_receipts (tenant_id, provider_id, created_at);
