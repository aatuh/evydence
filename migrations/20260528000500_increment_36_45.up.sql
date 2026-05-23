CREATE TABLE IF NOT EXISTS cosign_verifications (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    artifact_id text,
    container_image_id text,
    artifact_signature_id text NOT NULL,
    subject_digest text NOT NULL,
    rekor_uuid text,
    rekor_log_index text,
    certificate_identity text,
    certificate_issuer text,
    result text NOT NULL,
    checks jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS cosign_verifications_tenant_signature_idx
    ON cosign_verifications (tenant_id, artifact_signature_id, created_at);

CREATE TABLE IF NOT EXISTS signing_providers (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    status text NOT NULL,
    key_ref text NOT NULL,
    encrypted boolean NOT NULL DEFAULT false,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS merkle_batches (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    from_sequence bigint NOT NULL,
    to_sequence bigint NOT NULL,
    entry_count integer NOT NULL,
    leaf_hashes text[] NOT NULL,
    root_hash text NOT NULL,
    signature_refs text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS merkle_batches_tenant_sequence_idx
    ON merkle_batches (tenant_id, from_sequence, to_sequence);

CREATE TABLE IF NOT EXISTS transparency_checkpoints (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    batch_id text NOT NULL,
    provider text NOT NULL,
    external_url text,
    external_id text,
    timestamp_hash text NOT NULL,
    state text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS transparency_checkpoints_tenant_batch_idx
    ON transparency_checkpoints (tenant_id, batch_id, created_at);

CREATE TABLE IF NOT EXISTS object_retention_policies (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    object_prefix text NOT NULL,
    mode text NOT NULL,
    retention_days integer NOT NULL,
    status text NOT NULL,
    verified_at timestamptz,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_manifests (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    state_hash text NOT NULL,
    resource_counts jsonb NOT NULL,
    consistency_checks jsonb NOT NULL,
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);
