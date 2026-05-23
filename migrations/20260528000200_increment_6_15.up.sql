CREATE TABLE IF NOT EXISTS resource_index (
    tenant_id text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    product_id text,
    project_id text,
    release_id text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS resource_index_tenant_type_created_idx
    ON resource_index (tenant_id, resource_type, created_at DESC);

CREATE INDEX IF NOT EXISTS resource_index_tenant_release_idx
    ON resource_index (tenant_id, release_id, resource_type)
    WHERE release_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS evidence_lifecycle_events (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    evidence_id text NOT NULL,
    action text NOT NULL,
    reason text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    replacement_id text,
    actor_id text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_lifecycle_events_tenant_evidence_idx
    ON evidence_lifecycle_events (tenant_id, evidence_id, created_at);

CREATE TABLE IF NOT EXISTS release_candidates (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    release_id text NOT NULL,
    name text NOT NULL,
    state text NOT NULL,
    snapshot_hash text NOT NULL,
    document jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    promoted_at timestamptz,
    rejected_at timestamptz
);

CREATE INDEX IF NOT EXISTS release_candidates_tenant_release_idx
    ON release_candidates (tenant_id, release_id, created_at);

CREATE TABLE IF NOT EXISTS container_images (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    artifact_id text,
    repository text NOT NULL,
    tag text,
    digest text NOT NULL,
    platform text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, repository, digest)
);

CREATE TABLE IF NOT EXISTS artifact_signatures (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    artifact_id text NOT NULL,
    subject_digest text NOT NULL,
    algorithm text NOT NULL,
    key_id text,
    signature text NOT NULL,
    payload_ref text,
    payload_hash text,
    verification_status text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS artifact_signatures_tenant_artifact_idx
    ON artifact_signatures (tenant_id, artifact_id, created_at);

CREATE TABLE IF NOT EXISTS source_repositories (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    project_id text,
    provider text NOT NULL,
    full_name text NOT NULL,
    clone_url text,
    default_branch text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, provider, full_name)
);

CREATE TABLE IF NOT EXISTS source_commits (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    sha text NOT NULL,
    author text,
    message_hash text,
    committed_at timestamptz NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, repository_id, sha)
);

CREATE TABLE IF NOT EXISTS source_branches (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    name text NOT NULL,
    head_commit_id text,
    protected boolean NOT NULL DEFAULT false,
    protection_hash text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, repository_id, name)
);

CREATE TABLE IF NOT EXISTS pull_requests (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    provider text NOT NULL,
    provider_id text NOT NULL,
    title text NOT NULL,
    state text NOT NULL,
    source_branch text,
    target_branch text,
    head_commit_id text,
    review_decision text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS pull_requests_tenant_repository_idx
    ON pull_requests (tenant_id, repository_id, created_at);

CREATE TABLE IF NOT EXISTS deployment_environments (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    product_id text NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, product_id, name)
);

CREATE TABLE IF NOT EXISTS deployment_events (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    release_id text NOT NULL,
    artifact_ids text[] NOT NULL DEFAULT '{}',
    status text NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    rollback_of text,
    evidence_id text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS deployment_events_tenant_release_idx
    ON deployment_events (tenant_id, release_id, created_at);

CREATE INDEX IF NOT EXISTS deployment_events_tenant_environment_idx
    ON deployment_events (tenant_id, environment_id, created_at);
