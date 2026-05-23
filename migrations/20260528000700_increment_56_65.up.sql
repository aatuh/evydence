CREATE TABLE IF NOT EXISTS organizations (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    status text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, slug)
);

CREATE TABLE IF NOT EXISTS human_users (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    organization_id text,
    email text NOT NULL,
    display_name text NOT NULL,
    status text NOT NULL,
    deactivated_at timestamptz,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS role_bindings (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    role text NOT NULL,
    resource_type text,
    resource_id text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS sso_providers (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    groups_claim text,
    role_mapping jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS user_identity_links (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    provider_id text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL,
    verified boolean NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, provider_id, subject)
);

CREATE TABLE IF NOT EXISTS sso_sessions (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    provider_id text NOT NULL,
    prefix text NOT NULL,
    hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS legal_holds (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    scope_type text NOT NULL,
    scope_id text NOT NULL,
    reason text NOT NULL,
    owner text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS retention_overrides (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    scope_type text NOT NULL,
    scope_id text NOT NULL,
    retention_until timestamptz NOT NULL,
    reason text NOT NULL,
    owner text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS customer_portal_access (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    package_id text NOT NULL,
    customer_name text NOT NULL,
    prefix text NOT NULL,
    hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    access_count integer NOT NULL DEFAULT 0,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS questionnaire_templates (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    questions jsonb NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, name, version)
);

CREATE TABLE IF NOT EXISTS questionnaire_packages (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    template_id text NOT NULL,
    package_id text,
    product_id text,
    release_id text,
    responses jsonb NOT NULL,
    manifest_hash text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS commercial_collectors (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    version text NOT NULL,
    manifest_hash text NOT NULL,
    allowed_scopes text[] NOT NULL DEFAULT '{}',
    status text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, provider, name, version)
);

CREATE INDEX IF NOT EXISTS organizations_tenant_idx ON organizations (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS human_users_tenant_status_idx ON human_users (tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS role_bindings_tenant_subject_idx ON role_bindings (tenant_id, subject_type, subject_id);
CREATE INDEX IF NOT EXISTS sso_providers_tenant_idx ON sso_providers (tenant_id, type, created_at);
CREATE INDEX IF NOT EXISTS user_identity_links_tenant_user_idx ON user_identity_links (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS sso_sessions_tenant_user_idx ON sso_sessions (tenant_id, user_id, expires_at);
CREATE INDEX IF NOT EXISTS legal_holds_tenant_scope_idx ON legal_holds (tenant_id, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS retention_overrides_tenant_scope_idx ON retention_overrides (tenant_id, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS customer_portal_access_tenant_package_idx ON customer_portal_access (tenant_id, package_id);
CREATE INDEX IF NOT EXISTS questionnaire_packages_tenant_release_idx ON questionnaire_packages (tenant_id, release_id, created_at);
CREATE INDEX IF NOT EXISTS commercial_collectors_tenant_provider_idx ON commercial_collectors (tenant_id, provider, created_at);
