-- Public provider/session history is unchanged. Login state contains only
-- hashes and short-lived operational metadata, never raw nonce/state values.
ALTER TABLE sso_providers ADD CONSTRAINT sso_providers_oidc_request_owner UNIQUE (tenant_id,id);
CREATE TABLE oidc_authentication_requests (
    id text PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 1024),
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 1024),
    provider_id text NOT NULL CHECK (octet_length(provider_id) BETWEEN 1 AND 1024),
    delivery text NOT NULL CHECK (delivery IN ('api','browser')),
    trust_fingerprint text NOT NULL CHECK (trust_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    state_hash text NOT NULL UNIQUE CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    nonce_hash text NOT NULL UNIQUE CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    schema_version text NOT NULL CHECK (schema_version='oidc-authentication-request.v1.0.0'),
    FOREIGN KEY (tenant_id,provider_id) REFERENCES sso_providers(tenant_id,id),
    CHECK (state_hash<>nonce_hash),
    CHECK (isfinite(created_at) AND isfinite(expires_at) AND created_at >= '0001-01-01 00:00:00+00' AND expires_at < '10000-01-01 00:00:00+00'),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
    CHECK (consumed_at IS NULL OR (isfinite(consumed_at) AND consumed_at>=created_at AND consumed_at<expires_at))
);
CREATE INDEX oidc_authentication_requests_owner_expiry ON oidc_authentication_requests(tenant_id,provider_id,expires_at,id);
