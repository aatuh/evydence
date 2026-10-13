-- SAML SP configuration and finite login/replay state are operational records.
-- Existing providers, identity links, sessions and evidence remain unchanged.
CREATE TABLE saml_provider_bindings (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 1024),
    provider_id text NOT NULL CHECK (octet_length(provider_id) BETWEEN 1 AND 1024),
    recipient text NOT NULL CHECK (octet_length(recipient) BETWEEN 1 AND 4096),
    name_id_format text NOT NULL CHECK (name_id_format IN ('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified','urn:oasis:names:tc:SAML:2.0:nameid-format:persistent','urn:oasis:names:tc:SAML:2.0:nameid-format:transient','urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')),
    schema_version text NOT NULL CHECK (schema_version='saml-provider-binding.v1.0.0'),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= '0001-01-01 00:00:00+00' AND updated_at < '10000-01-01 00:00:00+00'),
    PRIMARY KEY (tenant_id,provider_id),
    FOREIGN KEY (tenant_id,provider_id) REFERENCES sso_providers(tenant_id,id)
);
CREATE TABLE saml_authentication_requests (
    id text PRIMARY KEY CHECK (id ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,127}$'),
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 1024),
    provider_id text NOT NULL CHECK (octet_length(provider_id) BETWEEN 1 AND 1024),
    delivery text NOT NULL CHECK (delivery IN ('api','browser')),
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 4096),
    audience text NOT NULL CHECK (octet_length(audience) BETWEEN 1 AND 4096),
    recipient text NOT NULL CHECK (octet_length(recipient) BETWEEN 1 AND 4096),
    name_id_format text NOT NULL CHECK (name_id_format IN ('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified','urn:oasis:names:tc:SAML:2.0:nameid-format:persistent','urn:oasis:names:tc:SAML:2.0:nameid-format:transient','urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')),
    trust_fingerprint text NOT NULL CHECK (trust_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    state_hash text NOT NULL UNIQUE CHECK (state_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    schema_version text NOT NULL CHECK (schema_version='saml-authentication-request.v1.0.0'),
    UNIQUE (tenant_id,provider_id,id),
    FOREIGN KEY (tenant_id,provider_id) REFERENCES saml_provider_bindings(tenant_id,provider_id),
    CHECK (isfinite(created_at) AND isfinite(expires_at) AND created_at >= '0001-01-01 00:00:00+00' AND expires_at < '10000-01-01 00:00:00+00'),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
    CHECK (consumed_at IS NULL OR (isfinite(consumed_at) AND consumed_at>=created_at AND consumed_at<expires_at))
);
CREATE INDEX saml_authentication_requests_owner_expiry ON saml_authentication_requests(tenant_id,provider_id,expires_at,id);
CREATE TABLE saml_assertion_consumptions (
    tenant_id text NOT NULL,
    provider_id text NOT NULL,
    assertion_hash text NOT NULL CHECK (assertion_hash ~ '^sha256:[0-9a-f]{64}$'),
    request_id text NOT NULL,
    consumed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    schema_version text NOT NULL CHECK (schema_version='saml-assertion-consumption.v1.0.0'),
    PRIMARY KEY (tenant_id,provider_id,assertion_hash),
    UNIQUE (tenant_id,provider_id,request_id),
    FOREIGN KEY (tenant_id,provider_id,request_id) REFERENCES saml_authentication_requests(tenant_id,provider_id,id),
    CHECK (isfinite(consumed_at) AND isfinite(expires_at) AND consumed_at >= '0001-01-01 00:00:00+00' AND expires_at < '10000-01-01 00:00:00+00'),
    CHECK (expires_at>consumed_at AND expires_at<=consumed_at+interval '6 minutes')
);
CREATE INDEX saml_assertion_consumptions_owner_expiry ON saml_assertion_consumptions(tenant_id,provider_id,expires_at,assertion_hash);
