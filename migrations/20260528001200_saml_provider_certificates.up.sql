ALTER TABLE sso_providers
    ADD COLUMN IF NOT EXISTS saml_signing_certificates jsonb NOT NULL DEFAULT '[]'::jsonb;
