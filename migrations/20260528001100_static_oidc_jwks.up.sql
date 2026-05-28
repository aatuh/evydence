ALTER TABLE sso_providers
    ADD COLUMN IF NOT EXISTS jwks jsonb NOT NULL DEFAULT '{}'::jsonb;
