ALTER TABLE sso_providers
    ADD COLUMN IF NOT EXISTS trust_material_updated_at timestamptz;
