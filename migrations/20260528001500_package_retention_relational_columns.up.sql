ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS released_at timestamptz;

ALTER TABLE object_retention_policies
    ADD COLUMN IF NOT EXISTS verification_checks jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS verification_limitations text[] NOT NULL DEFAULT '{}';
