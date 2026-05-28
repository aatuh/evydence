ALTER TABLE public_transparency_log_entries
    ADD COLUMN IF NOT EXISTS inclusion_root_hash text,
    ADD COLUMN IF NOT EXISTS inclusion_proof_hash text,
    ADD COLUMN IF NOT EXISTS inclusion_verified_at timestamptz,
    ADD COLUMN IF NOT EXISTS verification_checks jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS verification_limitations text[] NOT NULL DEFAULT '{}';
