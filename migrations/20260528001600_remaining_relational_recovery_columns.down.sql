ALTER TABLE public_transparency_log_entries
    DROP COLUMN IF EXISTS verification_limitations,
    DROP COLUMN IF EXISTS verification_checks,
    DROP COLUMN IF EXISTS inclusion_verified_at,
    DROP COLUMN IF EXISTS inclusion_proof_hash,
    DROP COLUMN IF EXISTS inclusion_root_hash;
