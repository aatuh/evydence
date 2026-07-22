ALTER TABLE object_retention_policies
    DROP COLUMN IF EXISTS verification_expires_at,
    DROP COLUMN IF EXISTS verification_observed_at,
    DROP COLUMN IF EXISTS verification_legal_hold,
    DROP COLUMN IF EXISTS verification_retention_days,
    DROP COLUMN IF EXISTS verification_mode,
    DROP COLUMN IF EXISTS verification_bucket,
    DROP COLUMN IF EXISTS verification_provider,
    DROP COLUMN IF EXISTS max_verification_age_hours;
