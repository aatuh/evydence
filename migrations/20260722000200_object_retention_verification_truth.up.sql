ALTER TABLE object_retention_policies
    ADD COLUMN IF NOT EXISTS max_verification_age_hours integer NOT NULL DEFAULT 24,
    ADD COLUMN IF NOT EXISTS verification_provider text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS verification_bucket text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS verification_mode text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS verification_retention_days integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS verification_legal_hold boolean,
    ADD COLUMN IF NOT EXISTS verification_observed_at timestamptz,
    ADD COLUMN IF NOT EXISTS verification_expires_at timestamptz;

UPDATE object_retention_policies
SET status = CASE
        WHEN status = 'verified' THEN 'not_verified'
        ELSE status
    END,
    verification_limitations = array_append(
        verification_limitations,
        'Legacy retention verification did not record complete provider observation metadata and is not treated as current provider enforcement.'
    ),
    schema_version = 'object-retention-policy.v2.0.0'
WHERE schema_version <> 'object-retention-policy.v2.0.0';
