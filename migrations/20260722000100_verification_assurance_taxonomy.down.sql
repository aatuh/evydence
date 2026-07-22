ALTER TABLE provider_verifications
    DROP COLUMN IF EXISTS assurance_profile;

ALTER TABLE cosign_verifications
    DROP COLUMN IF EXISTS assurance_profile,
    DROP COLUMN IF EXISTS limitations;

ALTER TABLE verification_results
    DROP COLUMN IF EXISTS assurance_profile,
    DROP COLUMN IF EXISTS limitations,
    DROP COLUMN IF EXISTS schema_version;
