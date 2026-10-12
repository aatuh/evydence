ALTER TABLE cosign_verifications
    DROP COLUMN IF EXISTS verification_mode,
    DROP COLUMN IF EXISTS trust_root_version,
    DROP COLUMN IF EXISTS verifier_library_version;
