ALTER TABLE cosign_verifications
    ADD COLUMN IF NOT EXISTS verifier_library_version text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS trust_root_version text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS verification_mode text NOT NULL DEFAULT '';
