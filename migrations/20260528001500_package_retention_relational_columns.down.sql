ALTER TABLE object_retention_policies
    DROP COLUMN IF EXISTS verification_limitations,
    DROP COLUMN IF EXISTS verification_checks;

ALTER TABLE legal_holds
    DROP COLUMN IF EXISTS released_at;
