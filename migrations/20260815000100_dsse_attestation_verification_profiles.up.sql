ALTER TABLE dsse_trust_roots
    ADD COLUMN IF NOT EXISTS allowed_predicate_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS expected_builder_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS required_claims jsonb NOT NULL DEFAULT '[]'::jsonb;

-- Legacy roots have no immutable policy and are intentionally not eligible for
-- the EVY-603 trusted-attestation profile. They remain auditable records.
UPDATE dsse_trust_roots
SET status = 'legacy_untrusted'
WHERE schema_version <> 'dsse-trust-root.v2.0.0'
   OR jsonb_array_length(allowed_predicate_types) = 0
   OR jsonb_array_length(expected_builder_ids) = 0
   OR jsonb_array_length(required_claims) = 0;
