ALTER TABLE dsse_trust_roots
    DROP COLUMN IF EXISTS required_claims,
    DROP COLUMN IF EXISTS expected_builder_ids,
    DROP COLUMN IF EXISTS allowed_predicate_types;
