DROP INDEX IF EXISTS signing_keys_one_active_provider_per_tenant;

ALTER TABLE signing_keys
  DROP COLUMN IF EXISTS compromised_at,
  DROP COLUMN IF EXISTS historical_validity_policy,
  DROP COLUMN IF EXISTS revocation_semantics,
  DROP COLUMN IF EXISTS revocation_reason,
  DROP COLUMN IF EXISTS valid_until,
  DROP COLUMN IF EXISTS valid_from,
  DROP COLUMN IF EXISTS public_key_fingerprint,
  DROP COLUMN IF EXISTS provider,
  DROP COLUMN IF EXISTS version;
