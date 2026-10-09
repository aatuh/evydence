ALTER TABLE signing_keys
  ADD COLUMN IF NOT EXISTS version integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'local_ed25519',
  ADD COLUMN IF NOT EXISTS public_key_fingerprint text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS valid_from timestamptz,
  ADD COLUMN IF NOT EXISTS valid_until timestamptz,
  ADD COLUMN IF NOT EXISTS revocation_reason text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS revocation_semantics text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS historical_validity_policy text NOT NULL DEFAULT 'preserve',
  ADD COLUMN IF NOT EXISTS compromised_at timestamptz;

-- Legacy records retain their public material and historic validity. Their
-- version and start time are derived only from already persisted facts.
UPDATE signing_keys
SET provider = 'local_ed25519'
WHERE provider = '';

UPDATE signing_keys
SET valid_from = created_at
WHERE valid_from IS NULL;

UPDATE signing_keys
SET valid_until = revoked_at,
    revocation_semantics = 'ordinary'
WHERE status = 'revoked'
  AND revoked_at IS NOT NULL
  AND valid_until IS NULL;

WITH ranked AS (
  SELECT id,
         row_number() OVER (PARTITION BY tenant_id, provider ORDER BY created_at, id) AS lifecycle_version,
         row_number() OVER (PARTITION BY tenant_id, provider, status ORDER BY created_at DESC, id DESC) AS status_rank
  FROM signing_keys
)
UPDATE signing_keys AS key
SET version = ranked.lifecycle_version,
    status = CASE
      WHEN key.status = 'active' AND ranked.status_rank > 1 THEN 'retiring'
      ELSE key.status
    END
FROM ranked
WHERE key.id = ranked.id;

ALTER TABLE signing_keys
  ALTER COLUMN valid_from SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_active_provider_per_tenant
  ON signing_keys (tenant_id, provider)
  WHERE status = 'active';
