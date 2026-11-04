-- Operational migration execution metadata. Earlier rows remain unknown:
-- do not backfill hashes or principals for SQL this runner did not execute.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

ALTER TABLE schema_migrations
 ADD COLUMN IF NOT EXISTS checksum_sha256 text
  CHECK (checksum_sha256 IS NULL OR checksum_sha256 ~ '^[0-9a-f]{64}$'),
 ADD COLUMN IF NOT EXISTS applied_by name
  CHECK ((checksum_sha256 IS NULL) = (applied_by IS NULL));
