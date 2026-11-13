-- Never erase stored execution provenance through a downgrade.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM schema_migrations WHERE checksum_sha256 IS NOT NULL OR applied_by IS NOT NULL) THEN
  RAISE EXCEPTION 'cannot remove recorded migration execution metadata' USING ERRCODE = '55000';
 END IF;
END
$$;

ALTER TABLE schema_migrations
 DROP COLUMN checksum_sha256,
 DROP COLUMN applied_by;
