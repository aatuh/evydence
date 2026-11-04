DO $evydence$
BEGIN
 LOCK TABLE schema_migration_operations IN ACCESS EXCLUSIVE MODE;
 IF EXISTS (SELECT 1 FROM schema_migration_operations LIMIT 1) THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='recorded migration operations prevent downgrade';
 END IF;
 DROP TABLE schema_migration_operations;
END
$evydence$;
