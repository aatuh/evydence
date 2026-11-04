-- Apply after migrations, before starting daemons, on a dedicated schema.
-- Connect as its non-administrative migration owner. Supply search_path and
-- evydence.runtime_role as connection settings; this file creates no roles,
-- passwords or default grants and transfers no ownership. The DO statement is
-- atomic, including when a grant fails. The native runner uses a read-only
-- validation phase before bookkeeping/SQL and the grant phase under its lock.
-- Canonical source: internal/adapters/postgres/runtime_role.sql.
-- Regenerate the deployment copy with make migration-role-policy-generate.
DO $evydence_runtime_role$
DECLARE
    target_schema name := pg_catalog.current_schema();
    phase text := COALESCE(NULLIF(pg_catalog.current_setting('evydence.runtime_role_phase', true), ''), 'grant');
    runtime_name text := pg_catalog.current_setting('evydence.runtime_role', true);
    schema_id oid;
    migration_id oid;
    runtime_id oid;
    tracking_id oid;
    relation record;
BEGIN
    IF phase NOT IN ('validate', 'grant') OR target_schema IS NULL OR target_schema = 'information_schema'
       OR target_schema::text LIKE 'pg\_%' ESCAPE '\'
       OR runtime_name IS NULL OR pg_catalog.octet_length(runtime_name) NOT BETWEEN 1 AND 63
       OR current_user <> session_user THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'invalid Evydence runtime role profile';
    END IF;

    SELECT role.oid INTO migration_id FROM pg_catalog.pg_roles role WHERE role.rolname = session_user;
    SELECT role.oid INTO runtime_id FROM pg_catalog.pg_roles role WHERE role.rolname = runtime_name;
    SELECT namespace.oid INTO schema_id FROM pg_catalog.pg_namespace namespace
        WHERE namespace.nspname = target_schema AND namespace.nspowner = migration_id;
    IF runtime_id IS NULL OR schema_id IS NULL OR runtime_id = migration_id
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles role WHERE role.oid IN (runtime_id, migration_id)
           AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR role.rolcreaterole
                OR role.rolreplication OR role.rolbypassrls))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members membership
           WHERE membership.member IN (runtime_id, migration_id))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_database database
           WHERE database.datname = pg_catalog.current_database() AND database.datdba IN (runtime_id, migration_id))
       OR pg_catalog.has_database_privilege(runtime_id, pg_catalog.current_database(), 'CREATE')
       OR pg_catalog.has_database_privilege(migration_id, pg_catalog.current_database(), 'CREATE') THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evydence runtime role profile requires dedicated roles and schema ownership';
    END IF;

    SELECT entry.oid INTO tracking_id FROM pg_catalog.pg_class entry
        WHERE entry.relnamespace = schema_id AND entry.relname = 'schema_migrations'
          AND entry.relkind = 'r' AND entry.relowner = migration_id;
    IF (tracking_id IS NULL AND phase = 'grant')
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_class entry WHERE entry.relnamespace = schema_id
           AND entry.relname IN ('schema_migrations','schema_migration_operations')
           AND (entry.relkind <> 'r' OR entry.relowner <> migration_id))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_class entry WHERE entry.relnamespace = schema_id
           AND (entry.relowner <> migration_id OR entry.relkind NOT IN ('r', 'p', 'i', 'I', 'v', 'm', 'S')))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc routine WHERE routine.pronamespace = schema_id
           AND (routine.proowner <> migration_id OR routine.prosecdef OR routine.prokind <> 'f'))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_type entry WHERE entry.typnamespace = schema_id
           AND entry.typowner <> migration_id)
       OR (SELECT count(*) FROM (SELECT 1 FROM pg_catalog.pg_class entry
           WHERE entry.relnamespace = schema_id LIMIT 1025) bounded) > 1024
       OR (SELECT count(*) FROM (SELECT 1 FROM pg_catalog.pg_proc routine
           WHERE routine.pronamespace = schema_id LIMIT 257) bounded) > 256 THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evydence runtime role profile requires bounded migration-owned objects';
    END IF;

    -- A broad default table grant could expose future migration bookkeeping
    -- before this profile runs. Reject it instead of changing global defaults.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl defaults
        CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) grant_entry
        WHERE defaults.defaclrole = migration_id AND defaults.defaclobjtype = 'r'
          AND defaults.defaclnamespace IN (0, schema_id)
          AND grant_entry.grantee IN (0, runtime_id)) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evydence runtime role profile refuses broad default table grants';
    END IF;

    IF phase = 'validate' THEN
        RETURN;
    END IF;

    -- Never cascade revocations into another role's dependent grants. Such a
    -- dependency requires operator review and rolls back this entire statement.
    EXECUTE pg_catalog.format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC', target_schema);
    EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA %I FROM %I', target_schema, runtime_name);
    EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %I TO %I', target_schema, runtime_name);
    EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC, %I', target_schema, runtime_name);
    EXECUTE pg_catalog.format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM PUBLIC, %I', target_schema, runtime_name);
    EXECUTE pg_catalog.format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM PUBLIC, %I', target_schema, runtime_name);
    FOR relation IN SELECT entry.oid, entry.relname, entry.relkind FROM pg_catalog.pg_class entry
        WHERE entry.relnamespace = schema_id AND entry.relkind IN ('r', 'p', 'v', 'm', 'S')
        ORDER BY entry.oid
    LOOP
        IF relation.relname IN ('ledger_state', 'resource_index') THEN
            -- Production uses focused services, not compatibility snapshots.
            CONTINUE;
        ELSIF relation.relkind = 'S' THEN
            EXECUTE pg_catalog.format('GRANT USAGE, SELECT ON SEQUENCE %I.%I TO %I', target_schema, relation.relname, runtime_name);
        ELSIF relation.relname IN ('schema_migrations','schema_migration_operations') OR relation.relkind IN ('v', 'm') THEN
            EXECUTE pg_catalog.format('GRANT SELECT ON TABLE %I.%I TO %I', target_schema, relation.relname, runtime_name);
        ELSE
            EXECUTE pg_catalog.format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO %I', target_schema, relation.relname, runtime_name);
        END IF;
    END LOOP;

    -- REVOKE can leave a grant made by a different grantor. Never report
    -- success while such a path retains forbidden privileges. Reject the
    -- graph atomically instead of cascading into another role's grants.
    IF pg_catalog.has_schema_privilege(runtime_id, schema_id, 'CREATE')
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_class entry WHERE entry.relnamespace = schema_id
           AND entry.relname IN ('schema_migrations','schema_migration_operations')
           AND (pg_catalog.has_table_privilege(runtime_id, entry.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                OR pg_catalog.has_any_column_privilege(runtime_id, entry.oid, 'INSERT,UPDATE,REFERENCES')))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace namespace
           CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) grant_entry
           WHERE namespace.oid = schema_id AND
               ((grant_entry.grantee = 0 AND grant_entry.privilege_type = 'CREATE')
                OR (grant_entry.grantee = runtime_id AND
                    (grant_entry.is_grantable OR grant_entry.privilege_type <> 'USAGE'))))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_class entry
           CROSS JOIN LATERAL pg_catalog.aclexplode(entry.relacl) grant_entry
           WHERE entry.relnamespace = schema_id AND grant_entry.grantee IN (0, runtime_id)
               AND (grant_entry.grantee = 0 OR grant_entry.is_grantable
                    OR entry.relname IN ('ledger_state', 'resource_index')
                    OR (entry.relname IN ('schema_migrations','schema_migration_operations') AND grant_entry.privilege_type <> 'SELECT')
                    OR (entry.relkind IN ('v', 'm') AND grant_entry.privilege_type <> 'SELECT')
                    OR (entry.relkind = 'S' AND grant_entry.privilege_type NOT IN ('USAGE', 'SELECT'))
                    OR (entry.relkind IN ('r', 'p') AND grant_entry.privilege_type NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE'))))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute attribute
           JOIN pg_catalog.pg_class entry ON entry.oid = attribute.attrelid
           CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) grant_entry
           WHERE entry.relnamespace = schema_id AND grant_entry.grantee IN (0, runtime_id))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc routine
           CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) grant_entry
           WHERE routine.pronamespace = schema_id AND grant_entry.grantee IN (0, runtime_id)) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Evydence runtime role profile could not establish scoped privileges';
    END IF;
END
$evydence_runtime_role$;
