# Separate Migration And Runtime Database Roles

This how-to is for an operator rehearsing a dedicated PostgreSQL schema from a
verified source checkout. It covers database permissions, not API authorization,
tenant isolation, provider credentials or independent audit retention.

The native migration command embeds
[`internal/adapters/postgres/runtime_role.sql`](../../internal/adapters/postgres/runtime_role.sql).
Its checked operator copy is
[`deploy/postgres/runtime-role.sql`](../../deploy/postgres/runtime-role.sql).
It grants ordinary table reads/writes, view reads and sequence use to a runtime
role. Migration records are read-only to that role; compatibility snapshot/index
tables are inaccessible. Schema changes and migration-record writes remain with
the migration owner for this role boundary. Existing application checks still enforce tenant and
append-only business rules; these grants do not enforce those rules themselves.

Select `EVYDENCE_MIGRATION_RUNTIME_ROLE` on the migration command to validate
these identities, record the operation and apply grants under one schema lock.
The Helm hook exposes this as `migration.runtimeRole`; the production-like
Compose migration service passes the environment option through. Neither
deployment creates roles or transfers existing ownership. Configure separate
migration/runtime credentials before opting in; the base Compose database user
does not satisfy this dedicated-role profile.

## Prepare Dedicated Identities

Use a dedicated schema, not a schema shared with another application. Both roles
must be distinct login roles without memberships, superuser, database creation,
role administration, replication or RLS-bypass privileges. Neither may own the
database or have its `CREATE` privilege. The migration identity must own the
schema and all its objects. Foreign-owned objects, security-definer routines,
unsupported object kinds and broad default table grants are rejected.

For a new schema, connect through an operator-managed libpq service definition.
Keep service/password files private; see PostgreSQL's
[connection service files](https://www.postgresql.org/docs/16/libpq-pgservice.html)
and [password files](https://www.postgresql.org/docs/16/libpq-pgpass.html).
This example assumes the database is named `evydence`:

```sh
psql 'service=evydence-admin' --no-psqlrc --set=ON_ERROR_STOP=1
```

Enter these SQL and psql commands interactively. The password commands prompt
without putting values in command arguments or shell history:

```sql
CREATE ROLE evydence_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE evydence_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password evydence_migrator
\password evydence_runtime
GRANT CONNECT ON DATABASE evydence TO evydence_migrator, evydence_runtime;
CREATE SCHEMA evydence AUTHORIZATION evydence_migrator;
\quit
```

Configure the migrator and runtime connections with `search_path=evydence` and
their respective identities. Store each connection credential separately using
the [configuration and private-file contract](../reference/configuration.md).
Create a separate `evydence-migrator` libpq service for protected inspection or repair.
The SQL policy creates no users, passwords or ownership transfers.

An existing administrator-owned or shared schema needs a rehearsed ownership
transfer or restore before adopting this profile. Review that against a paired
database/object backup. The policy refuses mismatched ownership; it does not
rewrite old migration principals, backfill unknown checksums or move data.

## Run A Managed Migration

1. Stop API and worker processes and let them drain, following the
   [upgrade runbook](../runbooks/upgrade.md#upgrade).
2. Configure the migration command with the migration identity, then select the
   existing runtime role:

   ```sh
   export EVYDENCE_MIGRATION_RUNTIME_ROLE=evydence_runtime
   ```

   Run the explicit-target, checksum-verified command from the
   [upgrade runbook](../runbooks/upgrade.md#explicit-target-and-verified-inputs).
   Use the same selected image/policy for the job and daemons. Keep this option
   out of daemon environments; it is migration-only. The runner validates
   authority before creating bookkeeping tables, commits initial grants and a
   `started` audit row, applies each missing SQL file, then atomically commits
   final grants and a `succeeded` row before releasing the coordinator. A no-op
   migration still revalidates grants and records a new operation.
3. Inspect the bounded operation history through a protected migration-owner
   session, using the configured schema:

   ```sql
   SELECT sequence, operation_id, phase, target_version, runtime_role,
          performed_by, committed_migrations, policy_sha256, occurred_at
   FROM evydence.schema_migration_operations
   ORDER BY sequence DESC LIMIT 20;
   ```

   The latest row must be `succeeded` for the intended runtime identity, target
   and policy. `performed_by` comes from authenticated PostgreSQL `session_user`.
   `failed` preserves the known committed prefix; `uncertain` uses a null count
   when a commit outcome cannot be established. An interrupted connection may
   leave only `started`. Retain logs and operator records; these rows do not
   provide independent or administrator-proof retention.
4. Check the grants before starting daemons with the runtime connection. For
   these example names, run the following through a protected operator session:

   ```sql
   SELECT has_schema_privilege('evydence_runtime', 'evydence', 'USAGE') AS can_use_schema,
          has_schema_privilege('evydence_runtime', 'evydence', 'CREATE') AS can_create;
   SELECT has_table_privilege('evydence_runtime', 'evydence.schema_migrations', 'SELECT') AS can_check_versions,
          has_table_privilege('evydence_runtime', 'evydence.schema_migrations', 'INSERT') AS can_record_version,
          has_table_privilege('evydence_runtime', 'evydence.schema_migrations', 'UPDATE') AS can_rewrite_version;
   SELECT has_table_privilege('evydence_runtime', 'evydence.schema_migration_operations', 'SELECT') AS can_read_operations,
          has_table_privilege('evydence_runtime', 'evydence.schema_migration_operations', 'UPDATE') AS can_rewrite_operations;
   ```

   Expected results are `true, false`, `true, false, false` and `true, false`. These spot checks
   are not a complete database permission audit. Preserve the migration command
   result and protected operator change record.
5. Start daemons and verify readiness and representative application work. Startup
   and readiness use their held schema lease to require a successful operation
   matching their authenticated runtime identity, local catalog target and
   embedded policy digest. They also reject schema creation or migration-metadata
   write privileges. Repeat the managed command after each upgrade: new tables
   deliberately receive no automatic runtime grants before this policy runs.

Once an operation is recorded, ordinary migration calls cannot advance the
schema by omitting the runtime-role option. A failed final grant phase blocks
runtime startup even when all version rows exist. Reconcile the cause, review
recorded versions and checksums, then repeat the managed command. Never edit or
delete operation history to clear readiness. Applying the standalone SQL copy
can repair grants, but does not record a successful operation or clear an
interrupted marker; a managed retry is still required.

The policy changes only the selected schema's grants. It removes public object
privileges there and resets the selected runtime role's grants. It does not
change role attributes, memberships, database-wide grants or global defaults.
Other roles' dependent grants or residual forbidden grants cause an error and
atomic rollback rather than a cascading revocation. The final check includes
effective metadata permissions, column grants and grant options. Review those
dependencies before retrying; the script does not override them. Target schemas
are bounded to 1,024 catalog relations
and 256 routines.

## Repository Verification And Limits

The focused regression is:

```sh
go test ./internal/adapters/postgres -run '^(TestMigrationDatabaseRoleProfile|TestManagedMigration|TestMigrationOperation)' -count=1 -timeout=120s
```

It requires `EVYDENCE_TEST_DATABASE_URL` pointing at a disposable test database
whose administrator can create isolated roles and schemas. It tests actual
separate login connections and the committed policy, including ordinary writes,
read-only migration checks, denied metadata/DDL operations, memberships,
revocation, quoted identifiers, dependent-grant rollback and the current schema.
Missing test configuration produces skips, not database-role evidence. Use the
host's RAM gate for this live fixture/test operation.

Migration execution checksums and authenticated principals remain in
`schema_migrations`; operation events use `schema_migration_operations` and
schema version `migration-operation.v1`. Both are operational metadata outside
tenant evidence commitments. The additive audit migration refuses downgrade
once events exist. Run `make migration-role-policy-check` to check the exported
policy and versioned bootstrap DDL against their canonical sources; regenerate
the SQL copy with `make migration-role-policy-generate` after a policy change.
Role provisioning and existing-schema adoption remain operator-owned and need
their own rehearsal. These local role and native-command tests do not
verify a deployed provider, a live cluster or protection against the schema
owner or a database administrator.
