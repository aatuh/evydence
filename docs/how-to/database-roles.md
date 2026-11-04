# Separate Migration And Runtime Database Roles

This how-to is for an operator rehearsing a dedicated PostgreSQL schema from a
verified source checkout. It covers database permissions, not API authorization,
tenant isolation, provider credentials or independent audit retention.

The executable policy is [`deploy/postgres/runtime-role.sql`](../../deploy/postgres/runtime-role.sql).
It grants ordinary table reads/writes, view reads and sequence use to a runtime
role. Migration records are read-only to that role; compatibility snapshot/index
tables are inaccessible. Schema changes and migration-record writes remain with
the migration owner for this role boundary. Existing application checks still enforce tenant and
append-only business rules; these grants do not enforce those rules themselves.

This is a manual migration/grant procedure. The current Helm hook and Compose
migration service do not execute this grant phase. Their automated role setup
and grant integration remain in EVY-1206. Do not switch those deployment profiles
to these credentials until that integration has been configured and verified.

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
Create a separate `evydence-migrator` libpq service for the grant command below.
The SQL policy creates no users, passwords or ownership transfers.

An existing administrator-owned or shared schema needs a rehearsed ownership
transfer or restore before adopting this profile. Review that against a paired
database/object backup. The policy refuses mismatched ownership; it does not
rewrite old migration principals, backfill unknown checksums or move data.
Verified adoption automation remains in EVY-1206.

## Run The Migration And Grant Phases

1. Stop API and worker processes and let them drain, following the
   [upgrade runbook](../runbooks/upgrade.md#upgrade).
2. Run the explicit-target, checksum-verified migration command from that
   runbook using the migration identity. Retain its result and execution history.
3. From the verified checkout root, apply the role policy as that same identity:

   ```sh
   psql "service=evydence-migrator options='-c search_path=evydence -c evydence.runtime_role=evydence_runtime -c lock_timeout=5000 -c statement_timeout=30000'" \
     --no-psqlrc --set=ON_ERROR_STOP=1 --file=deploy/postgres/runtime-role.sql
   ```

4. Check the grants before starting daemons with the runtime connection. For
   these example names, run the following through a protected operator session:

   ```sql
   SELECT has_schema_privilege('evydence_runtime', 'evydence', 'USAGE') AS can_use_schema,
          has_schema_privilege('evydence_runtime', 'evydence', 'CREATE') AS can_create;
   SELECT has_table_privilege('evydence_runtime', 'evydence.schema_migrations', 'SELECT') AS can_check_versions,
          has_table_privilege('evydence_runtime', 'evydence.schema_migrations', 'INSERT') AS can_record_version,
          has_table_privilege('evydence_runtime', 'evydence.schema_migrations', 'UPDATE') AS can_rewrite_version;
   ```

   Expected results are `true, false` and `true, false, false`. These spot checks
   are not a complete database permission audit. Preserve the migration command
   result, grant-command exit status and protected operator change record.
5. Start daemons and verify readiness and representative application work. Repeat
   the grant phase after each upgrade: new tables deliberately receive no
   automatic runtime grants before this policy runs.

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
go test ./internal/adapters/postgres -run '^TestMigrationDatabaseRoleProfile' -count=1 -timeout=120s
```

It requires `EVYDENCE_TEST_DATABASE_URL` pointing at a disposable test database
whose administrator can create isolated roles and schemas. It tests actual
separate login connections and the committed policy, including ordinary writes,
read-only migration checks, denied metadata/DDL operations, memberships,
revocation, quoted identifiers, dependent-grant rollback and the current schema.
Missing test configuration produces skips, not database-role evidence. Use the
host's RAM gate for this live fixture/test operation.

Migration execution checksums and authenticated principals remain in
`schema_migrations`. The grant script adds no durable audit event of its own;
retain its operator record. Automatic grant execution, durable operation-level
audit and deployment adoption remain incomplete. These local role tests do not
verify a deployed provider, a live cluster or protection against the schema
owner or a database administrator.
