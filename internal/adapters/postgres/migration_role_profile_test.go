package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type migrationRoleFixture struct {
	t                      *testing.T
	ctx                    context.Context
	admin                  *pgx.Conn
	schema, owner, runtime string
	migrator, application  *Store
	extraRoles             []string
}

func newMigrationRoleFixture(t *testing.T, quoted bool) *migrationRoleFixture {
	t.Helper()
	raw := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		cancel()
		t.Fatal("cannot open role-profile fixture administrator")
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	f := &migrationRoleFixture{t: t, ctx: ctx, admin: admin,
		schema: "evy_role_schema_" + suffix, owner: "evy_role_owner_" + suffix, runtime: "evy_role_runtime_" + suffix}
	if quoted {
		f.schema, f.owner, f.runtime = "evy schema '"+suffix, "evy owner \""+suffix, "evy runtime \""+suffix
	}
	var created []string
	schemaCreated := false
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer stop()
		for _, store := range []*Store{f.application, f.migrator} {
			if store != nil {
				store.Close()
			}
		}
		if schemaCreated {
			if _, err := admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" CASCADE"); err != nil {
				t.Error("cannot remove owned role-profile schema")
			}
		}
		created = append(created, f.extraRoles...)
		for _, role := range created {
			// These unique roles were created by this fixture only. Remove their
			// database-local grants before dropping them; no external role is used.
			if _, err := admin.Exec(cleanup, "DROP OWNED BY "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Error("cannot remove owned role-profile grants")
			}
		}
		for i := len(created) - 1; i >= 0; i-- {
			if _, err := admin.Exec(cleanup, "DROP ROLE "+pgx.Identifier{created[i]}.Sanitize()); err != nil {
				t.Error("cannot remove owned role-profile role")
			}
		}
		if err := admin.Close(cleanup); err != nil {
			t.Error("cannot close role-profile administrator")
		}
	})
	passwords := map[string]string{f.owner: rand.Text(), f.runtime: rand.Text()}
	for _, role := range []string{f.owner, f.runtime} {
		var statement string
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',$1::text,$2::text)`, role, passwords[role]).Scan(&statement); err != nil {
			t.Fatal("cannot prepare owned fixture role")
		}
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("cannot create owned fixture role")
		}
		created = append(created, role)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" AUTHORIZATION "+pgx.Identifier{f.owner}.Sanitize()); err != nil {
		t.Fatal("cannot create owned role-profile schema")
	}
	schemaCreated = true
	open := func(role string) *Store {
		config, err := pgxpool.ParseConfig(raw)
		if err != nil {
			t.Fatal("cannot prepare role-profile connection")
		}
		config.ConnConfig.User, config.ConnConfig.Password = role, passwords[role]
		config.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{f.schema}.Sanitize()
		config.MaxConns, config.MinConns, config.MinIdleConns = 2, 0, 0
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal("cannot open role-profile pool")
		}
		return &Store{pool: pool}
	}
	f.migrator, f.application = open(f.owner), open(f.runtime)
	return f
}

func (f *migrationRoleFixture) profile(ctx context.Context, store *Store, role string) error {
	f.t.Helper()
	body, err := os.ReadFile("../../../deploy/postgres/runtime-role.sql")
	if err != nil {
		f.t.Fatal("committed runtime role profile is missing")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT pg_catalog.set_config('evydence.runtime_role',$1,true)`, role); err == nil {
		_, err = tx.Exec(ctx, string(body))
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func requireRoleDenied(t *testing.T, err error) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "42501" {
		t.Fatal("database role did not reject the unauthorized operation with insufficient_privilege")
	}
}

func (f *migrationRoleFixture) migrate() string {
	f.t.Helper()
	dir := f.t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.up.sql"), []byte("CREATE TABLE business_records(id integer PRIMARY KEY, value text NOT NULL);"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if count, err := f.migrator.ApplyMigrations(f.ctx, dir); err != nil || count != 1 {
		f.t.Fatal("role fixture migration failed")
	}
	return dir
}

func TestMigrationDatabaseRoleProfileSeparatesDDLAndRuntimeWork(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	dir := f.migrate()
	if _, err := f.migrator.pool.Exec(f.ctx, "GRANT ALL ON SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" TO "+pgx.Identifier{f.runtime}.Sanitize()+"; GRANT ALL ON ALL TABLES IN SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" TO "+pgx.Identifier{f.runtime}.Sanitize()); err != nil {
		t.Fatal("cannot configure the pre-profile broad runtime grant")
	}
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal("role profile rejected the dedicated schema owner")
	}
	for _, statement := range []string{
		"CREATE TABLE unauthorized_runtime_ddl(id integer)",
		"ALTER TABLE business_records ADD COLUMN unauthorized integer",
		"DROP TABLE business_records",
		"INSERT INTO schema_migrations(version)VALUES('unauthorized')",
		"UPDATE schema_migrations SET checksum_sha256=repeat('b',64)",
		"DELETE FROM schema_migrations", "TRUNCATE schema_migrations",
		"TRUNCATE business_records",
	} {
		_, err := f.application.pool.Exec(f.ctx, statement)
		requireRoleDenied(t, err)
	}
	if _, err := f.application.pool.Exec(f.ctx, "INSERT INTO business_records VALUES(1,'original'); UPDATE business_records SET value='changed' WHERE id=1"); err != nil {
		t.Fatal("runtime role lost ordinary business writes")
	}
	var value string
	if err := f.application.pool.QueryRow(f.ctx, "SELECT value FROM business_records WHERE id=1").Scan(&value); err != nil || value != "changed" {
		t.Fatal("runtime role lost ordinary reads")
	}
	if err := f.application.RequireNoPendingMigrations(f.ctx, dir); err != nil {
		t.Fatal("runtime role could not perform the read-only migration check")
	}
	if err := os.WriteFile(filepath.Join(dir, "b.up.sql"), []byte("CREATE TABLE next_business_record(id integer);"), 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := f.application.ApplyMigrations(f.ctx, dir)
	if count != 0 {
		t.Fatal("runtime role executed a migration")
	}
	requireRoleDenied(t, err)
	if count, err := f.migrator.ApplyMigrations(f.ctx, dir); err != nil || count != 1 {
		t.Fatal("dedicated migrator could not upgrade after runtime grants")
	}
	_, err = f.application.pool.Exec(f.ctx, "INSERT INTO next_business_record VALUES(1)")
	requireRoleDenied(t, err)
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal("cannot refresh runtime grants after an upgrade")
	}
	if _, err := f.application.pool.Exec(f.ctx, "INSERT INTO next_business_record VALUES(1)"); err != nil {
		t.Fatal("refreshed role profile omitted new business tables")
	}
	var principal string
	if err := f.application.pool.QueryRow(f.ctx, "SELECT applied_by::text FROM schema_migrations WHERE version='b'").Scan(&principal); err != nil || principal != f.owner {
		t.Fatal("migration provenance lost the authenticated migrator identity")
	}
	if _, err := f.migrator.pool.Exec(f.ctx, "REVOKE INSERT ON business_records FROM "+pgx.Identifier{f.runtime}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	_, err = f.application.pool.Exec(f.ctx, "INSERT INTO business_records VALUES(2,'revoked')")
	requireRoleDenied(t, err)
}

func TestMigrationDatabaseRoleProfileRejectsUnsafeAuthority(t *testing.T) {
	for _, scenario := range []string{"runtime_caller", "same_role", "missing_role", "empty_role", "oversized_role", "superuser", "create_role", "create_database", "replication", "bypass_rls", "no_login", "owner_superuser", "membership", "noinherit_membership", "runtime_owns_table", "foreign_owner", "default_table_grant", "global_default_table_grant"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMigrationRoleFixture(t, false)
			f.migrate()
			store, role := f.migrator, f.runtime
			identifier := pgx.Identifier{f.runtime}.Sanitize()
			switch scenario {
			case "runtime_caller":
				if _, err := f.migrator.pool.Exec(f.ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" TO "+identifier); err != nil {
					t.Fatal(err)
				}
				store = f.application
			case "same_role":
				role = f.owner
			case "missing_role":
				role = "nonexistent_" + fmt.Sprint(time.Now().UnixNano())
			case "empty_role":
				role = ""
			case "oversized_role":
				role = fmt.Sprintf("%064d", 0)
			case "superuser":
				if _, err := f.admin.Exec(f.ctx, "ALTER ROLE "+identifier+" SUPERUSER"); err != nil {
					t.Fatal(err)
				}
			case "create_role":
				if _, err := f.admin.Exec(f.ctx, "ALTER ROLE "+identifier+" CREATEROLE"); err != nil {
					t.Fatal(err)
				}
			case "create_database", "replication", "bypass_rls", "no_login":
				attribute := map[string]string{"create_database": "CREATEDB", "replication": "REPLICATION", "bypass_rls": "BYPASSRLS", "no_login": "NOLOGIN"}[scenario]
				if _, err := f.admin.Exec(f.ctx, "ALTER ROLE "+identifier+" "+attribute); err != nil {
					t.Fatal(err)
				}
			case "owner_superuser":
				if _, err := f.admin.Exec(f.ctx, "ALTER ROLE "+pgx.Identifier{f.owner}.Sanitize()+" SUPERUSER"); err != nil {
					t.Fatal(err)
				}
			case "membership", "noinherit_membership":
				if _, err := f.admin.Exec(f.ctx, "GRANT "+pgx.Identifier{f.owner}.Sanitize()+" TO "+identifier); err != nil {
					t.Fatal(err)
				}
				if scenario == "noinherit_membership" {
					if _, err := f.admin.Exec(f.ctx, "ALTER ROLE "+identifier+" NOINHERIT"); err != nil {
						t.Fatal(err)
					}
				}
			case "runtime_owns_table":
				if _, err := f.admin.Exec(f.ctx, "ALTER TABLE "+pgx.Identifier{f.schema, "business_records"}.Sanitize()+" OWNER TO "+identifier); err != nil {
					t.Fatal(err)
				}
			case "foreign_owner":
				if _, err := f.admin.Exec(f.ctx, "CREATE TABLE "+pgx.Identifier{f.schema, "foreign_owned_record"}.Sanitize()+"(id integer)"); err != nil {
					t.Fatal(err)
				}
			case "default_table_grant":
				if _, err := f.migrator.pool.Exec(f.ctx, "ALTER DEFAULT PRIVILEGES IN SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" GRANT SELECT ON TABLES TO "+identifier); err != nil {
					t.Fatal(err)
				}
			case "global_default_table_grant":
				if _, err := f.migrator.pool.Exec(f.ctx, "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO "+identifier); err != nil {
					t.Fatal(err)
				}
			}
			acl := func() string {
				var value string
				if err := f.admin.QueryRow(f.ctx, `SELECT COALESCE(relacl::text,'') FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass($1)`, pgx.Identifier{f.schema, "schema_migrations"}.Sanitize()).Scan(&value); err != nil {
					t.Fatal("cannot inspect migration-record grants")
				}
				return value
			}
			before := acl()
			requireRoleDenied(t, f.profile(f.ctx, store, role))
			if after := acl(); after != before {
				t.Fatal("rejected role profile changed migration-record grants")
			}
		})
	}
}

func TestMigrationDatabaseRoleProfileQuotesRoleAndSchemaNames(t *testing.T) {
	f := newMigrationRoleFixture(t, true)
	f.migrate()
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal("quoted schema and role names did not receive scoped grants")
	}
	if _, err := f.application.pool.Exec(f.ctx, "INSERT INTO business_records VALUES(1,'quoted')"); err != nil {
		t.Fatal("quoted runtime role did not receive business grants")
	}
	var current string
	if err := f.application.pool.QueryRow(f.ctx, "SELECT session_user::text").Scan(&current); err != nil || current != f.runtime {
		t.Fatal("test did not connect as its dedicated runtime identity")
	}
}

func TestMigrationDatabaseRoleProfileRevokesColumnLevelMetadataWrites(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	f.migrate()
	if _, err := f.migrator.pool.Exec(f.ctx, "GRANT INSERT(version), UPDATE(checksum_sha256) ON schema_migrations TO "+pgx.Identifier{f.runtime}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal("cannot apply runtime role profile")
	}
	for _, statement := range []string{"INSERT INTO schema_migrations(version)VALUES('column_grant')", "UPDATE schema_migrations SET checksum_sha256=repeat('b',64)"} {
		_, err := f.application.pool.Exec(f.ctx, statement)
		requireRoleDenied(t, err)
	}
}

func TestMigrationDatabaseRoleProfilePreservesDependentGrantsAtomically(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	f.migrate()
	if _, err := f.migrator.pool.Exec(f.ctx, "GRANT USAGE,CREATE ON SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" TO "+pgx.Identifier{f.runtime}.Sanitize()+"; GRANT SELECT ON business_records TO "+pgx.Identifier{f.runtime}.Sanitize()+" WITH GRANT OPTION"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.application.pool.Exec(f.ctx, "GRANT SELECT ON business_records TO PUBLIC"); err != nil {
		t.Fatal(err)
	}
	acl := func() string {
		var value string
		if err := f.admin.QueryRow(f.ctx, `SELECT nspacl::text FROM pg_catalog.pg_namespace WHERE nspname=$1`, f.schema).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := acl()
	var postgresError *pgconn.PgError
	if err := f.profile(f.ctx, f.migrator, f.runtime); !errors.As(err, &postgresError) || postgresError.Code != "2BP01" {
		t.Fatal("role profile silently removed dependent grants")
	}
	if after := acl(); after != before {
		t.Fatal("failed grant revocation left partial schema permissions")
	}
}

func TestMigrationDatabaseRoleProfileSupportsCommittedSchema(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	if _, err := f.migrator.ApplyMigrations(f.ctx, "../../../migrations"); err != nil {
		t.Fatal("dedicated migrator cannot apply the current schema")
	}
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal("runtime role profile does not support the current schema")
	}
	if _, err := f.application.pool.Exec(f.ctx, "INSERT INTO tenants(id,name)VALUES('runtime_role_tenant','Runtime role'); UPDATE tenants SET name='Changed' WHERE id='runtime_role_tenant'"); err != nil {
		t.Fatal("runtime role cannot perform ordinary application persistence")
	}
	if err := f.application.RequireNoPendingMigrations(f.ctx, "../../../migrations"); err != nil {
		t.Fatal("runtime role cannot validate the current schema read-only")
	}
	for _, table := range []string{"ledger_state", "resource_index"} {
		_, err := f.application.pool.Exec(f.ctx, "SELECT * FROM "+pgx.Identifier{table}.Sanitize()+" LIMIT 1")
		requireRoleDenied(t, err)
	}
}

func TestMigrationDatabaseRoleProfilePreservesInvokerTriggersViewsAndSequences(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	f.migrate()
	if _, err := f.migrator.pool.Exec(f.ctx, `CREATE FUNCTION normalize_business_record() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN NEW.value := lower(NEW.value); RETURN NEW; END $body$;
CREATE TRIGGER normalize_business_record BEFORE INSERT ON business_records FOR EACH ROW EXECUTE FUNCTION normalize_business_record();
CREATE VIEW business_view AS SELECT value FROM business_records;
CREATE SEQUENCE business_sequence`); err != nil {
		t.Fatal("cannot prepare invoker-trigger fixture")
	}
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal("cannot apply runtime role profile to invoker trigger")
	}
	if _, err := f.application.pool.Exec(f.ctx, "INSERT INTO business_records VALUES(1,'UPPER')"); err != nil {
		t.Fatal("runtime grants broke an invoker trigger")
	}
	var value string
	if err := f.application.pool.QueryRow(f.ctx, "SELECT value FROM business_view").Scan(&value); err != nil || value != "upper" {
		t.Fatal("runtime role cannot read its triggered projection")
	}
	var sequence int64
	if err := f.application.pool.QueryRow(f.ctx, "SELECT nextval('business_sequence')").Scan(&sequence); err != nil || sequence != 1 {
		t.Fatal("runtime role cannot use a business sequence")
	}
	for _, statement := range []string{"INSERT INTO business_view VALUES('view-write')", "SELECT setval('business_sequence',100)"} {
		_, err := f.application.pool.Exec(f.ctx, statement)
		requireRoleDenied(t, err)
	}
}

func TestMigrationDatabaseRoleProfileLeavesOtherSchemasUnchanged(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	f.migrate()
	other := f.schema + "_other"
	if _, err := f.admin.Exec(f.ctx, "CREATE SCHEMA "+pgx.Identifier{other}.Sanitize()+" AUTHORIZATION "+pgx.Identifier{f.owner}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
		defer cancel()
		if _, err := f.admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{other}.Sanitize()+" CASCADE"); err != nil {
			t.Error("cannot remove separate schema fixture")
		}
	})
	if _, err := f.migrator.pool.Exec(f.ctx, "CREATE TABLE "+pgx.Identifier{other, "other_records"}.Sanitize()+"(id integer); GRANT SELECT,INSERT ON "+pgx.Identifier{other, "other_records"}.Sanitize()+" TO "+pgx.Identifier{f.runtime}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	acl := func() string {
		var value string
		if err := f.admin.QueryRow(f.ctx, `SELECT relacl::text FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass($1)`, pgx.Identifier{other, "other_records"}.Sanitize()).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := acl()
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal("cannot apply scoped runtime role profile")
	}
	if after := acl(); after != before {
		t.Fatal("runtime role profile changed another schema's grants")
	}
}

func TestMigrationDatabaseRoleProfileCannotLeaveOtherGrantorMetadataWrites(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	f.migrate()
	grantor := "evy_role_grantor_" + fmt.Sprint(time.Now().UnixNano())
	if _, err := f.admin.Exec(f.ctx, "CREATE ROLE "+pgx.Identifier{grantor}.Sanitize()+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	f.extraRoles = append(f.extraRoles, grantor)
	if _, err := f.migrator.pool.Exec(f.ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" TO "+pgx.Identifier{grantor}.Sanitize()+"; GRANT UPDATE(checksum_sha256) ON schema_migrations TO "+pgx.Identifier{grantor}.Sanitize()+" WITH GRANT OPTION"); err != nil {
		t.Fatal(err)
	}
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(f.ctx, "SET LOCAL ROLE "+pgx.Identifier{grantor}.Sanitize()+"; GRANT UPDATE(checksum_sha256) ON "+pgx.Identifier{f.schema, "schema_migrations"}.Sanitize()+" TO "+pgx.Identifier{f.runtime}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	acl := func() string {
		var value string
		if err := f.admin.QueryRow(f.ctx, `SELECT nspacl::text FROM pg_catalog.pg_namespace WHERE nspname=$1`, f.schema).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := acl()
	err = f.profile(f.ctx, f.migrator, f.runtime)
	if err != nil {
		// A grant graph requiring collateral revocation must fail closed.
		var postgresError *pgconn.PgError
		if !errors.As(err, &postgresError) || (postgresError.Code != "42501" && postgresError.Code != "2BP01") {
			t.Fatal("unexpected role-profile failure")
		}
		if after := acl(); after != before {
			t.Fatal("residual-grant rejection left partial schema grants")
		}
		return
	}
	_, err = f.application.pool.Exec(f.ctx, "UPDATE schema_migrations SET checksum_sha256=repeat('c',64)")
	requireRoleDenied(t, err)
}
