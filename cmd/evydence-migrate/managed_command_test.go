package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func dedicatedCommandRoles(t *testing.T, f *migrationCommandFixture) (string, string, string) {
	t.Helper()
	owner, role := "PRIVATE_OWNER_"+rand.Text(), "PRIVATE_RUNTIME_"+rand.Text()
	passwords := map[string]string{owner: rand.Text(), role: rand.Text()}
	for _, name := range []string{owner, role} {
		var statement string
		if err := f.admin.QueryRow(f.ctx, `SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',$1::text,$2::text)`, name, passwords[name]).Scan(&statement); err != nil {
			t.Fatal("cannot prepare owned command role")
		}
		if _, err := f.admin.Exec(f.ctx, statement); err != nil {
			t.Fatal("cannot create owned command role")
		}
		f.ownedRoles = append(f.ownedRoles, name)
	}
	if _, err := f.admin.Exec(f.ctx, "ALTER SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" OWNER TO "+pgx.Identifier{owner}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(f.databaseURL)
	if err != nil {
		t.Fatal("cannot prepare private command connection")
	}
	parsed.User = url.UserPassword(owner, passwords[owner])
	f.databaseURL = parsed.String()
	parsed.User = url.UserPassword(role, passwords[role])
	return owner, role, parsed.String()
}

func TestMigrationCommandManagedRoleGrantsAndAudits(t *testing.T) {
	f := newMigrationCommandFixture(t, map[string]string{"a.up.sql": "CREATE TABLE managed_command_effects(id integer);"})
	owner, role, runtimeURL := dedicatedCommandRoles(t, f)
	var output bytes.Buffer
	for range 2 {
		if err := runMigrationProcess(f.ctx, f.environment(t, "a", "30", "EVYDENCE_MIGRATION_RUNTIME_ROLE="+role), &output, applyMigrations); err != nil {
			t.Fatal("native managed command failed", err)
		}
	}
	if strings.Contains(output.String(), "PRIVATE") || !strings.Contains(output.String(), `"msg":"audit"`) {
		t.Fatal("managed command leaked private role configuration or omitted audit correlation")
	}
	runtime, err := postgres.Open(f.ctx, runtimeURL)
	if err != nil {
		t.Fatal("cannot open granted runtime store")
	}
	defer runtime.Close()
	if err := runtime.CheckMigrationState(f.ctx, f.dir); err != nil {
		t.Fatal("native managed command did not prepare role-bound runtime", err)
	}
	connection, err := pgx.Connect(f.ctx, runtimeURL)
	if err != nil {
		t.Fatal("cannot open runtime persistence probe")
	}
	defer func() {
		if err := connection.Close(f.ctx); err != nil {
			t.Error("cannot close runtime persistence probe")
		}
	}()
	if _, err := connection.Exec(f.ctx, "INSERT INTO managed_command_effects VALUES(1)"); err != nil {
		t.Fatal("native grant phase did not enable business writes")
	}
	var records, operations int
	var correct bool
	statement := fmt.Sprintf(`SELECT count(*),count(DISTINCT operation_id),bool_and(performed_by::text=$1 AND runtime_role::text=$2) FROM %s`, pgx.Identifier{f.schema, "schema_migration_operations"}.Sanitize())
	if err := f.admin.QueryRow(f.ctx, statement, owner, role).Scan(&records, &operations, &correct); err != nil || records != 4 || operations != 2 || !correct {
		t.Fatal("native command did not record two authenticated append-only operations")
	}
}
