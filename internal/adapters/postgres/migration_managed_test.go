package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestManagedMigrationAppliesPolicyAndAuditsAuthenticatedOperation(t *testing.T) {
	f := newMigrationRoleFixture(t, true)
	dir, checksums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "CREATE TABLE managed_records(id integer PRIMARY KEY);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "a", checksums)
	if err != nil {
		t.Fatal(err)
	}
	managed := plan.WithRuntimeRole(f.runtime)
	if plan.enforceRuntimeRole {
		t.Fatal("runtime-role selection mutated the original plan")
	}
	encoded, _ := json.Marshal(managed)
	if strings.Contains(string(encoded)+fmt.Sprintf("%v %#v", managed, managed), f.runtime) {
		t.Fatal("managed plan exposed private role selection")
	}
	for _, wanted := range []int{1, 0} {
		count, err := f.migrator.ApplyMigrationPlan(f.ctx, managed)
		if err != nil || count != wanted {
			t.Fatal("managed migration did not complete schema/grants", count, err)
		}
		if err := f.application.CheckMigrationState(f.ctx, dir); err != nil {
			t.Fatal("successful role-bound operation did not admit its runtime", err)
		}
	}
	if _, err := f.application.pool.Exec(f.ctx, "INSERT INTO managed_records VALUES(1)"); err != nil {
		t.Fatal("managed grants omitted application writes")
	}
	var events, operations int
	var actorOK, digestOK bool
	if err := f.migrator.pool.QueryRow(f.ctx, `SELECT count(*),count(DISTINCT operation_id),bool_and(performed_by=session_user),bool_and(policy_sha256=$1) FROM schema_migration_operations`, migrationChecksum(runtimeRolePolicySQL)).Scan(&events, &operations, &actorOK, &digestOK); err != nil || events != 4 || operations != 2 || !actorOK || !digestOK {
		t.Fatal("managed audit did not preserve two append-only authenticated operations", err)
	}
	_, err = f.application.pool.Exec(f.ctx, "UPDATE schema_migration_operations SET phase='succeeded'")
	requireRoleDenied(t, err)
}

func TestManagedMigrationRejectsAuthorityBeforeSchemaBookkeeping(t *testing.T) {
	for _, roleChoice := range []string{"same", "missing", "administrative"} {
		t.Run(roleChoice, func(t *testing.T) {
			f := newMigrationRoleFixture(t, false)
			role := f.runtime
			if roleChoice == "same" {
				role = f.owner
			}
			if roleChoice == "missing" {
				role = "missing_role"
			}
			if roleChoice == "administrative" {
				if _, err := f.admin.Exec(f.ctx, "ALTER ROLE "+pgx.Identifier{f.runtime}.Sanitize()+" CREATEROLE"); err != nil {
					t.Fatal(err)
				}
			}
			dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "CREATE TABLE forbidden_effect(id integer);"})
			plan, err := PrepareMigrationPlan(f.ctx, dir, "a", sums)
			if err != nil {
				t.Fatal(err)
			}
			count, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(role))
			if count != 0 || !errors.Is(err, ErrMigrationRuntimeRole) {
				t.Fatal("invalid authority reached managed SQL", count, err)
			}
			var relations int
			if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1`, f.schema).Scan(&relations); err != nil || relations != 0 {
				t.Fatal("rejected authority created schema bookkeeping")
			}
		})
	}
}

func TestManagedMigrationFailureRecordsPrefixAndBlocksUntilRepair(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "CREATE TABLE managed_records(id integer);", "b.up.sql": "INSERT INTO managed_records VALUES(1); SELECT 1/0;"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "b", sums)
	if err != nil {
		t.Fatal(err)
	}
	count, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime))
	if err == nil || count != 1 {
		t.Fatal("failed managed migration lost its committed prefix", count, err)
	}
	var phase string
	var committed int
	if err := f.migrator.pool.QueryRow(f.ctx, `SELECT phase,committed_migrations FROM schema_migration_operations ORDER BY sequence DESC LIMIT 1`).Scan(&phase, &committed); err != nil || phase != "failed" || committed != 1 {
		t.Fatal("failed operation was not durably recorded")
	}
	if err := f.application.CheckMigrationState(f.ctx, dir); err == nil {
		t.Fatal("failed operation admitted runtime")
	}
	if err := os.WriteFile(filepath.Join(dir, "b.up.sql"), []byte("INSERT INTO managed_records VALUES(2);"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Regenerate the operator checksum file for the reviewed pending fix only;
	// applied a remains byte-identical and its stored fingerprint is checked.
	var manifest strings.Builder
	for _, name := range []string{"a.up.sql", "b.up.sql"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%s  migrations/%s\n", migrationChecksum(string(body)), name)
	}
	if err := os.WriteFile(sums, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err = PrepareMigrationPlan(f.ctx, dir, "b", sums)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime)); count != 1 || err != nil {
		t.Fatal("reviewed pending fix could not recover managed operation", count, err)
	}
	if err := f.application.CheckMigrationState(f.ctx, dir); err != nil {
		t.Fatal("successful recovery retained failed runtime gate", err)
	}
}

func TestManagedMigrationCancellationPersistsTerminalOutcome(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT pg_sleep(2);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "a", sums)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 150*time.Millisecond)
	defer cancel()
	count, err := f.migrator.ApplyMigrationPlan(ctx, plan.WithRuntimeRole(f.runtime))
	if count != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("managed execution lost cancellation", count, err)
	}
	var phase string
	if err := f.migrator.pool.QueryRow(f.ctx, `SELECT phase FROM schema_migration_operations ORDER BY sequence DESC LIMIT 1`).Scan(&phase); err != nil || (phase != "failed" && phase != "started" && phase != "uncertain") {
		t.Fatal("canceled operation claimed success or lost its durable start")
	}
}

func TestMigrationRolePolicyArtifactsMatchCanonicalSources(t *testing.T) {
	artifact, err := os.ReadFile("../../../deploy/postgres/runtime-role.sql")
	if err != nil || string(artifact) != runtimeRolePolicySQL {
		t.Fatal("deployment runtime policy differs from embedded canonical SQL")
	}
	ddl, err := os.ReadFile("../../../migrations/20261104000100_migration_operation_audit.up.sql")
	if err != nil || strings.TrimSpace(string(ddl)) != strings.TrimSpace(fmt.Sprintf(migrationOperationSchemaSQL, "schema_migration_operations")+";") {
		t.Fatal("versioned operation DDL differs from bootstrap schema")
	}
}

func TestManagedMigrationCannotBeBypassedByOrdinaryRunner(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "CREATE TABLE managed_records(id integer);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "a", sums)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.up.sql"), []byte("CREATE TABLE bypassed_record(id integer);"), 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := f.migrator.ApplyMigrations(f.ctx, dir)
	if count != 0 || !errors.Is(err, ErrMigrationRuntimeRole) {
		t.Fatal("ordinary runner bypassed an activated managed schema", count, err)
	}
	var exists bool
	if err := f.migrator.pool.QueryRow(f.ctx, `SELECT to_regclass('bypassed_record') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatal("ordinary runner changed managed schema")
	}
}

func TestManagedMigrationGrantFailureBlocksCompleteSchemaUntilRepair(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "CREATE TABLE managed_records(id integer); CREATE FUNCTION policy_review_probe() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "a", sums)
	if err != nil {
		t.Fatal(err)
	}
	count, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime))
	if count != 1 || !errors.Is(err, ErrMigrationRuntimeRole) {
		t.Fatal("final role-policy failure lost the committed SQL result", count, err)
	}
	if err := f.application.RequireNoPendingMigrations(f.ctx, dir); err != nil {
		t.Fatal("fixture did not reach a fully recorded schema")
	}
	if err := f.application.CheckMigrationState(f.ctx, dir); !errors.Is(err, ErrMigrationRuntimeNotReady) {
		t.Fatal("grant failure admitted a fully migrated runtime", err)
	}
	// Explicit operator repair changes the unsupported function property. The
	// recorded migration bytes and their checksum remain untouched.
	if _, err := f.migrator.pool.Exec(f.ctx, "ALTER FUNCTION policy_review_probe() SECURITY INVOKER"); err != nil {
		t.Fatal(err)
	}
	if count, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime)); count != 0 || err != nil {
		t.Fatal("no-op grant repair did not recover managed state", count, err)
	}
	if err := f.application.CheckMigrationState(f.ctx, dir); err != nil {
		t.Fatal("completed grant repair did not admit runtime", err)
	}
}
