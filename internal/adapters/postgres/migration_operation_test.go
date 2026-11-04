package postgres

import (
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Seed the intended durable contract independently of the runner so these
// regressions also prove that readiness handles interrupted existing state.
const migrationOperationFixtureSQL = `CREATE TABLE schema_migration_operations (
 sequence bigint PRIMARY KEY,
 operation_id text NOT NULL,
 phase text NOT NULL,
 target_version text NOT NULL,
 runtime_role name NOT NULL,
 performed_by name NOT NULL DEFAULT session_user,
 committed_migrations integer,
 policy_sha256 text NOT NULL DEFAULT repeat('a',64),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 schema_version text NOT NULL DEFAULT 'migration-operation.v1')`

func TestMigrationOperationStateBlocksIncompleteRuntimeStartup(t *testing.T) {
	for _, state := range []struct {
		phase, role, version string
		ready                bool
	}{
		{"started", "", "migration-operation.v1", false},
		{"failed", "", "migration-operation.v1", false},
		{"uncertain", "", "migration-operation.v1", false},
		{"succeeded", "", "migration-operation.v1", true},
		{"succeeded", "wrong_runtime", "migration-operation.v1", false},
		{"succeeded", "", "migration-operation.v2", false},
	} {
		t.Run(state.phase+"/"+state.role+"/"+state.version, func(t *testing.T) {
			f := newMigrationRoleFixture(t, false)
			dir := f.migrate()
			if _, err := f.migrator.pool.Exec(f.ctx, migrationOperationFixtureSQL); err != nil {
				t.Fatal(err)
			}
			if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
				t.Fatal(err)
			}
			if err := f.application.CheckMigrationState(f.ctx, dir); err != nil {
				t.Fatal("empty operation history changed version-only compatibility")
			}
			role := state.role
			if role == "" {
				role = f.runtime
			}
			policy, err := os.ReadFile("../../../deploy/postgres/runtime-role.sql")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO schema_migration_operations(sequence,operation_id,phase,target_version,runtime_role,schema_version,policy_sha256)VALUES(1,'operation',$1,'a',$2,$3,$4)`, state.phase, role, state.version, migrationChecksum(string(policy))); err != nil {
				t.Fatal(err)
			}
			err = f.application.CheckMigrationState(f.ctx, dir)
			if (err == nil) != state.ready {
				t.Fatal("runtime readiness ignored the durable migration/grant outcome")
			}
		})
	}
}

func TestMigrationOperationRecordsAreReadOnlyToRuntime(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	f.migrate()
	if _, err := f.migrator.pool.Exec(f.ctx, migrationOperationFixtureSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO schema_migration_operations(sequence,operation_id,phase,target_version,runtime_role)VALUES(1,'operation','started','a',$1)`, f.runtime); err != nil {
		t.Fatal(err)
	}
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"UPDATE schema_migration_operations SET phase='succeeded'",
		"DELETE FROM schema_migration_operations", "TRUNCATE schema_migration_operations",
		"INSERT INTO schema_migration_operations(sequence,operation_id,phase,target_version,runtime_role)VALUES(2,'forged','succeeded','a',session_user)",
	} {
		_, err := f.application.pool.Exec(f.ctx, statement)
		requireRoleDenied(t, err)
	}
	var phase string
	if err := f.application.pool.QueryRow(f.ctx, "SELECT phase FROM "+pgx.Identifier{f.schema, "schema_migration_operations"}.Sanitize()).Scan(&phase); err != nil || phase != "started" {
		t.Fatal("runtime role could not read intact operation history")
	}
}
