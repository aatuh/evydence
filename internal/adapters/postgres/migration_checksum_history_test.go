package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMigrationChecksumHistoryPersistsExecutedBytesAndPrincipal(t *testing.T) {
	for _, mode := range []string{"ordinary", "verified"} {
		t.Run(mode, func(t *testing.T) {
			f := newMigrationRunnerTestFixture(t)
			const body = "INSERT INTO migration_effects(value)VALUES(1);"
			dir, checksums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": body})
			var applied int
			var err error
			if mode == "ordinary" {
				applied, err = f.stores[0].ApplyMigrations(f.ctx, dir)
			} else {
				plan, planErr := PrepareMigrationPlan(f.ctx, dir, "a", checksums)
				if planErr != nil {
					t.Fatal(planErr)
				}
				if err := os.WriteFile(filepath.Join(dir, "a.up.sql"), []byte("SELECT 1/0;"), 0o600); err != nil {
					t.Fatal(err)
				}
				applied, err = f.stores[0].ApplyMigrationPlan(f.ctx, plan)
			}
			if err != nil || applied != 1 {
				t.Fatal("migration did not execute its owned SQL", applied, err)
			}
			f.requireCounts(1, 1)
			var checksum, principal, authenticated string
			if err := f.admin.QueryRow(f.ctx, "SELECT checksum_sha256,applied_by::text,session_user::text FROM "+f.quoted+".schema_migrations WHERE version='a'").Scan(&checksum, &principal, &authenticated); err != nil {
				t.Fatal("execution checksum/principal was not recorded", err)
			}
			if checksum != fmt.Sprintf("%x", sha256.Sum256([]byte(body))) || principal == "" || principal != authenticated {
				t.Fatal("execution metadata did not describe actual frozen bytes and authenticated database principal")
			}
		})
	}
}

func TestMigrationChecksumHistoryRejectsChangedAppliedSQLBeforePendingSQL(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	dir, _ := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "INSERT INTO migration_effects(value)VALUES(1);"})
	if count, err := f.stores[0].ApplyMigrations(f.ctx, dir); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.up.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.up.sql"), []byte("INSERT INTO migration_effects(value)VALUES(99);"), 0o600); err != nil {
		t.Fatal(err)
	}
	if count, err := f.stores[1].ApplyMigrations(f.ctx, dir); !errors.Is(err, ErrMigrationChecksum) || count != 0 {
		t.Fatal("changed recorded SQL was ignored before applying a pending migration", count, err)
	}
	f.requireCounts(1, 1)
}

func TestMigrationChecksumHistoryVerifiedPlanRequiresLegacyAcknowledgement(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version,applied_at)VALUES('a','2001-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	dir, checksums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT 1/0;", "b.up.sql": "INSERT INTO migration_effects(value)VALUES(99);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "b", checksums)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := f.stores[0].ApplyMigrationPlan(f.ctx, plan); !errors.Is(err, ErrMigrationLegacyHistory) || count != 0 {
		t.Fatal("verified plan silently accepted unknown historical SQL", count, err)
	}
	f.requireCounts(0, 1)
}

func TestMigrationChecksumHistoryLegacyAcknowledgementNeverPermitsMismatch(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version)VALUES('a')"); err != nil {
		t.Fatal(err)
	}
	dir, _ := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT 1/0;", "b.up.sql": "INSERT INTO migration_effects(value)VALUES(1);"})
	if count, err := f.stores[0].ApplyMigrations(f.ctx, dir); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	dir, checksums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT 1/0;", "b.up.sql": "SELECT 'PRIVATE_CHANGED';", "c.up.sql": "INSERT INTO migration_effects(value)VALUES(99);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "c", checksums)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := f.stores[1].ApplyMigrationPlan(f.ctx, plan.WithLegacyHistory()); !errors.Is(err, ErrMigrationChecksum) || count != 0 {
		t.Fatal("legacy acknowledgement bypassed a stored checksum mismatch", count, err)
	}
	if plan.allowLegacyHistory {
		t.Fatal("acknowledgement mutated the original immutable plan")
	}
	f.requireCounts(1, 2)
	var stillUnknown bool
	if err := f.admin.QueryRow(f.ctx, "SELECT checksum_sha256 IS NULL AND applied_by IS NULL FROM "+f.quoted+".schema_migrations WHERE version='a'").Scan(&stillUnknown); err != nil || !stillUnknown {
		t.Fatal("legacy checksum metadata was invented", err)
	}
}

func executeChecksumMetadataMigration(t *testing.T, f *migrationRunnerTestFixture, direction string) error {
	t.Helper()
	root, err := os.OpenRoot("../../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	body, err := root.ReadFile("20261029000100_migration_execution_checksums." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(f.ctx, "SET LOCAL search_path TO "+f.quoted); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, string(body)); err != nil {
		return err
	}
	return tx.Commit(f.ctx)
}

func TestMigrationChecksumHistoryVersionedDDLAndDowngradeGuard(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(fmt.Sprintf("recorded_%t", recorded), func(t *testing.T) {
			f := newMigrationRunnerTestFixture(t)
			if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version,applied_at)VALUES('a','2001-01-01T00:00:00Z')"); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := executeChecksumMetadataMigration(t, f, "up"); err != nil {
					t.Fatal("additive metadata migration was not repeatable", err)
				}
			}
			if recorded {
				if count, err := f.stores[0].ApplyMigrations(f.ctx, f.writeMigration("SELECT 1;")); err != nil || count != 1 {
					t.Fatal(count, err)
				}
			}
			err := executeChecksumMetadataMigration(t, f, "down")
			var databaseError *pgconn.PgError
			if recorded {
				if !errors.As(err, &databaseError) || databaseError.Code != "55000" {
					t.Fatal("downgrade erased execution provenance", err)
				}
				f.requireCounts(0, 2)
			} else if err != nil {
				t.Fatal("metadata-only legacy downgrade failed", err)
			}
			var checksumColumn bool
			if err := f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name='schema_migrations' AND column_name='checksum_sha256')`, f.schema).Scan(&checksumColumn); err != nil || checksumColumn != recorded {
				t.Fatal("downgrade changed unexpected metadata columns", err)
			}
		})
	}
}

func TestMigrationChecksumHistoryRejectsMalformedMetadata(t *testing.T) {
	for _, setup := range []string{"versioned", "runner"} {
		t.Run(setup, func(t *testing.T) {
			f := newMigrationRunnerTestFixture(t)
			if setup == "versioned" {
				if err := executeChecksumMetadataMigration(t, f, "up"); err != nil {
					t.Fatal(err)
				}
			} else if count, err := f.stores[0].ApplyMigrations(f.ctx, t.TempDir()); err != nil || count != 0 {
				t.Fatal("runner metadata bootstrap failed", count, err)
			}
			if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version)VALUES('a')"); err != nil {
				t.Fatal(err)
			}
			// Only these fixed test assignments become SQL text.
			for _, fields := range []string{"checksum_sha256='invalid',applied_by=session_user", "checksum_sha256=repeat('a',64)", "applied_by=session_user"} {
				_, err := f.admin.Exec(f.ctx, "UPDATE "+f.quoted+".schema_migrations SET "+fields+" WHERE version='a'")
				var databaseError *pgconn.PgError
				if !errors.As(err, &databaseError) || databaseError.Code != "23514" {
					t.Fatal("execution metadata admitted an invalid checksum or half-known provenance", err)
				}
			}
		})
	}
}

func TestMigrationChecksumHistoryConflictingOrdinaryRecordRollsBack(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	dir := f.writeMigration("INSERT INTO schema_migrations(version)VALUES('20261029000001_cleanup_probe'); INSERT INTO migration_effects(value)VALUES(1);")
	if count, err := f.stores[0].ApplyMigrations(f.ctx, dir); err == nil || count != 0 {
		t.Fatal("conflicting version record committed without execution provenance", count, err)
	}
	f.requireCounts(0, 0)
}
