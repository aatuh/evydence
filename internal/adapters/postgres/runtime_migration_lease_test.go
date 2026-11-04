package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeMigrationLeaseChecksDoNotWaitBehindQueuedMigration(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	store := runtimeMigrationTestStore(t, f, 0)
	if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version)VALUES('20261029000001_cleanup_probe')"); err != nil {
		t.Fatal(err)
	}
	release, err := store.AcquireRuntimeMigrationLease(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
		defer cancel()
		if err := release(cleanup); err != nil {
			t.Error(err)
		}
	}()
	dir := f.writeMigration("SELECT 1;")
	jobCtx, cancelJob := context.WithCancel(f.ctx)
	defer cancelJob()
	result := make(chan migrationRunnerTestResult, 1)
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		count, err := f.stores[1].ApplyMigrations(jobCtx, dir)
		result <- migrationRunnerTestResult{count, err}
	}()
	f.waitForDatabaseWaiter()
	ctx, cancel := context.WithTimeout(f.ctx, 500*time.Millisecond)
	defer cancel()
	if err := store.RequireNoPendingMigrations(ctx, dir); err != nil {
		t.Fatal("held runtime tried to acquire another shared session behind its waiting migrator", err)
	}
	cancelJob()
	select {
	case <-result:
	case <-f.ctx.Done():
		t.Fatal("queued migration did not stop")
	}
}

func runtimeMigrationTestStore(t *testing.T, f *migrationRunnerTestFixture, index int) *Store {
	t.Helper()
	config := f.stores[index].pool.Config()
	config.MaxConns = 2
	f.stores[index].Close()
	pool, err := pgxpool.NewWithConfig(f.ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	f.stores[index] = &Store{pool: pool}
	return f.stores[index]
}

func TestRuntimeMigrationLeaseLostSessionFailsReadiness(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	store := runtimeMigrationTestStore(t, f, 0)
	release, err := store.AcquireRuntimeMigrationLease(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
		defer cancel()
		if err := release(cleanup); err == nil {
			t.Error("lost lease cleanup reported success")
		}
	}()
	dir := f.writeMigration("SELECT 1;")
	if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version)VALUES('20261029000001_cleanup_probe')"); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckMigrationState(f.ctx, dir); err != nil {
		t.Fatal(err)
	}
	if err := store.runtimeMigrationLease.connection.Conn().Close(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReadiness(f.ctx); err != nil {
		t.Fatal("independent pool connection unavailable", err)
	}
	if err := store.CheckMigrationState(f.ctx, dir); err == nil {
		t.Fatal("healthy replacement connection hid lost runtime migration lease")
	}
}

func TestRuntimeMigrationLeaseCanceledCleanupRetainsOwnership(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	store := runtimeMigrationTestStore(t, f, 0)
	release, err := store.AcquireRuntimeMigrationLease(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
		defer cancel()
		if err := release(cleanup); err != nil {
			t.Error(err)
		}
	}()
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := release(canceled); err == nil {
		t.Fatal("cleanup without deadline was accepted")
	}
	expired, stop := context.WithTimeout(canceled, time.Second)
	defer stop()
	if err := release(expired); !errors.Is(err, context.Canceled) {
		t.Fatal("expired cleanup consumed ownership", err)
	}
	dir := f.writeMigration("INSERT INTO migration_effects(value)VALUES(1);")
	blocked, cancelBlocked := context.WithTimeout(f.ctx, 100*time.Millisecond)
	count, err := f.stores[1].ApplyMigrations(blocked, dir)
	cancelBlocked()
	if count != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired cleanup released active fence", count, err)
	}
	f.requireCounts(0, 0)
	cleanup, cancelCleanup := context.WithTimeout(f.ctx, time.Second)
	defer cancelCleanup()
	if err := release(cleanup); err != nil {
		t.Fatal(err)
	}
	if count, err := f.stores[1].ApplyMigrations(f.ctx, dir); count != 1 || err != nil {
		t.Fatal("fresh cleanup retained lock", count, err)
	}
}

func TestRuntimeMigrationLeasesAllowConcurrentReaders(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	for index := range 2 {
		store := runtimeMigrationTestStore(t, f, index)
		ctx, cancel := context.WithTimeout(f.ctx, time.Second)
		release, err := store.AcquireRuntimeMigrationLease(ctx)
		cancel()
		if err != nil {
			t.Fatal("runtime readers could not coexist", err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
			defer stop()
			if err := release(cleanup); err != nil {
				t.Error(err)
			}
		}()
	}
}
