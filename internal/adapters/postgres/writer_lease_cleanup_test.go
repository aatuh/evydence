package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAPIWriterLeaseRejectsLostOwnershipAndDiscardsSession(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	release, err := f.stores[0].AcquireAPIWriterLease(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn := f.stores[0].writerLease
	before := conn.Conn().PgConn().PID()
	if _, err := conn.Exec(f.ctx, `SELECT pg_advisory_unlock($1)`, apiWriterLeaseKey); err != nil {
		t.Fatal(err)
	}
	if err := release(f.ctx); err == nil {
		t.Fatal("lost writer ownership was silently accepted")
	}
	var after uint32
	if err := f.stores[0].pool.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&after); err != nil || before == after {
		t.Fatal("uncertain writer lease session was reused", err)
	}
}

func TestAPIWriterLeaseCanceledCleanupRetainsOwnershipUntilFreshCleanup(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	release, err := f.stores[0].AcquireAPIWriterLease(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := release(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled cleanup changed writer ownership", err)
	}
	if other, err := f.stores[1].AcquireAPIWriterLease(f.ctx); err == nil {
		_ = other(f.ctx)
		t.Fatal("canceled cleanup admitted another writer")
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(f.ctx), time.Second)
	defer stop()
	if err := release(cleanup); err != nil {
		t.Fatal("fresh bounded cleanup did not release retained ownership", err)
	}
}
