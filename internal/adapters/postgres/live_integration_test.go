package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresLiveIntegrationFailsClosedOnPoolExhaustionAndConnectionLoss
// verifies two real-server failure modes that in-memory substitutes cannot
// reproduce: an exhausted pool respects the caller's deadline, and a killed
// backend is never treated as a healthy connection.
func TestPostgresLiveIntegrationFailsClosedOnPoolExhaustionAndConnectionLoss(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	config.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exhaustedCtx, cancelExhausted := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = pool.Acquire(exhaustedCtx)
	cancelExhausted()
	if !errors.Is(err, context.DeadlineExceeded) {
		held.Release()
		t.Fatalf("pool exhaustion error = %v, want context deadline exceeded", err)
	}
	held.Release()

	victim, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	victimPID := victim.Conn().PgConn().PID()
	killer, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		victim.Release()
		t.Fatal(err)
	}
	defer killer.Close(context.WithoutCancel(ctx))
	var terminated bool
	if err := killer.QueryRow(ctx, "SELECT pg_terminate_backend($1)", victimPID).Scan(&terminated); err != nil {
		victim.Release()
		t.Fatalf("terminate test backend: %v", err)
	}
	if !terminated {
		victim.Release()
		t.Fatal("test backend was not terminated")
	}
	if _, err := victim.Exec(ctx, "SELECT 1"); err == nil {
		victim.Release()
		t.Fatal("terminated backend unexpectedly accepted a query")
	}
	victim.Release()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool did not recover with a fresh connection: %v", err)
	}
}
