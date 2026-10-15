package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestStoreShutdownWaitsForBothPoolsBeforeWriterLeaseRelease(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	for _, readPool := range []bool{false, true} {
		t.Run(map[bool]string{false: "command-pool", true: "package-read-pool"}[readPool], func(t *testing.T) {
			store, err := Open(t.Context(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			other, err := Open(t.Context(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			release, err := store.AcquireAPIWriterLease(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := release(t.Context()); err != nil {
					t.Error(err)
				}
			}()
			pool := store.pool
			if readPool {
				pool = store.packageReadPool
			}
			borrowed, err := pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer borrowed.Release()
			budget, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			err = store.WaitForIdle(budget)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("active connection was not bounded", err)
			}
			if err = store.CheckAPIWriterLease(t.Context()); err != nil {
				t.Fatal("writer lease lost before work drained", err)
			}
			if unexpected, err := other.AcquireAPIWriterLease(t.Context()); err == nil {
				_ = unexpected(t.Context())
				t.Fatal("second writer admitted while work remained")
			}
			borrowed.Release()
			budget, cancel = context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err = store.WaitForIdle(budget); err != nil {
				t.Fatal("idle pools included the owned lease as unfinished work", err)
			}
			if err = release(budget); err != nil {
				t.Fatal("bounded lease release failed", err)
			}
			next, err := other.AcquireAPIWriterLease(budget)
			if err != nil {
				t.Fatal("next writer not admitted after release", err)
			}
			if err = next(budget); err != nil {
				t.Fatal(err)
			}
		})
	}
}
