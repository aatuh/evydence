package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresCatalogCreationGuardsLockParentsThroughReplayWithoutChildReads(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"product:write", "project:write", "release:write"}}
	for _, c := range nativeCatalogCases() {
		calls, guards := 0, 0
		for range 2 {
			_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", c.path, "locks", []byte(c.body), func(ctx context.Context) error {
				if err := c.guard(ctx, o, a); err != nil {
					return err
				}
				guards++
				for _, tc := range []struct {
					table, id string
					blocked   bool
				}{{"tenants", "tenant", true}, {"products", "product", c.kind != "product"}, {"projects", "project", false}, {"products", "other-product", false}, {"sso_sessions", "operator-session", false}} {
					probe, err := p.Begin(ctx)
					if err != nil {
						return err
					}
					_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
					_ = probe.Rollback(context.WithoutCancel(ctx))
					var pe *pgconn.PgError
					if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
						t.Fatal("catalog guard lost parent lock or reached unrelated rows", c.kind, tc, err)
					}
				}
				return nil
			}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
			if err != nil {
				t.Fatal(err)
			}
		}
		if calls != 1 || guards != 2 {
			t.Fatal("guard skipped replay or reran write", c.kind, calls, guards)
		}
	}
	if got := catalogNativeCounts(t, p); got != [7]int{3, 3, 0, 0, 0, 3, 0} {
		t.Fatal("guard wrote catalog effects", got)
	}
}

func TestPostgresCatalogCreationNativeConcurrentReplayCreatesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"product:write", "project:write", "release:write"}}
	for _, c := range nativeCatalogCases() {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var calls atomic.Int32
		type reply struct {
			status int
			value  any
			err    error
		}
		done := make(chan reply, 2)
		start := make(chan struct{})
		for range 2 {
			go func() {
				<-start
				s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", c.path, "concurrent", []byte(c.body), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(ctx context.Context) (int, any, error) { calls.Add(1); return c.create(ctx, o, a) })
				done <- reply{s, v, err}
			}()
		}
		close(start)
		var replies [2]string
		for i := range replies {
			select {
			case r := <-done:
				if r.err != nil || r.status != 201 {
					t.Fatal("concurrent catalog failed", c.kind, r.status, r.err)
				}
				b, err := json.Marshal(r.value)
				if err != nil {
					t.Fatal(err)
				}
				replies[i] = string(b)
			case <-ctx.Done():
				t.Fatal("catalog replay leaked transaction", c.kind, ctx.Err())
			}
		}
		cancel()
		assertRetentionHTTPReplay(t, replies[0], replies[1])
		if calls.Load() != 1 {
			t.Fatal("catalog replay executed twice", c.kind, calls.Load())
		}
	}
	if got := catalogNativeCounts(t, p); got != [7]int{4, 4, 1, 3, 0, 3, 0} {
		t.Fatal("concurrent catalog duplicated effects", got)
	}
}

func TestPostgresCatalogCreationCancelledGuardsReleaseFenceBeforeTenantLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"product:write", "project:write", "release:write"}}
	for _, c := range nativeCatalogCases() {
		leader, err := p.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
		if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
			t.Fatal(err)
		}
		leaderPID := leader.Conn().PgConn().PID()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- c.guard(ctx, o, a) }()
		waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
			var blocked bool
			err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
			return blocked, err
		}, done)
		if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
			t.Fatal("catalog tenant lock preceded writer fence", c.kind, err)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("catalog lost cancellation", c.kind, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("catalog cancellation leaked transaction", c.kind)
		}
		if err := leader.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := c.guard(t.Context(), o, a); err != nil {
			t.Fatal("cancelled catalog guard leaked fence", c.kind, err)
		}
	}
	if got := catalogNativeCounts(t, p); got != [7]int{3, 3, 0, 0, 0, 0, 0} {
		t.Fatal("cancelled guards wrote effects", got)
	}
}
