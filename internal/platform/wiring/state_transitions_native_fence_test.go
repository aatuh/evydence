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

func TestPostgresStateTransitionGuardsKeepOwnershipLocksThroughReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedStateTransitionNative(t, p, nativeTransitionCases()[2])
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"release:write"}}
	for _, c := range []nativeTransitionCase{nativeTransitionCases()[0], nativeTransitionCases()[2]} {
		calls, guards := 0, 0
		for range 2 {
			_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", c.path, "locks", c.fingerprint(c.body, c.revision), func(ctx context.Context) error {
				if err := c.guard(ctx, o, a); err != nil {
					return err
				}
				guards++
				for _, tc := range []struct {
					table, id string
					blocked   bool
				}{{"tenants", "tenant", true}, {"products", "product", true}, {"releases", "release", true}, {"release_candidates", "candidate", c.candidate()}, {"projects", "project", false}, {"products", "other-product", false}, {"releases", "other-release", false}, {"sso_sessions", "operator-session", false}} {
					probe, err := p.Begin(ctx)
					if err != nil {
						return err
					}
					_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
					_ = probe.Rollback(context.WithoutCancel(ctx))
					var pe *pgconn.PgError
					if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
						t.Fatal("transition guard lost ownership lock or reached unrelated row", tc, err)
					}
				}
				return nil
			}, func(context.Context) (int, any, error) { calls++; return 200, map[string]any{"id": "guard-only"}, nil })
			if err != nil {
				t.Fatal(err)
			}
		}
		if calls != 1 || guards != 2 {
			t.Fatal("state guard skipped replay or executed twice", calls, guards)
		}
	}
	if got := stateTransitionNativeCounts(t, p); got != [6]int{1, 1, 0, 0, 2, 0} {
		t.Fatal("guard changed lifecycle/audit", got)
	}
}

func TestPostgresStateTransitionsNativeConcurrentReplayChangesStateOnce(t *testing.T) {
	for _, c := range nativeTransitionCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedStateTransitionNative(t, p, c)
			o := subjectVerificationOptions(t, store, nil)
			a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"release:write"}}
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
					s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", c.path, "concurrent", c.fingerprint(c.body, c.revision), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(ctx context.Context) (int, any, error) { calls.Add(1); return c.create(ctx, o, a) })
					done <- reply{s, v, err}
				}()
			}
			close(start)
			var replies [2]string
			for n := range replies {
				select {
				case r := <-done:
					if r.err != nil || r.status != 200 {
						t.Fatal("concurrent state transition failed", r.status, r.err)
					}
					b, err := json.Marshal(r.value)
					if err != nil {
						t.Fatal(err)
					}
					replies[n] = string(b)
				case <-ctx.Done():
					t.Fatal("transition leaked transaction", ctx.Err())
				}
			}
			assertRetentionHTTPReplay(t, replies[0], replies[1])
			want := [6]int{int(c.revision + 1), 0, 1, 0, 1, 0}
			if c.candidate() {
				want[0], want[1] = 1, 2
			}
			if calls.Load() != 1 || stateTransitionNativeCounts(t, p) != want {
				t.Fatal("concurrent replay duplicated transition", calls.Load(), stateTransitionNativeCounts(t, p), want)
			}
		})
	}
}

func TestPostgresStateTransitionCancelledGuardsReleaseFenceBeforeOwnershipLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedStateTransitionNative(t, p, nativeTransitionCases()[2])
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"release:write"}}
	for _, c := range []nativeTransitionCase{nativeTransitionCases()[0], nativeTransitionCases()[2]} {
		leader, err := p.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
		if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
			t.Fatal(err)
		}
		pid := leader.Conn().PgConn().PID()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- c.guard(ctx, o, a) }()
		waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
			var blocked bool
			err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
			return blocked, err
		}, done)
		if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
			t.Fatal("ownership lock preceded fence", err)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("guard lost cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("transition cancellation leaked transaction")
		}
		if err := leader.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := c.guard(t.Context(), o, a); err != nil {
			t.Fatal("cancelled guard leaked fence", err)
		}
	}
	if got := stateTransitionNativeCounts(t, p); got != [6]int{1, 1, 0, 0, 0, 0} {
		t.Fatal("cancelled guard wrote effects", got)
	}
}
