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

func TestPostgresDeploymentCreationGuardsKeepOwnershipLocksThroughReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDeploymentCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"deployment:write"}}
	baseline := deploymentCreationNativeCounts(t, p)
	for _, c := range nativeDeploymentCases() {
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
				}{
					{"tenants", "tenant", true}, {"products", "product", true}, {"deployment_environments", "env", c.kind == "event"}, {"releases", "release", c.kind == "event"}, {"artifacts", "artifact", c.kind == "event"}, {"artifacts", "artifact-b", c.kind == "event"}, {"deployment_events", "rollback", c.kind == "event"},
					{"projects", "project", false}, {"products", "other-product", false}, {"releases", "other-release", false}, {"deployment_environments", "other-env", false}, {"deployment_events", "other-rollback", false}, {"artifacts", "foreign-artifact", false}, {"sso_sessions", "operator-session", false},
				} {
					probe, err := p.Begin(ctx)
					if err != nil {
						return err
					}
					_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
					_ = probe.Rollback(context.WithoutCancel(ctx))
					var pe *pgconn.PgError
					if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
						t.Fatal("deployment guard lost ownership lock or reached unrelated row", c.kind, tc, err)
					}
				}
				return nil
			}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
			if err != nil {
				t.Fatal(err)
			}
		}
		if calls != 1 || guards != 2 {
			t.Fatal("deployment guard skipped replay or executed twice", c.kind, calls, guards)
		}
	}
	baseline[5] += 2
	if got := deploymentCreationNativeCounts(t, p); got != baseline {
		t.Fatal("deployment guard wrote domain effects", got, baseline)
	}
}

func TestPostgresDeploymentCreationNativeConcurrentReplayWritesOnce(t *testing.T) {
	for _, c := range nativeDeploymentCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedDeploymentCreationNative(t, p)
			baseline := deploymentCreationNativeCounts(t, p)
			o := subjectVerificationOptions(t, store, nil)
			a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"deployment:write"}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var calls atomic.Int32
			type reply struct {
				status int
				value  any
				err    error
			}
			done, start := make(chan reply, 2), make(chan struct{})
			for range 2 {
				go func() {
					<-start
					s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", c.path, "concurrent", []byte(c.body), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(ctx context.Context) (int, any, error) { calls.Add(1); return c.create(ctx, o, a) })
					done <- reply{s, v, err}
				}()
			}
			close(start)
			var replies [2]string
			for n := range replies {
				select {
				case r := <-done:
					if r.err != nil || r.status != 201 {
						t.Fatal("concurrent deployment failed", r.status, r.err)
					}
					b, err := json.Marshal(r.value)
					if err != nil {
						t.Fatal(err)
					}
					replies[n] = string(b)
				case <-ctx.Done():
					t.Fatal("deployment leaked transaction", ctx.Err())
				}
			}
			assertDeploymentCreationReplay(t, replies[0], replies[1])
			if got, want := deploymentCreationNativeCounts(t, p), c.addEffects(baseline); calls.Load() != 1 || got != want {
				t.Fatal("concurrent deployment duplicated effects", calls.Load(), got, want)
			}
		})
	}
}

func TestPostgresDeploymentCreationCancelledGuardsReleaseFenceBeforeOwnershipLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedDeploymentCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"deployment:write"}}
	baseline := deploymentCreationNativeCounts(t, p)
	for _, c := range nativeDeploymentCases() {
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
			t.Fatal("deployment ownership lock preceded writer fence", err)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("deployment guard lost cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled deployment leaked transaction")
		}
		if err := leader.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := c.guard(t.Context(), o, a); err != nil {
			t.Fatal("cancelled deployment leaked fence", err)
		}
	}
	if got := deploymentCreationNativeCounts(t, p); got != baseline {
		t.Fatal("cancelled guard wrote effects", got, baseline)
	}
}
