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

func TestPostgresBuildCreationGuardLocksJoinOuterReplayWithoutMetadataReads(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"build:write"}}
	in := buildCreationNativeInput()
	calls, guards := 0, 0
	for range 2 {
		_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/builds", "locks", []byte("input"), func(ctx context.Context) error {
			if err := o.BuildCommands.AuthorizeBuildCreation(ctx, a, in); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table, id string
				blocked   bool
			}{{"tenants", "tenant", true}, {"projects", "project", true}, {"products", "product", true}, {"releases", "release", true}, {"artifacts", "artifact", true}, {"build_runs", "linked-build", false}, {"projects", "other-project", false}, {"products", "other-product", false}, {"releases", "other-release", false}, {"artifacts", "foreign-artifact", false}, {"sso_sessions", "operator-session", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("build guard lost parent lock or locked unrelated row", tc, err)
				}
			}
			return nil
		}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := buildCreationNativeCounts(t, p); calls != 1 || guards != 2 || got != [5]int{1, 0, 0, 1, 0} {
		t.Fatal("read-only guard skipped replay or wrote effects", calls, guards, got)
	}
}

func TestPostgresBuildCreationNativeConcurrentReplayCreatesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"build:write"}}
	in := buildCreationNativeInput()
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
			s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/builds", "concurrent", []byte("input"), func(ctx context.Context) error {
				return o.BuildCommands.AuthorizeBuildCreation(ctx, a, in)
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := o.BuildCommands.CreateBuildRun(ctx, a, in)
				return 201, v, err
			})
			done <- reply{s, v, err}
		}()
	}
	close(start)
	var replies [2]string
	for i := range replies {
		select {
		case r := <-done:
			if r.err != nil || r.status != 201 {
				t.Fatal("concurrent build failed", r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[i] = string(b)
		case <-ctx.Done():
			t.Fatal("concurrent build leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, replies[0], replies[1])
	if got := buildCreationNativeCounts(t, p); calls.Load() != 1 || got != [5]int{2, 1, 0, 1, 0} {
		t.Fatal("concurrent build duplicated effects", calls.Load(), got)
	}
}

func TestPostgresBuildCreationCancelledGuardReleasesFenceBeforeTenantLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"build:write"}}
	in := buildCreationNativeInput()
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
	go func() { done <- o.BuildCommands.AuthorizeBuildCreation(ctx, a, in) }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("build tenant lock preceded writer fence", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("build guard lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled build guard leaked transaction")
	}
	if err := leader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := o.BuildCommands.AuthorizeBuildCreation(t.Context(), a, in); err != nil {
		t.Fatal("cancelled build guard leaked fence", err)
	}
	if got := buildCreationNativeCounts(t, p); got != [5]int{1, 0, 0, 0, 0} {
		t.Fatal("cancelled guard wrote effects", got)
	}
}
