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

func TestPostgresArtifactImageRegistrationGuardsKeepOwnershipLocksThroughReplay(t *testing.T) {
	for _, c := range nativeRegistrationCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedBuildCreationNative(t, p)
			one := registrationNativeHTTP(t, store, c, "original", c.body, 201)
			var e struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &e); err != nil {
				t.Fatal(err)
			}
			o := subjectVerificationOptions(t, store, nil)
			a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
			artifactID := "artifact"
			if c.kind == "artifact" {
				artifactID = e.Data.ID
			}
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
					}{{"tenants", "tenant", true}, {"artifacts", artifactID, true}, {"artifacts", "foreign-artifact", false}, {"products", "product", false}, {"projects", "project", false}, {"container_images", e.Data.ID, c.kind == "image"}} {
						probe, err := p.Begin(ctx)
						if err != nil {
							return err
						}
						_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
						_ = probe.Rollback(context.WithoutCancel(ctx))
						var pe *pgconn.PgError
						if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
							t.Fatal("guard lost ownership lock or loaded unrelated rows", tc, err)
						}
					}
					return nil
				}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
				if err != nil {
					t.Fatal(err)
				}
			}
			if calls != 1 || guards != 2 {
				t.Fatal("guard skipped replay or wrote twice", calls, guards)
			}
			want := [6]int{2, 0, 1, 0, 2, 0}
			if c.kind == "artifact" {
				want[0]++
			} else {
				want[1]++
			}
			if got := registrationNativeCounts(t, p); got != want {
				t.Fatal("read-only guard wrote business effects", got, want)
			}
		})
	}
}

func TestPostgresArtifactImageRegistrationNativeConcurrentReplayCreatesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	for _, c := range nativeRegistrationCases() {
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
		for n := range replies {
			select {
			case r := <-done:
				if r.err != nil || r.status != 201 {
					t.Fatal("concurrent registration failed", c.kind, r.status, r.err)
				}
				b, err := json.Marshal(r.value)
				if err != nil {
					t.Fatal(err)
				}
				replies[n] = string(b)
			case <-ctx.Done():
				t.Fatal("concurrent replay leaked transaction", ctx.Err())
			}
		}
		cancel()
		assertRetentionHTTPReplay(t, replies[0], replies[1])
		if calls.Load() != 1 {
			t.Fatal("registration executed twice", c.kind, calls.Load())
		}
	}
	if got := registrationNativeCounts(t, p); got != [6]int{3, 1, 2, 0, 2, 0} {
		t.Fatal("concurrent replay duplicated effects", got)
	}
}

func TestPostgresArtifactImageRegistrationCancelledGuardsReleaseFenceBeforeTenantLock(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	for _, c := range nativeRegistrationCases() {
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
			t.Fatal("tenant lock preceded writer fence", err)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("guard lost cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled guard leaked transaction")
		}
		if err := leader.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := c.guard(t.Context(), o, a); err != nil {
			t.Fatal("guard leaked cancelled fence", err)
		}
	}
	if got := registrationNativeCounts(t, p); got != [6]int{2, 0, 0, 0, 0, 0} {
		t.Fatal("cancelled guards wrote effects", got)
	}
}
