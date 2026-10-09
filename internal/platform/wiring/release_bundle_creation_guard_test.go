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
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresReleaseBundleGuardLocksJoinOuterReplayTransaction(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedReleaseBundleHTTP(t, p)
	c, err := BuildReleaseBundleCommands(store, store, store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"bundle:write"}}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeReleaseBundleCreation(ctx, a, "release")
	}}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT id FROM products WHERE id='product' FOR UPDATE NOWAIT`, `SELECT id FROM releases WHERE id='release' FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, err = tx.Exec(ctx, sql)
			_ = tx.Rollback(context.WithoutCancel(ctx))
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
				t.Fatal("bundle guard released source locks before mutation", err)
			}
		}
		v, err := c.CreateReleaseBundle(ctx, a, "release")
		return 201, domain.ReleaseBundleFromContextModel(v), err
	}
	_, one, err := executor.WithBody(t.Context(), a, "POST", "/v1/release-bundles", "outer", []byte(`{}`), run)
	if err != nil {
		t.Fatal(err)
	}
	_, two, err := executor.WithBody(t.Context(), a, "POST", "/v1/release-bundles", "outer", []byte(`{}`), run)
	if err != nil || calls != 1 || one == nil || two == nil || releaseBundleHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatal("outer bundle replay did not remain atomic", err, calls)
	}
}

func TestPostgresReleaseBundleConcurrentNativeDeliveryCommitsOneEffect(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedReleaseBundleHTTP(t, p)
	c, err := BuildReleaseBundleCommands(store, store, store)
	if err != nil {
		t.Fatal(err)
	}
	e, err := BuildDurableCommandExecutor(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"bundle:write"}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var calls atomic.Int32
	type result struct {
		status int
		value  any
		err    error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			status, value, err := e.WithBody(ctx, a, "POST", "/v1/release-bundles", "concurrent", []byte(`{"release_id":"release"}`), func(ctx context.Context) error { return c.AuthorizeReleaseBundleCreation(ctx, a, "release") }, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := c.CreateReleaseBundle(ctx, a, "release")
				return 201, domain.ReleaseBundleFromContextModel(v), err
			})
			results <- result{status, value, err}
		}()
	}
	close(start)
	var responses [2]string
	for i := range responses {
		select {
		case r := <-results:
			if r.err != nil || r.status != 201 {
				t.Fatal("concurrent bundle delivery failed", r.err, r.status)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			responses[i] = string(b)
		case <-ctx.Done():
			t.Fatal("concurrent bundle delivery did not release transactions", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, responses[0], responses[1])
	if calls.Load() != 1 || releaseBundleHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatal("concurrent delivery duplicated bundle effects", calls.Load())
	}
}

func TestPostgresReleaseBundleFencePrecedesSourceLocksAndCancelsCleanly(t *testing.T) {
	for _, stage := range []string{"guard", "write", "cancel"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedReleaseBundleHTTP(t, p)
			c, err := BuildReleaseBundleCommands(store, store, store)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			leader, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
			if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
				t.Fatal(err)
			}
			childCtx, cancelChild := context.WithCancel(ctx)
			defer cancelChild()
			done := make(chan error, 1)
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"bundle:write"}}
			go func() {
				var err error
				if stage == "write" {
					_, err = c.CreateReleaseBundle(childCtx, a, "release")
				} else {
					err = c.AuthorizeReleaseBundleCreation(childCtx, a, "release")
				}
				done <- err
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("bundle bypassed tenant fence", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
					var blocked bool
					if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if !blocked {
						continue
					}
					for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT id FROM products WHERE id='product' FOR UPDATE NOWAIT`, `SELECT id FROM releases WHERE id='release' FOR UPDATE NOWAIT`} {
						if _, err := leader.Exec(ctx, sql); err != nil {
							t.Fatal("bundle source lock preceded tenant fence", err)
						}
					}
					if stage == "cancel" {
						cancelChild()
					}
					if err := leader.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if stage == "cancel" {
							if !errors.Is(err, context.Canceled) {
								t.Fatal("cancelled guard completed", err)
							}
						} else if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("bundle did not release wait", ctx.Err())
					}
					want := [6]int{}
					if stage == "write" {
						want = [6]int{1, 1, 1, 1, 0, 0}
					}
					if releaseBundleHTTPCounts(t, p) != want {
						t.Fatal("fenced/cancelled bundle published wrong effects")
					}
					if err := c.AuthorizeReleaseBundleCreation(ctx, a, "release"); err != nil {
						t.Fatal("cancelled guard leaked transaction or lock", err)
					}
					return
				}
			}
		})
	}
}
