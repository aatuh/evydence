package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestPostgresRetentionMarkerReplayDoesNotExpireAndGuardJoinsOuterTransaction(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	at := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	c, err := operationsapp.NewRetentionMarkerCommands(operationsapp.RetentionMarkerConfig{Transactions: retentionMarkerTransactions{store}, Authorizer: operationsapp.NewRetentionMarkerAuthorizer(), Clock: application.ClockFunc(func() time.Time { return at }), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}
	in := operationsapp.RetentionOverrideInput{RetentionMarkerInput: operationsapp.RetentionMarkerInput{ScopeType: "tenant", ScopeID: "tenant", Reason: "review", Owner: "legal"}, RetentionUntil: at.Add(time.Hour)}
	executor := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeRetentionMarker(ctx, a, in.ScopeType, in.ScopeID)
	}}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`)
		_ = tx.Rollback(context.WithoutCancel(ctx))
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
			t.Fatal("guard locks released before outer mutation", err)
		}
		v, err := c.CreateRetentionOverride(ctx, a, in)
		return 201, domain.RetentionOverride(v), err
	}
	_, one, err := executor.WithBody(t.Context(), a, "POST", "/v1/retention-overrides", "clock", []byte(`{}`), run)
	if err != nil {
		t.Fatal(err)
	}
	at = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, two, err := executor.WithBody(t.Context(), a, "POST", "/v1/retention-overrides", "clock", []byte(`{}`), run)
	if err != nil || calls != 1 {
		t.Fatal("historical replay expired or reran command", err, calls)
	}
	x, _ := json.Marshal(one)
	y, _ := json.Marshal(two)
	assertRetentionHTTPReplay(t, string(x), string(y))
	if _, _, err := executor.WithBody(t.Context(), a, "POST", "/v1/retention-overrides", "fresh", []byte(`{}`), run); !errors.Is(err, operationsapp.ErrValidation) || retentionMarkerCounts(t, p) != [4]int{1, 1, 1, 1} {
		t.Fatal("expired fresh extension persisted", err)
	}
}

func TestPostgresRetentionMarkerFencePrecedesTenantAndSubjectLocks(t *testing.T) {
	for _, stage := range []string{"guard", "hold", "override"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, p)
			if _, err := p.Exec(t.Context(), `INSERT INTO products(id,tenant_id,name,slug) VALUES('p','tenant','Product','p')`); err != nil {
				t.Fatal(err)
			}
			c, err := BuildRetentionMarkerCommands(store)
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
			done := make(chan error, 1)
			go func() {
				a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}
				in := operationsapp.RetentionMarkerInput{ScopeType: "product", ScopeID: "p", Reason: "review", Owner: "legal"}
				var err error
				switch stage {
				case "guard":
					err = c.AuthorizeRetentionMarker(ctx, a, in.ScopeType, in.ScopeID)
				case "hold":
					_, err = c.CreateLegalHold(ctx, a, in)
				case "override":
					_, err = c.CreateRetentionOverride(ctx, a, operationsapp.RetentionOverrideInput{RetentionMarkerInput: in, RetentionUntil: time.Now().Add(time.Hour)})
				}
				done <- err
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("marker bypassed tenant fence", err)
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
					if _, err := leader.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`); err != nil {
						t.Fatal("tenant lock preceded fence", err)
					}
					if _, err := leader.Exec(ctx, `SELECT id FROM products WHERE id='p' FOR UPDATE NOWAIT`); err != nil {
						t.Fatal("subject lock preceded fence", err)
					}
					if err := leader.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("marker did not resume", ctx.Err())
					}
					want := [4]int{}
					if stage != "guard" {
						want = [4]int{1, 1, 0, 0}
					}
					if retentionMarkerCounts(t, p) != want {
						t.Fatal("fenced marker wrote wrong effects")
					}
					return
				}
			}
		})
	}
}
