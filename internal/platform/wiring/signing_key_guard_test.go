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
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresSigningKeyGuardsCheckFlatOwnershipAndHoldOuterLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSigningKeyHTTP(t, p)
	c, err := BuildSigningKeyCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	if err := c.AuthorizeSigningKeyRevocation(t.Context(), a, "foreign"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign key guard", err)
	}
	missing := a
	missing.TenantID = "missing"
	if err := c.AuthorizeSigningKeyRotation(t.Context(), missing); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("missing tenant guard", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE signing_keys SET revocation_reason=repeat('x',4097),encrypted_private_key=decode(repeat('ab',9*1024*1024),'hex')WHERE id='old'`); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeSigningKeyRevocation(t.Context(), a, "old"); err != nil {
		t.Fatal("guard decoded lifecycle/private fields", err)
	}
	if signingKeyHTTPCounts(t, p) != [4]int{1, 0, 0, 0} {
		t.Fatal("guard wrote effects")
	}
	if _, err := p.Exec(t.Context(), `UPDATE signing_keys SET revocation_reason=''WHERE id='old'`); err != nil {
		t.Fatal(err)
	}
	x := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeSigningKeyRevocation(ctx, a, "old")
	}}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`, `SELECT id FROM signing_keys WHERE id='old'FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, err = tx.Exec(ctx, sql)
			_ = tx.Rollback(context.WithoutCancel(ctx))
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "55P03" {
				t.Fatal("key replay guard released outer locks", err)
			}
		}
		v, err := c.RevokeSigningKey(ctx, a, "old", verificationapp.SigningKeyRevocationInput{Reason: "scheduled"})
		return 200, signingKeyToLegacy(v), err
	}
	for range 2 {
		if _, _, err := x.WithBody(t.Context(), a, "POST", "/v1/signing-keys/old/revoke", "outer", []byte(`{}`), run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || signingKeyHTTPCounts(t, p) != [4]int{1, 1, 1, 0} {
		t.Fatal("outer revoke replay duplicated lifecycle")
	}
}

func TestPostgresSigningKeyNativeDuplicateDeliveryCommitsOneEffect(t *testing.T) {
	for _, route := range signingKeyHTTPRoutes {
		t.Run(route.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSigningKeyHTTP(t, p)
			c, err := BuildSigningKeyCommands(store)
			if err != nil {
				t.Fatal(err)
			}
			e, err := BuildDurableCommandExecutor(store)
			if err != nil {
				t.Fatal(err)
			}
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
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
			for range 2 {
				go func() {
					<-start
					s, v, err := e.WithBody(ctx, a, "POST", route.path, "concurrent", []byte(route.body), func(ctx context.Context) error {
						if route.status == 201 {
							return c.AuthorizeSigningKeyRotation(ctx, a)
						}
						return c.AuthorizeSigningKeyRevocation(ctx, a, "old")
					}, func(ctx context.Context) (int, any, error) {
						calls.Add(1)
						if route.status == 201 {
							v, err := c.RotateSigningKey(ctx, a, "scheduled")
							return 201, signingKeyToLegacy(v), err
						}
						v, err := c.RevokeSigningKey(ctx, a, "old", verificationapp.SigningKeyRevocationInput{Reason: "incident", Semantics: "compromised", HistoricalValidityPolicy: "invalidate_all"})
						return 200, signingKeyToLegacy(v), err
					})
					results <- result{s, v, err}
				}()
			}
			close(start)
			var responses [2]string
			for i := range responses {
				select {
				case r := <-results:
					if r.err != nil || r.status != route.status {
						t.Fatal("duplicate key delivery failed", r.err, r.status)
					}
					b, err := json.Marshal(r.value)
					if err != nil {
						t.Fatal(err)
					}
					responses[i] = string(b)
				case <-ctx.Done():
					t.Fatal("key delivery did not release transactions", ctx.Err())
				}
			}
			assertRetentionHTTPReplay(t, responses[0], responses[1])
			if calls.Load() != 1 || signingKeyHTTPCounts(t, p) != [4]int{route.keys, 1, 1, 0} {
				t.Fatal("duplicate delivery created effects")
			}
		})
	}
}

func TestPostgresSigningKeyFencePrecedesTenantAndKeyLocksAndCancels(t *testing.T) {
	for _, stage := range []string{"rotation guard", "revocation guard", "rotate", "revoke", "cancel"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSigningKeyHTTP(t, p)
			c, err := BuildSigningKeyCommands(store)
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
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
			go func() {
				var err error
				switch stage {
				case "rotation guard":
					err = c.AuthorizeSigningKeyRotation(childCtx, a)
				case "rotate":
					_, err = c.RotateSigningKey(childCtx, a, "scheduled")
				case "revoke":
					_, err = c.RevokeSigningKey(childCtx, a, "old", verificationapp.SigningKeyRevocationInput{Reason: "incident"})
				default:
					err = c.AuthorizeSigningKeyRevocation(childCtx, a, "old")
				}
				done <- err
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("key command bypassed common fence", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
					var blocked bool
					if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if !blocked {
						continue
					}
					for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`, `SELECT id FROM signing_keys WHERE id='old'FOR UPDATE NOWAIT`} {
						if _, err := leader.Exec(ctx, sql); err != nil {
							t.Fatal("root/key lock preceded common fence", err)
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
								t.Fatal("cancelled command completed", err)
							}
						} else if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("key command failed to resume", ctx.Err())
					}
					want := [4]int{1, 0, 0, 0}
					switch stage {
					case "rotate":
						want = [4]int{2, 1, 0, 0}
					case "revoke":
						want = [4]int{1, 1, 0, 0}
					}
					if signingKeyHTTPCounts(t, p) != want {
						t.Fatal("fenced/cancelled command wrote wrong effects")
					}
					if err := c.AuthorizeSigningKeyRevocation(ctx, a, "old"); err != nil {
						t.Fatal("cancelled command leaked transaction", err)
					}
					return
				}
			}
		})
	}
}
