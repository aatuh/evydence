package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresMerkleCreationViewFencePrecedesTenantLock(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Merkle')`); err != nil {
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
		done <- (merkleCreationTransactions{store}).ExecuteMerkleCreation(ctx, func(ctx context.Context, tx verificationapp.MerkleCreationTransaction) error {
			_, err := tx.LockMerkleCreationView(ctx, "tenant")
			return err
		})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("view bypassed common tenant fence", err)
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
			if _, err := leader.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
				cancel()
				_ = leader.Rollback(context.WithoutCancel(ctx))
				<-done
				t.Fatal("tenant row lock preceded common writer fence", err)
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
				t.Fatal("view failed to release transaction", ctx.Err())
			}
			return
		}
	}
}

func TestPostgresMerkleCreationGuardLocksJoinOuterReplayTransaction(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedMerkleCreationHTTP(t, p, store)
	c, err := BuildMerkleCreationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	x := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeMerkleCreation(ctx, a) }}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`)
		_ = tx.Rollback(context.WithoutCancel(ctx))
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55P03" {
			t.Fatal("replay guard released tenant lock", err)
		}
		tx, err = p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT id FROM audit_chain_entries WHERE id='entry_1'FOR UPDATE NOWAIT`)
		_ = tx.Rollback(context.WithoutCancel(ctx))
		if err != nil {
			t.Fatal("replay guard locked chain leaves", err)
		}
		v, err := c.CreateMerkleBatch(ctx, a, verificationapp.CreateMerkleBatchInput{})
		return 201, domain.MerkleBatch(v), err
	}
	for range 2 {
		if _, _, err := x.WithBody(t.Context(), a, "POST", "/v1/merkle-batches", "outer", []byte(`{}`), run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || merkleCreationHTTPCounts(t, p) != [6]int{1, 1, 1, 4, 1, 0} {
		t.Fatal("outer replay duplicated Merkle effects")
	}
}

func TestPostgresMerkleCreationNativeDuplicateDeliveryCommitsOneEffect(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedMerkleCreationHTTP(t, p, store)
	c, err := BuildMerkleCreationCommands(store)
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
			s, v, err := e.WithBody(ctx, a, "POST", "/v1/merkle-batches", "concurrent", []byte(`{}`), func(ctx context.Context) error { return c.AuthorizeMerkleCreation(ctx, a) }, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := c.CreateMerkleBatch(ctx, a, verificationapp.CreateMerkleBatchInput{})
				return 201, domain.MerkleBatch(v), err
			})
			results <- result{s, v, err}
		}()
	}
	close(start)
	var responses [2]string
	for i := range responses {
		select {
		case r := <-results:
			if r.status != 201 || r.err != nil {
				t.Fatal("duplicate Merkle delivery failed", r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			responses[i] = string(b)
		case <-ctx.Done():
			t.Fatal("duplicate delivery failed to release transactions", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, responses[0], responses[1])
	if calls.Load() != 1 || merkleCreationHTTPCounts(t, p) != [6]int{1, 1, 1, 4, 1, 0} {
		t.Fatal("concurrent delivery duplicated Merkle effects")
	}
}

func TestPostgresMerkleCreationCancelledFenceWaitHasNoEffectsOrLeakedLocks(t *testing.T) {
	for _, guardOnly := range []bool{true, false} {
		t.Run(fmt.Sprint(guardOnly), func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedMerkleCreationHTTP(t, p, store)
			c, err := BuildMerkleCreationCommands(store)
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
				if guardOnly {
					done <- c.AuthorizeMerkleCreation(childCtx, a)
				} else {
					_, err := c.CreateMerkleBatch(childCtx, a, verificationapp.CreateMerkleBatchInput{})
					done <- err
				}
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("Merkle command bypassed shared fence", err)
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
					if _, err := leader.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
						t.Fatal("tenant lock preceded writer fence", err)
					}
					cancelChild()
					if err := leader.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if !errors.Is(err, context.Canceled) {
							t.Fatal("cancelled command completed", err)
						}
					case <-ctx.Done():
						t.Fatal("cancelled command failed to release transaction", ctx.Err())
					}
					if merkleCreationHTTPCounts(t, p) != [6]int{0, 0, 0, 3, 0, 0} {
						t.Fatal("cancelled command published effects")
					}
					if err := c.AuthorizeMerkleCreation(ctx, a); err != nil {
						t.Fatal("cancelled command leaked fence/transaction", err)
					}
					return
				}
			}
		})
	}
}
