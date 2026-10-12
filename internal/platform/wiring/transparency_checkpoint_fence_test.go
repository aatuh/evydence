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

func TestPostgresRecordedCheckpointSourceFencePrecedesTenantLock(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Checkpoint');INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at)VALUES('batch','tenant',1,1,1,'{}','sha256:root','{}','merkle-batch.v1.0.0',now())`); err != nil {
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
		done <- (transparencyCheckpointTransactions{store}).ExecuteTransparencyCheckpoint(ctx, func(ctx context.Context, tx verificationapp.TransparencyCheckpointTransaction) error {
			_, err := tx.ReadTransparencyCheckpointSource(ctx, "tenant", "batch")
			return err
		})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("source bypassed common writer fence", err)
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
				t.Fatal("checkpoint tenant row lock preceded common writer fence", err)
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
				t.Fatal("source failed to release transaction", ctx.Err())
			}
			return
		}
	}
}

func TestPostgresRecordedCheckpointGuardLocksJoinOuterReplayTransaction(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedRecordedCheckpointHTTP(t, p)
	c, err := BuildTransparencyCheckpointCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	x := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeTransparencyCheckpoint(ctx, a, "batch")
	}}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`, `SELECT id FROM merkle_batches WHERE tenant_id='tenant'AND id='batch'FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, err = tx.Exec(ctx, sql)
			_ = tx.Rollback(context.WithoutCancel(ctx))
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "55P03" {
				t.Fatal("replay guard released owned source lock", sql, err)
			}
		}
		if _, err := p.Exec(ctx, `UPDATE merkle_batches SET root_hash=root_hash WHERE tenant_id='other'AND id='foreign'`); err != nil {
			return 0, nil, err
		}
		v, err := c.CreateTransparencyCheckpoint(ctx, a, verificationapp.CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"})
		return 201, domain.TransparencyCheckpoint(v), err
	}
	for range 2 {
		if _, _, err := x.WithBody(t.Context(), a, "POST", "/v1/transparency-checkpoints", "outer", []byte(`{}`), run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || recordedCheckpointHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("outer replay duplicated checkpoint effects")
	}
}

func TestPostgresRecordedCheckpointNativeDuplicateDeliveryCommitsOneEffect(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedRecordedCheckpointHTTP(t, p)
	c, err := BuildTransparencyCheckpointCommands(store)
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
			s, v, err := e.WithBody(ctx, a, "POST", "/v1/transparency-checkpoints", "concurrent", []byte(`{}`), func(ctx context.Context) error { return c.AuthorizeTransparencyCheckpoint(ctx, a, "batch") }, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := c.CreateTransparencyCheckpoint(ctx, a, verificationapp.CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"})
				return 201, domain.TransparencyCheckpoint(v), err
			})
			results <- result{s, v, err}
		}()
	}
	close(start)
	var responses [2]string
	for i := range responses {
		select {
		case r := <-results:
			if r.err != nil || r.status != 201 {
				t.Fatal("duplicate delivery failed", r.err, r.status)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			responses[i] = string(b)
		case <-ctx.Done():
			t.Fatal("duplicate delivery did not release transactions", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, responses[0], responses[1])
	if calls.Load() != 1 || recordedCheckpointHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 0} {
		t.Fatal("concurrent delivery duplicated checkpoint effects")
	}
}

func TestPostgresRecordedCheckpointCancelledFenceWaitHasNoEffectsOrLeakedLocks(t *testing.T) {
	for _, guardOnly := range []bool{true, false} {
		t.Run(fmt.Sprint(guardOnly), func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedRecordedCheckpointHTTP(t, p)
			c, err := BuildTransparencyCheckpointCommands(store)
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
					done <- c.AuthorizeTransparencyCheckpoint(childCtx, a, "batch")
				} else {
					_, err := c.CreateTransparencyCheckpoint(childCtx, a, verificationapp.CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"})
					done <- err
				}
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("checkpoint bypassed common fence", err)
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
						t.Fatal("tenant lock preceded common fence", err)
					}
					cancelChild()
					if err := leader.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if !errors.Is(err, context.Canceled) {
							t.Fatal("cancelled checkpoint completed", err)
						}
					case <-ctx.Done():
						t.Fatal("cancelled checkpoint did not release transaction", ctx.Err())
					}
					if recordedCheckpointHTTPCounts(t, p) != [5]int{} {
						t.Fatal("cancelled checkpoint published effects")
					}
					if err := c.AuthorizeTransparencyCheckpoint(ctx, a, "batch"); err != nil {
						t.Fatal("cancelled checkpoint leaked fence/transaction", err)
					}
					return
				}
			}
		})
	}
}
