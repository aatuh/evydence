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
	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresBackupAndAuditViewsFencePrecedesTenantLock(t *testing.T) {
	for _, kind := range []string{"backup", "audit"} {
		t.Run(kind, func(t *testing.T) {
			_, p := openHTMLReportWiringStore(t)
			if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Backup')`); err != nil {
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
			child, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = child.Rollback(context.WithoutCancel(ctx)) }()
			r := repositories.New(child)
			done := make(chan error, 1)
			go func() {
				if kind == "backup" {
					_, err := r.Integrity.(verificationapp.BackupStateCommitmentReader).ReadBackupStateCommitment(ctx, "tenant")
					done <- err
				} else {
					_, err := r.Verification.(verificationapp.AuditChainVerificationReader).LockAuditChainVerification(ctx, "tenant")
					done <- err
				}
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("view bypassed common fence", err)
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
						t.Fatal("tenant row lock preceded common fence", err)
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
		})
	}
}

func TestPostgresBackupGenerationGuardLocksJoinOuterReplayWithoutAuditReads(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBackupGenerationHTTP(t, p, store)
	c, err := BuildBackupGenerationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"admin"}}
	x := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeBackupGeneration(ctx, a) }}
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
			t.Fatal("guard released tenant root lock", err)
		}
		tx, err = p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT id FROM audit_chain_entries WHERE id='backup-seed'FOR UPDATE NOWAIT`)
		_ = tx.Rollback(context.WithoutCancel(ctx))
		if err != nil {
			t.Fatal("replay guard locked audit entries", err)
		}
		v, err := c.GenerateBackupManifest(ctx, a)
		return 201, domain.BackupManifestFromContextModel(v), err
	}
	for range 2 {
		if _, _, err := x.WithBody(t.Context(), a, "POST", "/v1/backup-manifests", "outer", []byte(`{}`), run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || backupGenerationHTTPCounts(t, p) != [5]int{1, 2, 1, 0, 0} {
		t.Fatal("outer replay duplicated backup effects")
	}
}

func TestPostgresBackupGenerationNativeDuplicateDeliveryCommitsOneEffect(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBackupGenerationHTTP(t, p, store)
	c, err := BuildBackupGenerationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	e, err := BuildDurableCommandExecutor(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"admin"}}
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
			s, v, err := e.WithBody(ctx, a, "POST", "/v1/backup-manifests", "concurrent", []byte(`{}`), func(ctx context.Context) error { return c.AuthorizeBackupGeneration(ctx, a) }, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := c.GenerateBackupManifest(ctx, a)
				return 201, domain.BackupManifestFromContextModel(v), err
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
				t.Fatal("duplicate backup delivery failed", r.err, r.status)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			responses[i] = string(b)
		case <-ctx.Done():
			t.Fatal("duplicate backup delivery did not release transactions", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, responses[0], responses[1])
	if calls.Load() != 1 || backupGenerationHTTPCounts(t, p) != [5]int{1, 2, 1, 0, 0} {
		t.Fatal("concurrent delivery duplicated backup effects")
	}
}

func TestPostgresBackupGenerationCancelledFenceWaitHasNoEffectsOrLeakedLocks(t *testing.T) {
	for _, guardOnly := range []bool{true, false} {
		t.Run(fmt.Sprint(guardOnly), func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedBackupGenerationHTTP(t, p, store)
			c, err := BuildBackupGenerationCommands(store)
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
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"admin"}}
			go func() {
				if guardOnly {
					done <- c.AuthorizeBackupGeneration(childCtx, a)
				} else {
					_, err := c.GenerateBackupManifest(childCtx, a)
					done <- err
				}
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("backup bypassed common fence", err)
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
						t.Fatal("backup tenant lock preceded fence", err)
					}
					cancelChild()
					if err := leader.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if !errors.Is(err, context.Canceled) {
							t.Fatal("cancelled backup completed", err)
						}
					case <-ctx.Done():
						t.Fatal("cancelled backup did not release transaction", ctx.Err())
					}
					if backupGenerationHTTPCounts(t, p) != [5]int{0, 1, 0, 0, 0} {
						t.Fatal("cancelled backup published effects")
					}
					if err := c.AuthorizeBackupGeneration(ctx, a); err != nil {
						t.Fatal("cancelled backup leaked fence/transaction", err)
					}
					return
				}
			}
		})
	}
}
