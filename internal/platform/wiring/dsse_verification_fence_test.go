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

func TestPostgresDSSESubjectFencePrecedesOwnershipLocks(t *testing.T) {
	_, p := openHTMLReportWiringStore(t)
	seedDSSEVerification(t, p, false)
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
	done := make(chan error, 1)
	go func() {
		_, err := repositories.New(child).Verification.(verificationapp.DSSEVerificationReader).ResolveDSSEVerificationSubject(ctx, "tenant", "attestation")
		done <- err
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("DSSE reader bypassed common fence", err)
		case <-ctx.Done():
			t.Fatal("DSSE reader did not reach common fence", ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory' AND $2=ANY(pg_blocking_pids(pid)))`, child.Conn().PgConn().PID(), leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				continue
			}
			for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT id FROM products WHERE id='product' FOR UPDATE NOWAIT`, `SELECT id FROM projects WHERE id='project' FOR UPDATE NOWAIT`, `SELECT id FROM releases WHERE id='release' FOR UPDATE NOWAIT`, `SELECT id FROM build_runs WHERE id='build' FOR UPDATE NOWAIT`, `SELECT id FROM evidence_items WHERE id='evidence' FOR UPDATE NOWAIT`, `SELECT id FROM build_attestations WHERE id='attestation' FOR UPDATE NOWAIT`} {
				if _, err := leader.Exec(ctx, sql); err != nil {
					t.Fatal("ownership lock preceded common fence", err)
				}
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
				t.Fatal("DSSE reader did not release", ctx.Err())
			}
			return
		}
	}
}

func TestPostgresDSSEGuardOwnershipLocksJoinOuterReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedDSSEVerification(t, p, false)
	c, err := BuildDSSEVerificationCommands(store, objects)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"verify:read"}}
	x := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return c.AuthorizeDSSEVerification(ctx, a, "attestation")
	}}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		for _, tc := range []struct {
			sql     string
			blocked bool
		}{{`SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, true}, {`SELECT id FROM products WHERE id='product' FOR UPDATE NOWAIT`, true}, {`SELECT id FROM projects WHERE id='project' FOR UPDATE NOWAIT`, true}, {`SELECT id FROM releases WHERE id='release' FOR UPDATE NOWAIT`, true}, {`SELECT id FROM build_runs WHERE id='build' FOR UPDATE NOWAIT`, true}, {`SELECT id FROM evidence_items WHERE id='evidence' FOR UPDATE NOWAIT`, true}, {`SELECT id FROM build_attestations WHERE id='attestation' FOR UPDATE NOWAIT`, true}, {`SELECT id FROM dsse_trust_roots WHERE id='root' FOR UPDATE NOWAIT`, false}, {`SELECT digest FROM object_payloads WHERE tenant_id='tenant' FOR UPDATE NOWAIT`, false}, {`SELECT id FROM artifacts WHERE id='artifact' FOR UPDATE NOWAIT`, false}} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, err = tx.Exec(ctx, tc.sql)
			_ = tx.Rollback(context.WithoutCancel(ctx))
			var pe *pgconn.PgError
			if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
				t.Fatal("DSSE guard released ownership lock or locked inspection facts", tc.sql, err)
			}
		}
		v, err := c.VerifyDSSEAttestationSignature(ctx, a, "attestation")
		return 200, domain.VerificationResultFromContextModel(v), err
	}
	for range 2 {
		if _, _, err := x.WithBody(t.Context(), a, "POST", "/v1/build-attestations/attestation/verify-signature", "outer", []byte(`{}`), run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || objects.reads != 1 || dsseHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 1} {
		t.Fatal("outer DSSE replay duplicated inspection or effects")
	}
}

func TestPostgresDSSENativeDuplicateDeliveryCommitsOneReceipt(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedDSSEVerification(t, p, false)
	c, err := BuildDSSEVerificationCommands(store, objects)
	if err != nil {
		t.Fatal(err)
	}
	e, err := BuildDurableCommandExecutor(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"verify:read"}}
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
			s, v, err := e.WithBody(ctx, a, "POST", "/v1/build-attestations/attestation/verify-signature", "duplicate", []byte(`{}`), func(ctx context.Context) error { return c.AuthorizeDSSEVerification(ctx, a, "attestation") }, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := c.VerifyDSSEAttestationSignature(ctx, a, "attestation")
				return 200, domain.VerificationResultFromContextModel(v), err
			})
			results <- result{s, v, err}
		}()
	}
	close(start)
	var replies [2]string
	for i := range replies {
		select {
		case r := <-results:
			if r.err != nil || r.status != 200 {
				t.Fatal("duplicate DSSE delivery failed", r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[i] = string(b)
		case <-ctx.Done():
			t.Fatal("duplicate DSSE delivery leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, replies[0], replies[1])
	if calls.Load() != 1 || objects.reads != 1 || dsseHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 1} {
		t.Fatal("duplicate DSSE delivery reverified or duplicated effects")
	}
}

func TestPostgresDSSECancelledFenceWaitReleasesWithoutEffects(t *testing.T) {
	for _, guardOnly := range []bool{true, false} {
		t.Run(fmt.Sprint(guardOnly), func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			objects := seedDSSEVerification(t, p, false)
			c, err := BuildDSSEVerificationCommands(store, objects)
			if err != nil {
				t.Fatal(err)
			}
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"verify:read"}}
			leader, err := p.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
			if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if guardOnly {
					done <- c.AuthorizeDSSEVerification(ctx, a, "attestation")
				} else {
					_, err := c.VerifyDSSEAttestationSignature(ctx, a, "attestation")
					done <- err
				}
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
		waitForFence:
			for {
				select {
				case err := <-done:
					t.Fatal("DSSE operation bypassed fence", err)
				case <-ctx.Done():
					t.Fatal("DSSE operation did not reach fence", ctx.Err())
				case <-ticker.C:
					var blocked bool
					if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked {
						break waitForFence
					}
				}
			}
			for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT id FROM evidence_items WHERE id='evidence' FOR UPDATE NOWAIT`} {
				if _, err := leader.Exec(ctx, sql); err != nil {
					t.Fatal("row lock preceded common fence", err)
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("DSSE cancellation lost", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled DSSE operation leaked transaction")
			}
			if objects.reads != 0 || dsseHTTPCounts(t, p) != [5]int{} {
				t.Fatal("cancelled DSSE operation read bytes or wrote effects")
			}
			if err := leader.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := c.AuthorizeDSSEVerification(t.Context(), a, "attestation"); err != nil {
				t.Fatal("cancelled DSSE operation left locks", err)
			}
		})
	}
}
