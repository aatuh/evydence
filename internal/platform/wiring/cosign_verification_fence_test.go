package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

func TestPostgresCosignSubjectFencePrecedesTenantAndArtifactLocks(t *testing.T) {
	_, p := openHTMLReportWiringStore(t)
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Cosign')`); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant','Artifact','application/json',$1,1)`, `INSERT INTO artifact_signatures(id,tenant_id,artifact_id,subject_digest,algorithm,signature,verification_status,schema_version,created_at)VALUES('signature','tenant','artifact',$1,'cosign','ignored','recorded','artifact-signature.v1.0.0',now())`} {
		if _, err := p.Exec(t.Context(), sql, "sha256:"+strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
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
	done := make(chan error, 1)
	go func() {
		_, err := repositories.New(child).Verification.(verificationapp.CosignSnapshotReader).ResolveCosignSubject(ctx, "tenant", "signature")
		done <- err
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("subject reader bypassed common fence", err)
		case <-ctx.Done():
			t.Fatal("reader did not reach common fence", ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory'AND $2=ANY(pg_blocking_pids(pid)))`, child.Conn().PgConn().PID(), leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				continue
			}
			for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`, `SELECT id FROM artifacts WHERE id='artifact'FOR UPDATE NOWAIT`, `SELECT id FROM artifact_signatures WHERE id='signature'FOR UPDATE NOWAIT`} {
				if _, err := leader.Exec(ctx, sql); err != nil {
					t.Fatal("subject lock preceded common fence", err)
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
				t.Fatal("subject reader failed to release", ctx.Err())
			}
			return
		}
	}
}

func TestPostgresCosignGuardLocksJoinOuterReplayWithoutMutableFactReads(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects, verifier := seedCosignHTTP(t, p)
	c, err := BuildCosignVerificationCommands(store, objects, verifier)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"verify:read"}}
	in := verificationapp.VerifyCosignInput{ArtifactSignatureID: "signature", ExpectedIdentity: "foo!oidc.local", ExpectedIssuer: "http://oidc.local:8080", Mode: verificationapp.CosignVerificationModeKeyless, Offline: true}
	x := app.IdempotencyUnitOfWork{Transactions: store, Authorize: func(ctx context.Context, _ app.Repositories) error { return c.AuthorizeCosignVerification(ctx, a, in) }}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		for _, tc := range []struct {
			sql     string
			blocked bool
		}{{`SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`, true}, {`SELECT id FROM artifacts WHERE id='artifact'FOR UPDATE NOWAIT`, true}, {`SELECT id FROM artifact_signatures WHERE id='signature'FOR UPDATE NOWAIT`, true}, {`SELECT id FROM container_images WHERE id='image-a'FOR UPDATE NOWAIT`, false}, {`SELECT digest FROM object_payloads WHERE tenant_id='tenant'FOR UPDATE NOWAIT`, false}} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, err = tx.Exec(ctx, tc.sql)
			_ = tx.Rollback(context.WithoutCancel(ctx))
			var pe *pgconn.PgError
			if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
				t.Fatal("guard released ownership lock or locked mutable facts", tc.sql, err)
			}
		}
		v, err := c.VerifyCosign(ctx, a, in)
		return 200, domain.CosignVerificationFromContextModel(v), err
	}
	for range 2 {
		if _, _, err := x.WithBody(t.Context(), a, "POST", "/v1/artifact-signatures/signature/verify-cosign", "outer", []byte(cosignHTTPPolicy), run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || objects.reads != 1 || cosignHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 0, 0} {
		t.Fatal("outer replay reran verification or duplicated effects")
	}
}

func TestPostgresCosignNativeDuplicateDeliveryCommitsOneEffect(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects, verifier := seedCosignHTTP(t, p)
	c, err := BuildCosignVerificationCommands(store, objects, verifier)
	if err != nil {
		t.Fatal(err)
	}
	e, err := BuildDurableCommandExecutor(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"verify:read"}}
	in := verificationapp.VerifyCosignInput{ArtifactSignatureID: "signature", ExpectedIdentity: "foo!oidc.local", ExpectedIssuer: "http://oidc.local:8080", Mode: verificationapp.CosignVerificationModeKeyless, Offline: true}
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
			s, v, err := e.WithBody(ctx, a, "POST", "/v1/artifact-signatures/signature/verify-cosign", "concurrent", []byte(cosignHTTPPolicy), func(ctx context.Context) error { return c.AuthorizeCosignVerification(ctx, a, in) }, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := c.VerifyCosign(ctx, a, in)
				return 200, domain.CosignVerificationFromContextModel(v), err
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
				t.Fatal("duplicate verification failed", r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[i] = string(b)
		case <-ctx.Done():
			t.Fatal("duplicate delivery did not release transactions", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, replies[0], replies[1])
	if calls.Load() != 1 || objects.reads != 1 || cosignHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 0, 0} {
		t.Fatal("duplicate delivery reverified bundle or duplicated receipts")
	}
}

func TestPostgresCosignCancelledFenceWaitHasNoEffectsOrLeakedLocks(t *testing.T) {
	for _, guardOnly := range []bool{true, false} {
		t.Run(fmt.Sprint(guardOnly), func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			objects, verifier := seedCosignHTTP(t, p)
			c, err := BuildCosignVerificationCommands(store, objects, verifier)
			if err != nil {
				t.Fatal(err)
			}
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"verify:read"}}
			in := verificationapp.VerifyCosignInput{ArtifactSignatureID: "signature", Mode: verificationapp.CosignVerificationModeKey, Offline: true}
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
					done <- c.AuthorizeCosignVerification(ctx, a, in)
				} else {
					_, err := c.VerifyCosign(ctx, a, in)
					done <- err
				}
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
		waitForFence:
			for {
				select {
				case err := <-done:
					t.Fatal("verification bypassed fence", err)
				case <-ctx.Done():
					t.Fatal("verification did not reach fence", ctx.Err())
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
			for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`, `SELECT id FROM artifacts WHERE id='artifact'FOR UPDATE NOWAIT`} {
				if _, err := leader.Exec(ctx, sql); err != nil {
					t.Fatal("row lock preceded common fence", err)
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled verification leaked transaction")
			}
			if objects.reads != 0 || cosignHTTPCounts(t, p) != [6]int{} {
				t.Fatal("cancelled verification inspected payload or wrote")
			}
			if err := leader.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := c.AuthorizeCosignVerification(t.Context(), a, in); err != nil {
				t.Fatal("cancelled operation left locks", err)
			}
		})
	}
}
