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
	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresArtifactSignatureCreationFencePrecedesOwnershipLocks(t *testing.T) {
	_, p := openHTMLReportWiringStore(t)
	seedArtifactSignatureHTTP(t, p)
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
	childPID, leaderPID := child.Conn().PgConn().PID(), leader.Conn().PgConn().PID()
	done := make(chan error, 1)
	go func() {
		_, err := repositories.New(child).SupplyChain.(interface {
			LockArtifactSignatureCreationScope(context.Context, string, string) (application.ResourceReferences, error)
		}).LockArtifactSignatureCreationScope(ctx, "tenant", "artifact")
		done <- err
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
waitForFence:
	for {
		select {
		case err := <-done:
			t.Fatal("signature scope bypassed common fence", err)
		case <-ctx.Done():
			t.Fatal("signature scope did not reach fence", ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory'AND $2=ANY(pg_blocking_pids(pid)))`, childPID, leaderPID).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break waitForFence
			}
		}
	}
	for _, table := range []string{"tenants", "artifacts"} {
		if _, err := leader.Exec(ctx, "SELECT id FROM "+table+" FOR UPDATE NOWAIT"); err != nil {
			t.Fatal("row lock preceded writer fence", table, err)
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
		t.Fatal("signature scope fence did not release")
	}
}

func TestPostgresArtifactSignatureCreationGuardLocksJoinOuterReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedArtifactSignatureHTTP(t, p)
	opts := subjectVerificationOptions(t, store, objects)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	in := verificationapp.CreateArtifactSignatureInput{ArtifactID: "artifact", Algorithm: "cosign", Signature: "recorded"}
	calls := 0
	for range 2 {
		_, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/artifact-signatures", "joined", []byte(`{}`), func(ctx context.Context) error {
			return opts.ArtifactSignatureCommands.AuthorizeArtifactSignatureCreation(ctx, a, in)
		}, func(ctx context.Context) (int, any, error) {
			calls++
			for _, tc := range []struct {
				table   string
				blocked bool
			}{{"tenants", true}, {"artifacts", true}, {"build_runs", false}, {"products", false}, {"object_payloads", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return 0, nil, err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" FOR UPDATE NOWAIT")
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("signature scope lost ownership locks or locked unrelated facts", tc, err)
				}
			}
			v, err := opts.ArtifactSignatureCommands.CreateArtifactSignature(ctx, a, in)
			return 201, domain.ArtifactSignature{ID: v.ID}, err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || objects.stages != 0 || artifactSignatureHTTPCounts(t, p) != [6]int{1, 1, 0, 0, 1, 0} {
		t.Fatal("joined no-payload signature replay changed effects", calls, artifactSignatureHTTPCounts(t, p))
	}
}

func TestPostgresArtifactSignatureConcurrentDeliveryStagesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedArtifactSignatureHTTP(t, p)
	opts := subjectVerificationOptions(t, store, objects)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	in := verificationapp.CreateArtifactSignatureInput{ArtifactID: "artifact", Algorithm: "cosign", Signature: "recorded", RawPayload: []byte(`{"opaque":true}`), PayloadMediaType: "application/json"}
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
			s, v, err := opts.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/artifact-signatures", "duplicate", []byte(`{}`), func(ctx context.Context) error {
				return opts.ArtifactSignatureCommands.AuthorizeArtifactSignatureCreation(ctx, a, in)
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := opts.ArtifactSignatureCommands.CreateArtifactSignature(ctx, a, in)
				return 201, domain.ArtifactSignature{ID: v.ID, TenantID: v.TenantID, ArtifactID: v.ArtifactID, SubjectDigest: v.SubjectDigest, Algorithm: v.Algorithm, Signature: v.Signature, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, VerificationStatus: v.VerificationStatus, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
			})
			done <- reply{s, v, err}
		}()
	}
	close(start)
	var replies [2]string
	for i := range replies {
		select {
		case r := <-done:
			if r.status != 201 || r.err != nil {
				t.Fatal("concurrent signature delivery failed", r.status, r.err)
			}
			raw, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[i] = string(raw)
		case <-ctx.Done():
			t.Fatal("concurrent signature delivery leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, replies[0], replies[1])
	if calls.Load() != 1 || objects.stages != 1 || artifactSignatureHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatal("concurrent delivery staged or committed twice", calls.Load(), objects.stages, artifactSignatureHTTPCounts(t, p))
	}
}

func TestPostgresArtifactSignatureCancelledGuardReleasesFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedArtifactSignatureHTTP(t, p)
	opts := subjectVerificationOptions(t, store, objects)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"evidence:write"}}
	in := verificationapp.CreateArtifactSignatureInput{ArtifactID: "artifact", Algorithm: "cosign", Signature: "recorded"}
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
	go func() { done <- opts.ArtifactSignatureCommands.AuthorizeArtifactSignatureCreation(ctx, a, in) }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
waitForFence:
	for {
		select {
		case err := <-done:
			t.Fatal("signature guard bypassed common fence", err)
		case <-ctx.Done():
			t.Fatal("signature guard did not reach fence", ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break waitForFence
			}
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("signature cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled signature guard leaked transaction")
	}
	if err := leader.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := opts.ArtifactSignatureCommands.AuthorizeArtifactSignatureCreation(t.Context(), a, in); err != nil {
		t.Fatal("cancelled guard left ownership locks", err)
	}
	if objects.stages != 0 || artifactSignatureHTTPCounts(t, p) != [6]int{} {
		t.Fatal("cancelled guard staged or wrote effects")
	}
}
