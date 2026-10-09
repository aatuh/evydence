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
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresSubjectVerificationFencePrecedesAllOwnershipLocks(t *testing.T) {
	_, p := openHTMLReportWiringStore(t)
	seedSubjectVerificationScopes(t, p)
	for _, tc := range subjectScopeCases() {
		t.Run(tc.kind, func(t *testing.T) {
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
				_, err := repositories.New(child).Verification.(verificationapp.SubjectVerificationScopeReader).ResolveSubjectVerificationScope(ctx, "tenant", tc.kind, tc.id)
				done <- err
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("generic scope bypassed common fence", tc.kind, err)
				case <-ctx.Done():
					t.Fatal("generic scope did not reach fence", tc.kind, ctx.Err())
				case <-ticker.C:
					var blocked bool
					if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory'AND $2=ANY(pg_blocking_pids(pid)))`, childPID, leaderPID).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if !blocked {
						continue
					}
					for _, table := range []string{"tenants", "products", "projects", "releases", "build_runs", "evidence_items", "build_attestations", "artifacts", "artifact_signatures", "release_bundles", "merkle_batches", "backup_manifests"} {
						if _, err := leader.Exec(ctx, "SELECT id FROM "+table+" FOR UPDATE NOWAIT"); err != nil {
							t.Fatal("ownership lock preceded fence", tc.kind, table, err)
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
						t.Fatal("generic guard leaked fence waiter", ctx.Err())
					}
					return
				}
			}
		})
	}
}

func TestPostgresSubjectVerificationConcurrentDeliveryCommitsOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSubjectVerificationScopes(t, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
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
			status, value, err := opts.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/verify", "duplicate", []byte(subjectVerificationBody("backup_manifest", "backup")), func(ctx context.Context) error {
				return opts.SubjectVerification.AuthorizeSubjectVerification(ctx, a, "backup_manifest", "backup")
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := opts.SubjectVerification.VerifySubject(ctx, a, "backup_manifest", "backup")
				return 200, domain.VerificationResultFromContextModel(v), err
			})
			done <- reply{status, value, err}
		}()
	}
	close(start)
	var replies [2]string
	for i := range replies {
		select {
		case r := <-done:
			if r.err != nil || r.status != 200 {
				t.Fatal("duplicate generic delivery failed", r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[i] = string(b)
		case <-ctx.Done():
			t.Fatal("duplicate generic delivery leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, replies[0], replies[1])
	if calls.Load() != 1 || dsseHTTPCounts(t, p) != [5]int{1, 1, 1, 0, 1} {
		t.Fatal("duplicate generic delivery repeated effects", calls.Load(), dsseHTTPCounts(t, p))
	}
}

func TestPostgresSubjectVerificationCancelledGuardReleasesFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedSubjectVerificationScopes(t, p)
	opts := subjectVerificationOptions(t, store, objects)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
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
	go func() { done <- opts.SubjectVerification.AuthorizeSubjectVerification(ctx, a, "audit_chain", "") }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
waitForFence:
	for {
		select {
		case err := <-done:
			t.Fatal("generic guard bypassed fence", err)
		case <-ctx.Done():
			t.Fatal("generic guard did not reach fence", ctx.Err())
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
			t.Fatal("generic cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled generic guard leaked transaction")
	}
	if err := leader.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := opts.SubjectVerification.AuthorizeSubjectVerification(t.Context(), a, "audit_chain", ""); err != nil {
		t.Fatal("cancelled generic guard retained locks", err)
	}
	if objects.reads != 0 || dsseHTTPCounts(t, p) != [5]int{} {
		t.Fatal("cancelled guard inspected/wrote effects")
	}
}

func TestPostgresSubjectVerificationGuardLocksJoinOuterReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSubjectVerificationScopes(t, p)
	options := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
	for _, tc := range subjectScopeCases() {
		t.Run(tc.kind, func(t *testing.T) {
			locked := map[string]bool{"tenants": true}
			switch tc.kind {
			case "evidence_item", "build_attestation":
				for _, table := range []string{"products", "projects", "releases", "build_runs", "evidence_items"} {
					locked[table] = true
				}
				if tc.kind == "build_attestation" {
					locked["build_attestations"] = true
				}
			case "release_bundle", "audit_chain_release_manifest":
				locked["products"], locked["releases"], locked["release_bundles"] = true, true, true
			case "artifact_signature":
				locked["artifacts"], locked["artifact_signatures"] = true, true
			case "merkle_batch", "audit_chain_checkpoint":
				locked["merkle_batches"] = true
			case "backup_manifest":
				locked["backup_manifests"] = true
			}
			runCalls := 0
			for range 2 {
				_, _, err := options.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/verify", tc.kind, []byte(subjectVerificationBody(tc.kind, tc.id)), func(ctx context.Context) error {
					return options.SubjectVerification.AuthorizeSubjectVerification(ctx, a, tc.kind, tc.id)
				}, func(ctx context.Context) (int, any, error) {
					runCalls++
					for _, table := range []string{"tenants", "products", "projects", "releases", "build_runs", "evidence_items", "build_attestations", "artifacts", "artifact_signatures", "release_bundles", "merkle_batches", "backup_manifests", "dsse_trust_roots", "object_payloads"} {
						probe, err := p.Begin(ctx)
						if err != nil {
							return 0, nil, err
						}
						_, err = probe.Exec(ctx, "SELECT 1 FROM "+table+" FOR UPDATE NOWAIT")
						_ = probe.Rollback(context.WithoutCancel(ctx))
						var pe *pgconn.PgError
						if locked[table] && (!errors.As(err, &pe) || pe.Code != "55P03") || !locked[table] && err != nil {
							t.Fatal("guard released ownership or locked inspection facts", tc.kind, table, err)
						}
					}
					return 200, map[string]string{"fixture": "scope-only"}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if runCalls != 1 {
				t.Fatal("guard transaction broke replay", runCalls)
			}
		})
	}
	if dsseHTTPCounts(t, p) != [5]int{0, 0, 9, 0, 0} {
		t.Fatal("read-only guard published inspection effects", dsseHTTPCounts(t, p))
	}
}
