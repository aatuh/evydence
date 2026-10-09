package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func authorizeSourceWriteNative(ctx context.Context, o httpapi.ServerOptions, a domain.Actor, tc sourceWriteNativeCase) error {
	switch tc.table {
	case "source_commits":
		return o.SourceCommitCommands.AuthorizeSourceCommitRecording(ctx, a, integrationapp.RecordSourceCommitInput{RepositoryID: "repo", SHA: strings.Repeat("ab", 20)})
	case "source_branches":
		return o.SourceBranchCommands.AuthorizeSourceBranchUpsert(ctx, a, integrationapp.UpsertSourceBranchInput{RepositoryID: "repo", Name: "main", HeadCommitID: "head"})
	default:
		return o.PullRequestCommands.AuthorizePullRequestRecording(ctx, a, integrationapp.RecordPullRequestInput{RepositoryID: "repo", ProviderID: "17", Title: "Change", State: "open", HeadCommitID: "head"})
	}
}
func runSourceWriteNative(ctx context.Context, o httpapi.ServerOptions, a domain.Actor, tc sourceWriteNativeCase) (int, any, error) {
	switch tc.table {
	case "source_commits":
		v, err := o.SourceCommitCommands.RecordSourceCommit(ctx, a, integrationapp.RecordSourceCommitInput{RepositoryID: "repo", SHA: strings.Repeat("ab", 20), Author: "Author", Message: " exact sensitive message "})
		return 201, sourceCommitToDTO(v), err
	case "source_branches":
		v, err := o.SourceBranchCommands.UpsertSourceBranch(ctx, a, integrationapp.UpsertSourceBranchInput{RepositoryID: "repo", Name: "main", HeadCommitID: "head", Protected: true, ProtectionHash: "opaque"})
		return 201, sourceBranchToDTO(v), err
	default:
		v, err := o.PullRequestCommands.RecordPullRequest(ctx, a, integrationapp.RecordPullRequestInput{RepositoryID: "repo", ProviderID: "17", Title: "Change", State: "open", HeadCommitID: "head"})
		return 201, pullRequestToDTO(v), err
	}
}

func TestPostgresSourceWritesGuardLocksCurrentIdentitiesThroughOuterReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceWritesNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	for _, tc := range sourceWriteNativeCases() {
		t.Run(tc.table, func(t *testing.T) {
			calls, guards := 0, 0
			for range 2 {
				_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", tc.path, "locks", []byte(tc.body), func(ctx context.Context) error {
					if err := authorizeSourceWriteNative(ctx, o, a, tc); err != nil {
						return err
					}
					guards++
					for _, probeCase := range []struct {
						table, id string
						blocked   bool
					}{{"source_commits", "head", tc.table != "source_commits"}, {"tenants", "tenant", true}, {"source_repositories", "repo", true}, {"projects", "project", true}, {"products", "product", true}, {"source_repositories", "other-repo", false}, {"source_commits", "other-head", false}, {"sso_sessions", "operator-session", false}} {
						probe, err := p.Begin(ctx)
						if err != nil {
							return err
						}
						_, err = probe.Exec(ctx, "SELECT 1 FROM "+probeCase.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", probeCase.id)
						_ = probe.Rollback(context.WithoutCancel(ctx))
						var pe *pgconn.PgError
						if probeCase.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !probeCase.blocked && err != nil {
							t.Fatal("source guard lost identity lock or locked unrelated metadata", probeCase, err)
						}
					}
					return nil
				}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
				if err != nil {
					t.Fatal(err)
				}
			}
			if calls != 1 || guards != 2 {
				t.Fatal("source replay skipped guard or reran write", calls, guards)
			}
		})
	}
	if got := sourceWritesNativeCounts(t, p); got != [7]int{2, 0, 0, 0, 0, 3, 0} {
		t.Fatal("source guard wrote domain effects", got)
	}
}

func TestPostgresSourceWritesNativeConcurrentReplayExecutesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceWritesNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	for _, tc := range sourceWriteNativeCases() {
		t.Run(tc.table, func(t *testing.T) {
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
					s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", tc.path, "concurrent", []byte(tc.body), func(ctx context.Context) error { return authorizeSourceWriteNative(ctx, o, a, tc) }, func(ctx context.Context) (int, any, error) { calls.Add(1); return runSourceWriteNative(ctx, o, a, tc) })
					done <- reply{s, v, err}
				}()
			}
			close(start)
			var responses [2]string
			for i := range responses {
				select {
				case r := <-done:
					if r.err != nil || r.status != 201 {
						t.Fatal("concurrent source write failed", r.status, r.err)
					}
					b, err := json.Marshal(r.value)
					if err != nil {
						t.Fatal(err)
					}
					responses[i] = string(b)
				case <-ctx.Done():
					t.Fatal("source replay leaked transaction", ctx.Err())
				}
			}
			assertRetentionHTTPReplay(t, responses[0], responses[1])
			if calls.Load() != 1 {
				t.Fatal("source replay executed twice", calls.Load())
			}
		})
	}
	if got := sourceWritesNativeCounts(t, p); got != [7]int{3, 1, 1, 3, 0, 3, 0} {
		t.Fatal("source concurrency duplicated effects", got)
	}
}

func TestPostgresSourceWritesCancelledGuardsReleaseFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceWritesNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	for _, tc := range sourceWriteNativeCases() {
		t.Run(tc.table, func(t *testing.T) {
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
			go func() { done <- authorizeSourceWriteNative(ctx, o, a, tc) }()
			waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
				var blocked bool
				err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
				return blocked, err
			}, done)
			if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("source guard locked tenant before writer fence", err)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("source guard lost cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled source guard leaked transaction")
			}
			if err := leader.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := authorizeSourceWriteNative(t.Context(), o, a, tc); err != nil {
				t.Fatal("cancelled source guard leaked fence", err)
			}
		})
	}
	if got := sourceWritesNativeCounts(t, p); got != [7]int{2, 0, 0, 0, 0, 0, 0} {
		t.Fatal("cancelled source guards wrote effects", got)
	}
}
