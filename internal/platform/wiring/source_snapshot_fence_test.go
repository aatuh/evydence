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
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresSourceSnapshotNativeGuardLocksJoinOuterReplayWithoutChildReads(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	for _, provider := range []string{"github", "gitlab"} {
		body := snapshotNativeBody(t, "org/api", "project", 7)
		v := snapshotDecodePublic(t, snapshotNativeHTTP(t, store, provider, "seed", body, 201))
		calls, guards := 0, 0
		for range 2 {
			_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/collectors/"+provider+"/source-snapshots", "locks", []byte(body), func(ctx context.Context) error {
				if err := o.SourceSnapshotCommands.AuthorizeSourceSnapshot(ctx, a, provider, snapshotNativeInput()); err != nil {
					return err
				}
				guards++
				for _, tc := range []struct {
					table, id string
					blocked   bool
				}{{"tenants", "tenant", true}, {"projects", "project", true}, {"products", "product", true}, {"source_repositories", v.Repository.ID, true}, {"source_commits", v.Commit.ID, false}, {"source_branches", v.Branch.ID, false}, {"pull_requests", v.PullRequest.ID, false}, {"projects", "other-project", false}, {"sso_sessions", "operator-session", false}} {
					probe, err := p.Begin(ctx)
					if err != nil {
						return err
					}
					_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
					_ = probe.Rollback(context.WithoutCancel(ctx))
					var pe *pgconn.PgError
					if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
						t.Fatal("snapshot guard lost parent lock or reached child rows", tc, err)
					}
				}
				return nil
			}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
			if err != nil {
				t.Fatal(err)
			}
		}
		if calls != 1 || guards != 2 {
			t.Fatal("snapshot guard skipped replay check or reran write", calls, guards)
		}
	}
	if got := snapshotNativeCounts(t, p); got != [8]int{2, 2, 2, 2, 8, 0, 4, 0} {
		t.Fatal("read-only snapshot guard wrote effects", got)
	}
}

func TestPostgresSourceSnapshotNativeConcurrentReplayCreatesOneWorkflow(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	for _, provider := range []string{"github", "gitlab"} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		body := snapshotNativeBody(t, "org/api", "project", 7)
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
				s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/collectors/"+provider+"/source-snapshots", "concurrent", []byte(body), func(ctx context.Context) error {
					return o.SourceSnapshotCommands.AuthorizeSourceSnapshot(ctx, a, provider, snapshotNativeInput())
				}, func(ctx context.Context) (int, any, error) {
					calls.Add(1)
					v, err := o.SourceSnapshotCommands.RecordSourceSnapshot(ctx, a, provider, snapshotNativeInput())
					r := v.Repository
					return 201, map[string]any{"repository": domain.SourceRepository{ID: r.ID, TenantID: r.TenantID, ProjectID: r.ProjectID, Provider: r.Provider, FullName: r.FullName, CloneURL: r.CloneURL, DefaultBranch: r.DefaultBranch, SchemaVersion: r.SchemaVersion, CreatedAt: r.CreatedAt}, "commit": sourceCommitToDTO(v.Commit), "branch": sourceBranchToDTO(v.Branch), "pull_request": pullRequestToDTO(v.PullRequest)}, err
				})
				done <- reply{s, v, err}
			}()
		}
		close(start)
		var replies [2]string
		for i := range replies {
			select {
			case r := <-done:
				if r.err != nil || r.status != 201 {
					cancel()
					t.Fatal("concurrent snapshot failed", r.status, r.err)
				}
				raw, err := json.Marshal(r.value)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				replies[i] = string(raw)
			case <-ctx.Done():
				cancel()
				t.Fatal("concurrent snapshot leaked transaction", ctx.Err())
			}
		}
		cancel()
		assertRetentionHTTPReplay(t, replies[0], replies[1])
		if calls.Load() != 1 {
			t.Fatal("snapshot replay executed twice", calls.Load())
		}
	}
	if got := snapshotNativeCounts(t, p); got != [8]int{2, 2, 2, 2, 8, 0, 2, 0} {
		t.Fatal("concurrent snapshot duplicated workflow", got)
	}
}

func TestPostgresSourceSnapshotNativeCancelledGuardReleasesFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	for _, provider := range []string{"github", "gitlab"} {
		leader, err := p.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
			_ = leader.Rollback(t.Context())
			t.Fatal(err)
		}
		leaderPID := leader.Conn().PgConn().PID()
		defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		done := make(chan error, 1)
		go func() {
			done <- o.SourceSnapshotCommands.AuthorizeSourceSnapshot(ctx, a, provider, snapshotNativeInput())
		}()
		defer cancel()
		waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
			var blocked bool
			err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
			return blocked, err
		}, done)
		if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
			cancel()
			_ = leader.Rollback(t.Context())
			t.Fatal("snapshot tenant lock preceded writer fence", err)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				_ = leader.Rollback(t.Context())
				t.Fatal("snapshot guard lost cancellation", err)
			}
		case <-time.After(5 * time.Second):
			_ = leader.Rollback(t.Context())
			t.Fatal("snapshot cancellation leaked transaction")
		}
		if err := leader.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := o.SourceSnapshotCommands.AuthorizeSourceSnapshot(t.Context(), a, provider, snapshotNativeInput()); err != nil {
			t.Fatal("snapshot cancellation leaked fence", err)
		}
	}
	if got := snapshotNativeCounts(t, p); got != [8]int{} {
		t.Fatal("cancelled snapshot guards wrote effects", got)
	}
}
