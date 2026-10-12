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
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func TestPostgresSourceRepositoryGuardLocksBothSubmittedAndExistingParents(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	in := integrationapp.CreateSourceRepositoryInput{ProjectID: "project", Provider: "github", FullName: "org/api"}
	v, err := opts.SourceRepositoryCommands.CreateSourceRepository(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	in.ProjectID = "other-project"
	calls, guards := 0, 0
	for range 2 {
		_, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/source/repositories", "joined", []byte("input"), func(ctx context.Context) error {
			if err := opts.SourceRepositoryCommands.AuthorizeSourceRepositoryCreation(ctx, a, in); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table, id string
				blocked   bool
			}{{"tenants", "tenant", true}, {"projects", "project", true}, {"projects", "other-project", true}, {"products", "product", true}, {"products", "other-product", true}, {"source_repositories", v.ID, true}, {"projects", "foreign-project", false}, {"products", "foreign-product", false}, {"sso_sessions", "operator-session", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("source guard lost parent lock or locked unrelated row", tc, err)
				}
			}
			return nil
		}, func(ctx context.Context) (int, any, error) {
			calls++
			x, err := opts.SourceRepositoryCommands.CreateSourceRepository(ctx, a, in)
			return 201, domain.SourceRepository{ID: x.ID, TenantID: x.TenantID, ProjectID: x.ProjectID, Provider: x.Provider, FullName: x.FullName, CloneURL: x.CloneURL, DefaultBranch: x.DefaultBranch, SchemaVersion: x.SchemaVersion, CreatedAt: x.CreatedAt}, err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := sourceRepositoryNativeCounts(t, p); calls != 1 || guards != 2 || got != [5]int{1, 1, 0, 1, 0} {
		t.Fatal("joined source guard duplicated effects", calls, guards, got)
	}
}

func TestPostgresSourceRepositoryNativeConcurrentReplayCreatesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	in := integrationapp.CreateSourceRepositoryInput{ProjectID: "project", Provider: "github", FullName: "org/api"}
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
			s, v, err := opts.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/source/repositories", "concurrent", []byte("input"), func(ctx context.Context) error {
				return opts.SourceRepositoryCommands.AuthorizeSourceRepositoryCreation(ctx, a, in)
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				x, err := opts.SourceRepositoryCommands.CreateSourceRepository(ctx, a, in)
				return 201, domain.SourceRepository{ID: x.ID, TenantID: x.TenantID, ProjectID: x.ProjectID, Provider: x.Provider, FullName: x.FullName, CloneURL: x.CloneURL, DefaultBranch: x.DefaultBranch, SchemaVersion: x.SchemaVersion, CreatedAt: x.CreatedAt}, err
			})
			done <- reply{s, v, err}
		}()
	}
	close(start)
	var responses [2]string
	for i := range responses {
		select {
		case r := <-done:
			if r.err != nil || r.status != 201 {
				t.Fatal("concurrent source failed", r.status, r.err)
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
	if got := sourceRepositoryNativeCounts(t, p); calls.Load() != 1 || got != [5]int{1, 1, 0, 1, 0} {
		t.Fatal("concurrent source duplicated effects", calls.Load(), got)
	}
}

func TestPostgresSourceRepositoryFencePrecedesTenantLocks(t *testing.T) {
	_, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
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
		done <- repositories.New(child).Source.(integrationapp.SourceRepositoryCreationReader).LockRepositoryCreation(ctx, "tenant")
	}()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory'AND $2=ANY(pg_blocking_pids(pid)))`, childPID, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(ctx, `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("source tenant lock preceded writer fence", err)
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
		t.Fatal("source fence did not release")
	}
}

func TestPostgresSourceRepositoryCancelledGuardReleasesFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"source:write"}}
	in := integrationapp.CreateSourceRepositoryInput{ProjectID: "project", Provider: "github", FullName: "org/api"}
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
	go func() { done <- opts.SourceRepositoryCommands.AuthorizeSourceRepositoryCreation(ctx, a, in) }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("guard lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled source guard leaked transaction")
	}
	if err := leader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := opts.SourceRepositoryCommands.AuthorizeSourceRepositoryCreation(t.Context(), a, in); err != nil {
		t.Fatal("cancelled guard leaked writer fence", err)
	}
	if got := sourceRepositoryNativeCounts(t, p); got != [5]int{} {
		t.Fatal("guard wrote business effects", got)
	}
}
