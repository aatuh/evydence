package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestPostgresArtifactRegistrationSeesPendingAssociationDuringDigestReuse(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Pending artifacts');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildArtifactCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:write"}}}}
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM projects),(SELECT count(*)FROM releases),(SELECT count(*)FROM artifacts),(SELECT count(*)FROM build_runs),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rollback := errors.New("rollback pending artifact reuse")
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			if err := repos.ReleaseCatalog.InsertProject(txCtx, domain.Project{ID: "project", TenantID: "tenant", ProductID: "product", Name: "Project", CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: "release", TenantID: "tenant", ProductID: "product", Version: "1", State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertArtifact(txCtx, domain.Artifact{ID: "artifact", TenantID: "tenant", Name: "Original", MediaType: "application/octet-stream", Digest: digest, Size: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.Builds.InsertBuildRun(txCtx, domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: at, CreatedAt: at, SchemaVersion: "v1", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}}); err != nil {
				return 0, nil, err
			}
			v, err := commands.RegisterArtifact(txCtx, actor, releaseapp.RegisterArtifactInput{Name: "Ignored", MediaType: "text/plain", Digest: digest, Size: 99})
			if err != nil {
				return 0, nil, err
			}
			if v.ID != "artifact" || v.Name != "Original" || v.MediaType != "application/octet-stream" || v.Size != 1 {
				t.Fatal("reuse changed pending immutable artifact", v)
			}
			if fail {
				return 0, nil, rollback
			}
			return 201, v, nil
		}
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-artifact-reuse", "rollback", nil, run(true)); !errors.Is(err, rollback) || counts() != [5]int{} {
		t.Fatal("pending grant lookup or rollback failed", err, counts())
	}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-artifact-reuse", "commit", nil, func(ctx context.Context, repos app.Repositories) (int, any, error) {
			calls++
			return run(false)(ctx, repos)
		}); err != nil || counts() != [5]int{1, 1, 1, 1, 0} {
			t.Fatal("pending scope, duplicate effects or replay failed", err, counts())
		}
	}
	if calls != 1 {
		t.Fatal("reuse replay repeated command", calls)
	}
}
