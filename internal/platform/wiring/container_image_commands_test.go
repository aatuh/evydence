package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresContainerImageCommandsUseBoundedCurrentArtifactAndImageIdentity(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Images'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000));INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant',repeat('x',9000000),repeat('x',9000000),$1,1)`, digest)
	commands, err := BuildContainerImageCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	input := releaseapp.RegisterContainerImageInput{ArtifactID: "artifact", Repository: "registry.example.test/api", Tag: "v1", Digest: digest, Platform: "linux/amd64"}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM artifacts),(SELECT count(*)FROM container_images),(SELECT count(*)FROM audit_chain_entries)`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	image, err := commands.RegisterContainerImage(ctx, actor, input)
	if err != nil || image.ID == "" || image.ArtifactID != "artifact" || image.Tag != "v1" || counts() != [3]int{1, 1, 1} {
		t.Fatal("durable creation", image, err, counts())
	}
	input.Tag = "ignored-on-reuse"
	reused, err := commands.RegisterContainerImage(ctx, actor, input)
	if err != nil || reused != image || counts() != [3]int{1, 1, 1} {
		t.Fatal("immutable reuse", reused, err, counts())
	}
	foreign := actor
	foreign.TenantID = "other"
	if v, err := commands.RegisterContainerImage(ctx, foreign, input); !errors.Is(err, releaseapp.ErrNotFound) || v.ID != "" {
		t.Fatal("foreign artifact accepted", v, err)
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:write"}}}}
	omitted := input
	omitted.ArtifactID = ""
	if v, err := commands.RegisterContainerImage(ctx, human, omitted); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("existing actual association exposed without grant", v, err)
	}
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,source_identity,schema_version)VALUES('build','tenant','project','release','generic_ci','0123456789abcdef','passed',now(),jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest',$1::text)),'{}','v1')`, digest)
	if v, err := commands.RegisterContainerImage(ctx, human, omitted); err != nil || v != image {
		t.Fatal("current authorized association not reusable", v, err)
	}
	exec(`UPDATE container_images SET tag=repeat('x',65537)WHERE id=$1`, image.ID)
	if v, err := commands.RegisterContainerImage(ctx, actor, input); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" {
		t.Fatal("oversized image metadata returned or truncated", v.ID, err)
	}
	exec(`UPDATE container_images SET tag='v1'WHERE id=$1`, image.ID)
	exec(`CREATE FUNCTION reject_image_audit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected image audit failure';END$$;CREATE TRIGGER reject_image_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_image_audit()`)
	input.Repository = "registry.example.test/audit-failure"
	if v, err := commands.RegisterContainerImage(ctx, actor, input); err == nil || !strings.Contains(err.Error(), "injected image audit failure") || v.ID != "" || counts() != [3]int{1, 1, 1} {
		t.Fatal("audit failure committed image", v, err, counts())
	}
	exec(`DROP TRIGGER reject_image_audit ON audit_chain_entries`)
	for _, tc := range []struct {
		name   string
		change func(*releaseapp.RegisterContainerImageInput)
	}{
		{"NUL repository", func(in *releaseapp.RegisterContainerImageInput) { in.Repository = "bad\x00repository" }},
		{"NUL tag", func(in *releaseapp.RegisterContainerImageInput) { in.Tag = "bad\x00tag" }},
		{"invalid UTF8 platform", func(in *releaseapp.RegisterContainerImageInput) { in.Platform = string([]byte{255}) }},
		{"oversized metadata", func(in *releaseapp.RegisterContainerImageInput) { in.Tag = strings.Repeat("界", 22000) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := input
			bad.Repository = "registry.example.test/invalid"
			tc.change(&bad)
			if v, err := commands.RegisterContainerImage(ctx, actor, bad); !errors.Is(err, releaseapp.ErrValidation) || v.ID != "" || counts() != [3]int{1, 1, 1} {
				t.Fatal("unsupported storage input wrote image", v.ID, err, counts())
			}
		})
	}
	rollback := errors.New("rollback pending image")
	pendingDigest := "sha256:" + strings.Repeat("b", 64)
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			if err := repos.ReleaseCatalog.InsertArtifact(txCtx, domain.Artifact{ID: "pending-artifact", TenantID: "tenant", Name: "Pending", MediaType: "application/octet-stream", Digest: pendingDigest, Size: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.Builds.InsertBuildRun(txCtx, domain.BuildRun{ID: "pending-build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("b", 40), Status: "passed", StartedAt: at, CreatedAt: at, SchemaVersion: "v1", Outputs: []domain.BuildOutput{{ArtifactID: "pending-artifact", Digest: pendingDigest}}}); err != nil {
				return 0, nil, err
			}
			v, err := commands.RegisterContainerImage(txCtx, human, releaseapp.RegisterContainerImageInput{ArtifactID: "pending-artifact", Repository: "registry.example.test/pending", Digest: pendingDigest})
			if err != nil {
				return 0, nil, err
			}
			if fail {
				return 0, nil, rollback
			}
			return 201, v, nil
		}
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-image", "rollback", nil, run(true)); !errors.Is(err, rollback) || counts() != [3]int{1, 1, 1} {
		t.Fatal("pending read or outer rollback failed", err, counts())
	}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-image", "commit", nil, func(ctx context.Context, repos app.Repositories) (int, any, error) {
			calls++
			return run(false)(ctx, repos)
		}); err != nil || counts() != [3]int{2, 2, 2} {
			t.Fatal("pending artifact/grant or replay failed", err, counts())
		}
	}
	if calls != 1 {
		t.Fatal("replay repeated image creation", calls)
	}
}

func TestPostgresContainerImageCommandsSerializeAbsentIdentityReuse(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Concurrent images')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildContainerImageCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	input := releaseapp.RegisterContainerImageInput{Repository: "registry.example.test/concurrent", Digest: "sha256:" + strings.Repeat("c", 64)}
	type result struct {
		image releasedomain.ContainerImage
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			v, err := commands.RegisterContainerImage(ctx, actor, input)
			results <- result{v, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.image.ID == "" || first.image != second.image {
		t.Fatal("concurrent identity reuse diverged", first, second)
	}
	var images, audit int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM container_images),(SELECT count(*)FROM audit_chain_entries)`).Scan(&images, &audit); err != nil || images != 1 || audit != 1 {
		t.Fatal("concurrent reuse duplicated effects", images, audit, err)
	}
}
