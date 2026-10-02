package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestPostgresBuildCreationReadsOnlyCurrentCoordinates(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Builds'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('other-product','tenant','Other','other'),('foreign','other','Foreign','foreign')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000)),('other-project','tenant','other-product','Other'),('foreign','other','foreign','Foreign')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state,created_at)VALUES('release','tenant','product','1.0.0','draft',now()),('other-release','tenant','other-product','1.0.0','draft',now()),('foreign','other','foreign','1.0.0','draft',now())`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest,created_at)VALUES('artifact','tenant',repeat('x',9000000),repeat('x',9000000),1,$1,now()),('foreign','other','Foreign','application/octet-stream',1,$1,now())`, digest)
	commands, err := BuildBuildCommands(store, store)
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.ReadBuildProject(ctx, "tenant", "project")
	if err != nil || project.ID != "project" || project.ProductID != "product" || project.Name != "" || !project.CreatedAt.IsZero() {
		t.Fatal("project identity selected unrelated metadata", project, err)
	}
	release, err := store.ReadBuildRelease(ctx, "tenant", "release")
	if err != nil || release.ID != "release" || release.ProductID != "product" || release.Version != "1.0.0" || !release.CreatedAt.IsZero() {
		t.Fatal("release identity selected unrelated metadata", release, err)
	}
	artifact, err := store.ReadBuildArtifact(ctx, "tenant", "artifact")
	if err != nil || artifact.ID != "artifact" || artifact.Digest != digest || artifact.Name != "" || artifact.MediaType != "" || !artifact.CreatedAt.IsZero() {
		t.Fatal("artifact identity selected unrelated metadata", artifact, err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(releaseapp.BuildIdentityReader)
		if !ok {
			t.Fatal("transaction lacks bounded build identity reader")
		}
		p, err := reader.ReadBuildProject(ctx, "tenant", "project")
		if err != nil || p != project {
			t.Fatal("transaction selected project metadata", p, err)
		}
		r, err := reader.ReadBuildRelease(ctx, "tenant", "release")
		if err != nil || r != release {
			t.Fatal("transaction selected release metadata", r, err)
		}
		a, err := reader.ReadBuildArtifact(ctx, "tenant", "artifact")
		if err != nil || a != artifact {
			t.Fatal("transaction selected artifact metadata", a, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"build:write"}}
	in := releaseapp.CreateBuildRunInput{ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("b", 40), Status: "passed", StartedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), ProviderMetadata: map[string]any{"oidc_verified": true, "source": "spoofed", "provider": "spoofed"}, Outputs: []releasedomain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM build_runs WHERE tenant_id='tenant'),(SELECT count(*)FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*)FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	v, err := commands.CreateBuildRun(ctx, a, in)
	if err != nil || v.ID == "" || v.ProjectID != "project" || v.ReleaseID != "release" || len(v.Outputs) != 1 || v.Outputs[0].Digest != digest || v.SourceIdentity["oidc_verified"] != false || v.SourceIdentity["source"] != "api" || v.SourceIdentity["provider"] != "generic_ci" || counts() != [3]int{1, 1, 0} {
		t.Fatal("build metadata loaded or provider claims trusted", v, err, counts())
	}
	for _, tc := range []struct {
		project, release, artifact, digest string
		want                               error
	}{{"foreign", "release", "artifact", digest, releaseapp.ErrNotFound}, {"project", "foreign", "artifact", digest, releaseapp.ErrNotFound}, {"project", "other-release", "artifact", digest, releaseapp.ErrValidation}, {"project", "release", "foreign", digest, releaseapp.ErrNotFound}, {"project", "release", "artifact", "sha256:" + strings.Repeat("c", 64), releaseapp.ErrValidation}} {
		bad := in
		bad.ProjectID, bad.ReleaseID = tc.project, tc.release
		bad.Outputs = []releasedomain.BuildOutput{{ArtifactID: tc.artifact, Digest: tc.digest}}
		if v, err := commands.CreateBuildRun(ctx, a, bad); !errors.Is(err, tc.want) || v.ID != "" || counts() != [3]int{1, 1, 0} {
			t.Fatal("invalid scope persisted", tc, v, err, counts())
		}
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"build:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "other-project", Scopes: []string{"build:write"}}}}
	if _, err := commands.CreateBuildRun(ctx, human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("wrong project accepted", err)
	}
	human.ResourceGrants = nil
	if _, err := commands.CreateBuildRun(ctx, human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("revoked grant accepted", err)
	}
	for _, table := range []string{"build_runs", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_build_identity()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected build failure';END$$`)
		exec(`CREATE TRIGGER reject_build_identity BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_build_identity()`)
		if v, err := commands.CreateBuildRun(ctx, a, in); err == nil || v.ID != "" || counts() != [3]int{1, 1, 0} {
			t.Fatal("partial build committed", table, v, err, counts())
		}
		exec(`DROP TRIGGER reject_build_identity ON ` + table)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/builds", "build-replay", []byte(`{"status":"passed"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			calls++
			v, err := commands.CreateBuildRun(ctx, a, in)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || counts() != [3]int{2, 2, 0} {
		t.Fatal("replay added effects", calls, counts())
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"build:write"}}}
	noOutputs := in
	noOutputs.Outputs = nil
	if v, err := commands.CreateBuildRun(ctx, human, noOutputs); err != nil || v.ID == "" || counts() != [3]int{3, 3, 0} {
		t.Fatal("current project grant rejected", v, err, counts())
	}
	if v, err := commands.CreateBuildRun(ctx, human, in); err != nil || v.ID == "" || counts() != [3]int{4, 4, 0} {
		t.Fatal("current linked-artifact grant loaded unrelated metadata", v, err, counts())
	}
	grant, err := store.ReadBuildArtifactGrant(ctx, releasequery.ArtifactReadRequest{TenantID: "tenant", ID: "artifact", AllowedProjectIDs: []string{"project"}})
	if err != nil || !grant.Visible || grant.Artifact.ID != "artifact" || grant.Artifact.Name != "" || grant.Artifact.MediaType != "" || grant.Artifact.Digest != "" {
		t.Fatal("grant selected metadata", grant, err)
	}
	for _, badID := range []string{"bad\x00id", strings.Repeat("x", 1025), string([]byte{0xff})} {
		bad := in
		bad.ProjectID = badID
		if _, err := commands.CreateBuildRun(ctx, a, bad); !errors.Is(err, releaseapp.ErrValidation) || counts() != [3]int{4, 4, 0} {
			t.Fatal("malformed coordinate reached SQL", err, counts())
		}
	}
	exec(`UPDATE artifacts SET digest=$1 WHERE id='artifact'`, digest+"b")
	if v, err := store.ReadBuildArtifact(ctx, "tenant", "artifact"); !errors.Is(err, app.ErrConflict) || v.ID != "" {
		t.Fatal("oversized stored digest truncated", v, err)
	}
	exec(`UPDATE artifacts SET digest=$1 WHERE id='artifact'`, digest)
	exec(`UPDATE releases SET version=repeat('x',65537)WHERE id='release'`)
	if v, err := store.ReadBuildRelease(ctx, "tenant", "release"); !errors.Is(err, app.ErrConflict) || v.ID != "" {
		t.Fatal("oversized stored release version truncated", v, err)
	}
	if v, err := commands.CreateBuildRun(ctx, a, in); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" || counts() != [3]int{4, 4, 0} {
		t.Fatal("oversized coordinate persisted", v, err, counts())
	}
	exec(`UPDATE releases SET version='1.0.0'WHERE id='release'`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('tainted','tenant','foreign','Cross tenant')`)
	bad := in
	bad.ProjectID = "tainted"
	if v, err := commands.CreateBuildRun(ctx, a, bad); !errors.Is(err, releaseapp.ErrNotFound) || v.ID != "" || counts() != [3]int{4, 4, 0} {
		t.Fatal("inconsistent tenant parent accepted", v, err, counts())
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ReadBuildProject(cancelled, "tenant", "project"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read executed", err)
	}
}
