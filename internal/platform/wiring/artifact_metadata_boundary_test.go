package wiring

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestPostgresArtifactRegistrationAuthorizesBeforeBoundedMetadataRead(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Artifact metadata'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product',repeat('x',9000000));INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant',repeat('x',9000000),repeat('x',9000000),$1,1)`, digest)
	commands, err := BuildArtifactCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	in := releaseapp.RegisterArtifactInput{Name: "Ignored", MediaType: "text/plain", Digest: digest, Size: 99}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:write"}}}}
	if v, err := commands.RegisterArtifact(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("private oversized metadata loaded before authorization", v.ID, err)
	}
	key := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	if v, err := commands.RegisterArtifact(ctx, key, in); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" {
		t.Fatal("oversized stored metadata returned or truncated", v.ID, err)
	}
	exec(`UPDATE artifacts SET name='Original',media_type='application/octet-stream'WHERE id='artifact'`)
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,source_identity,schema_version)VALUES('build','tenant','project','release','generic_ci','0123456789abcdef','passed',now(),jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest',$1::text)),'{}','v1')`, digest)
	if v, err := commands.RegisterArtifact(ctx, human, in); err != nil || v.ID != "artifact" || v.Name != "Original" || v.MediaType != "application/octet-stream" || v.Size != 1 {
		t.Fatal("bounded authorized metadata changed", v, err)
	}
	exec(`UPDATE artifacts SET name=repeat('界',22000)WHERE id='artifact'`)
	if v, err := commands.RegisterArtifact(ctx, human, in); !errors.Is(err, releaseapp.ErrConflict) || v.ID != "" {
		t.Fatal("multibyte metadata byte overflow accepted", v.ID, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*releaseapp.RegisterArtifactInput)
	}{
		{"NUL name", func(in *releaseapp.RegisterArtifactInput) { in.Name = "bad\x00name" }},
		{"NUL media type", func(in *releaseapp.RegisterArtifactInput) { in.MediaType = "bad\x00media" }},
		{"invalid UTF8", func(in *releaseapp.RegisterArtifactInput) { in.Name = string([]byte{255}) }},
		{"oversized name", func(in *releaseapp.RegisterArtifactInput) { in.Name = strings.Repeat("界", 22000) }},
		{"oversized media type", func(in *releaseapp.RegisterArtifactInput) { in.MediaType = strings.Repeat("x", 65537) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := releaseapp.RegisterArtifactInput{Name: "New", MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("b", 64), Size: 1}
			tc.change(&bad)
			if v, err := commands.RegisterArtifact(ctx, key, bad); !errors.Is(err, releaseapp.ErrValidation) || v.ID != "" {
				t.Fatal("unsupported storage input accepted", v.ID, err)
			}
		})
	}
	var artifacts, audit int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM artifacts),(SELECT count(*)FROM audit_chain_entries)`).Scan(&artifacts, &audit); err != nil || artifacts != 1 || audit != 0 {
		t.Fatal("reuse or overflow wrote effects", artifacts, audit, err)
	}
}
