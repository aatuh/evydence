package wiring

import (
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestPostgresArtifactRegistrationCreationAndReusePreserveDurableTimestamp(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Artifact precision')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildArtifactCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	in := releaseapp.RegisterArtifactInput{Name: "Original", MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("c", 64), Size: 1}
	original, err := commands.RegisterArtifact(ctx, actor, in)
	if err != nil || original.ID == "" || original.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("new artifact does not use durable time precision", original, err)
	}
	fresh, err := BuildArtifactCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	in.Name, in.MediaType, in.Size = "Ignored", "text/plain", 99
	reused, err := fresh.RegisterArtifact(ctx, actor, in)
	if err != nil || reused != original {
		t.Fatal("fresh command changed immutable artifact or time", original, reused, err)
	}
	var artifacts, audit int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM artifacts),(SELECT count(*)FROM audit_chain_entries)`).Scan(&artifacts, &audit); err != nil || artifacts != 1 || audit != 1 {
		t.Fatal("reuse duplicated effects", artifacts, audit, err)
	}
}
