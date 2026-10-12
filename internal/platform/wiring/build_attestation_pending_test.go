package wiring

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresBuildAttestationSeesPendingBuildParentsAndArtifactGrants(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Pending attestations');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product')`); err != nil {
		t.Fatal(err)
	}
	objects, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	builds, err := BuildBuildCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	attestations, err := BuildBuildAttestationCommands(store, objects, true)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString(statement) + `","signatures":[{"sig":"untrusted"}]}`)
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"build:write"}}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"build:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"build:write"}}}}
	digest := "sha256:" + strings.Repeat("a", 64)
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	counts := func() [9]int {
		t.Helper()
		var n [9]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM projects),(SELECT count(*)FROM releases),(SELECT count(*)FROM artifacts),(SELECT count(*)FROM build_runs),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM build_attestations),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6], &n[7], &n[8]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rollback := errors.New("rollback pending attestation")
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			if err := repos.ReleaseCatalog.InsertProject(txCtx, domain.Project{ID: "project", TenantID: "tenant", ProductID: "product", Name: "Project", CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: "release", TenantID: "tenant", ProductID: "product", Version: "1", State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertArtifact(txCtx, domain.Artifact{ID: "artifact", TenantID: "tenant", Name: "Artifact", MediaType: "application/octet-stream", Digest: digest, Size: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			build, err := builds.CreateBuildRun(txCtx, actor, releaseapp.CreateBuildRunInput{ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: at, Outputs: []releasedomain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}})
			if err != nil {
				return 0, nil, err
			}
			attestation, err := attestations.UploadBuildAttestation(txCtx, human, build.ID, raw)
			if err != nil {
				return 0, nil, err
			}
			if attestation.BuildID != build.ID || attestation.EvidenceID == "" || attestation.VerificationStatus != "structurally_valid" {
				t.Fatal("pending attestation identity or structural result changed", attestation)
			}
			if fail {
				return 0, nil, rollback
			}
			return 201, attestation, nil
		}
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-build-attestation", "rollback", raw, run(true)); !errors.Is(err, rollback) || counts() != [9]int{} {
		t.Fatal("pending lookup or outer rollback failed", err, counts())
	}
	calls := 0
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-build-attestation", "commit", raw, func(ctx context.Context, repos app.Repositories) (int, any, error) {
			calls++
			return run(false)(ctx, repos)
		}); err != nil || counts() != [9]int{1, 1, 1, 1, 1, 1, 3, 1, 2} {
			t.Fatal("pending build/grant or committed effects failed", err, counts())
		}
	}
	if calls != 1 {
		t.Fatal("replay repeated compound command", calls)
	}
}
