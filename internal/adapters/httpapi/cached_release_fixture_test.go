package httpapi

import (
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

type cachedReleaseFixture struct {
	ledger    *app.Ledger
	scope     operationsFixtureScope
	project   domain.Project
	artifact  domain.Artifact
	build     domain.BuildRun
	candidate domain.ReleaseCandidate
}

// Missing-repository tests load real cached records through the existing
// persisted-state boundary. No command fallback or repository is provided.
func newCachedReleaseFixture(t *testing.T, name string) cachedReleaseFixture {
	t.Helper()
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	store := app.NewMemoryStore()
	cfg := app.Config{APIKeyPepper: "fixture-pepper", Store: store, Now: func() time.Time { return at }}
	ledger, err := newLegacyLedgerFixtureWithContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	state, ok, err := store.LoadState(t.Context())
	if err != nil || !ok {
		t.Fatal("bootstrap cache was not persisted", err)
	}
	product := domain.Product{ID: "cached-product", TenantID: actor.TenantID, Name: name, Slug: strings.ToLower(name), CreatedAt: at}
	release := domain.Release{ID: "cached-release", TenantID: actor.TenantID, ProductID: product.ID, Version: "1", State: "draft", Revision: 1, CreatedAt: at}
	f := cachedReleaseFixture{scope: operationsFixtureScope{actor: actor, product: product, release: release},
		project:  domain.Project{ID: "cached-project", TenantID: actor.TenantID, ProductID: product.ID, Name: "Cached project", CreatedAt: at},
		artifact: domain.Artifact{ID: "cached-artifact", TenantID: actor.TenantID, Name: "Cached artifact", MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("a", 64), Size: 42, CreatedAt: at}}
	f.build = domain.BuildRun{ID: "cached-build", TenantID: actor.TenantID, ProjectID: f.project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: at, Outputs: []domain.BuildOutput{{ArtifactID: f.artifact.ID, Digest: f.artifact.Digest}}, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: at}
	f.candidate = domain.ReleaseCandidate{ID: "cached-candidate", TenantID: actor.TenantID, ReleaseID: release.ID, Name: "Cached candidate", State: "open", Revision: 1, BuildIDs: []string{f.build.ID}, SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: at}
	f.candidate.SnapshotHash, err = application.NormalizedJSONHash(f.candidate)
	if err != nil {
		t.Fatal(err)
	}
	state.Products[product.ID], state.Releases[release.ID] = product, release
	state.Projects[f.project.ID], state.Artifacts[f.artifact.ID] = f.project, f.artifact
	state.BuildRuns[f.build.ID], state.ReleaseCandidates[f.candidate.ID] = f.build, f.candidate
	if err := store.SaveState(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	f.ledger, err = newLegacyLedgerFixtureWithContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
