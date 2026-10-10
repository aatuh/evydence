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
	ledger          *repositoryFixture
	historicalCache app.Store
	scope           operationsFixtureScope
	project         domain.Project
	artifact        domain.Artifact
	build           domain.BuildRun
	candidate       domain.ReleaseCandidate
}

// Missing-repository tests retain real historical cache rows separately from
// the transaction-only locator. No command fallback or repository is provided.
func newCachedReleaseFixture(t *testing.T, name string) cachedReleaseFixture {
	t.Helper()
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	factory := app.NewMemoryUnitOfWorkFactory()
	clock := application.ClockFunc(func() time.Time { return at })
	bootstrap := tenantBootstrapNativeFixture{factory, fixtureSessionCredentials("fixture-pepper"), clock}
	_, _, secret, err := bootstrap.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	locator := newLegacyLedgerFixture(app.Config{APIKeyPepper: "not-the-bootstrap-pepper", UnitOfWork: factory})
	actor, err := fixtureIdentityAuthenticator(locator, "fixture-pepper", clock).Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatal("native bootstrap rows could not be read", err)
	}
	// This is intentionally only the negative fixture's selected cache, not a
	// complete backup or a supported memory persistence/runtime profile.
	state := app.PersistedState{Tenants: snapshot.Tenants, APIKeys: snapshot.APIKeys,
		APIKeyHashes: map[string]string{}, SigningKeys: snapshot.SigningKeys,
		SigningKeyPrivate: map[string][]byte{}, Chain: snapshot.AuditEntries,
		Products: map[string]domain.Product{}, Releases: map[string]domain.Release{},
		Projects: map[string]domain.Project{}, Artifacts: map[string]domain.Artifact{},
		BuildRuns: map[string]domain.BuildRun{}, ReleaseCandidates: map[string]domain.ReleaseCandidate{}}
	for id, key := range state.APIKeys {
		state.APIKeyHashes[id], key.Hash = key.Hash, ""
		state.APIKeys[id] = key
	}
	for id, key := range state.SigningKeys {
		state.SigningKeyPrivate[id], key.Private = append([]byte(nil), key.Private...), nil
		state.SigningKeys[id] = key
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
	store := app.NewMemoryStore()
	if err := store.SaveState(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	f.historicalCache = store
	cfg := app.Config{APIKeyPepper: "fixture-pepper", Store: store, Now: clock.Now}
	f.ledger, err = newLegacyLedgerFixtureWithContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
