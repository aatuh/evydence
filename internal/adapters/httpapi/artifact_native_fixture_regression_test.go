package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func seedArtifactNativeFixture(t *testing.T, ledger *app.Ledger, owner operationsFixtureScope) domain.Artifact {
	t.Helper()
	a := domain.Artifact{ID: owner.product.ID + "-repository-artifact", TenantID: owner.actor.TenantID, Name: "Repository artifact", MediaType: "application/octet-stream", Size: 42, Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
	e := owner.evidence
	e.ID, e.Title = owner.product.ID+"-repository-artifact-reference", strings.Repeat("private-artifact-reference", 4000)
	e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: a.ID, Digest: a.Digest}}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.ReleaseCatalog.InsertArtifact(ctx, a); err != nil {
			return err
		}
		return r.Evidence.InsertEvidence(ctx, e)
	}); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestArtifactNativeFixtureUsesRepositoryOnlyPointCurrentAssociationsAndGrants(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	a := seedArtifactNativeFixture(t, ledger, owner)
	fa := seedArtifactNativeFixture(t, ledger, foreign)
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"evidence:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"evidence:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/artifacts/" + a.ID
	out := getRaw(t, server, "fixture", path, http.StatusOK).Body.String()
	want, err := json.Marshal(map[string]any{"data": a, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), out)
	if strings.Contains(out, "private-artifact-reference") || strings.Contains(out, foreign.actor.TenantID) {
		t.Fatal("point exposed association metadata or foreign tenant", out)
	}
	getRaw(t, server, "fixture", "/v1/artifacts/"+fa.ID, http.StatusNotFound)
	auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "ungranted", Scopes: []string{"evidence:read"}}}
	getRaw(t, server, "fixture", path, http.StatusForbidden)
	auth.actor = human
	auth.actor.ResourceGrants = nil
	getRaw(t, server, "fixture", path, http.StatusForbidden)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := server.artifactPointQuery.GetArtifact(ctx, owner.actor, a.ID); !errors.Is(err, context.Canceled) || v != (releasedomain.Artifact{}) {
		t.Fatal("cancelled point returned data", v, err)
	}
	// Native reference guards select only identity/digest and use the same
	// case-insensitive digest check as the actual Evidence creation adapter.
	guard := repositoryIngestionFixtureAuthority{ingestionFixtureAuthority: ingestionFixtureAuthority{catalogFixtureCommands{ledger: ledger}}}
	for _, digest := range []string{"", a.Digest, strings.ToUpper(a.Digest)} {
		if err := guard.ValidateArtifactReference(t.Context(), a.TenantID, a.ID, digest); err != nil {
			t.Fatal("owned digest reference failed", err)
		}
	}
	if err := guard.ValidateArtifactReference(t.Context(), a.TenantID, a.ID, "sha256:"+strings.Repeat("b", 64)); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("mismatched digest reference accepted", err)
	}
	if err := guard.ValidateArtifactReference(t.Context(), foreign.actor.TenantID, a.ID, ""); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign reference accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("point/guard reads changed stored state", err)
	}
}

func TestArtifactNativeFixtureDiscardsPointAndGrantOnCommitFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	a := seedArtifactNativeFixture(t, ledger, owner)
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	rollbacks := factory.rollbacks
	path := "/v1/artifacts/" + a.ID
	out := getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
	var problem map[string]any
	if err := json.Unmarshal([]byte(out), &problem); err != nil {
		t.Fatal(err)
	}
	if factory.rollbacks != rollbacks+1 || problem["instance"] != path || problem["data"] != nil || strings.Contains(out, "private-query") || strings.Contains(out, a.Name) {
		t.Fatal("failed point commit leaked projection or transaction", out)
	}
	if v, err := server.artifactPointQuery.GetArtifact(t.Context(), owner.actor, a.ID); err == nil || v != (releasedomain.Artifact{}) {
		t.Fatal("failed point returned data", v, err)
	}
	guard := repositoryIngestionFixtureAuthority{ingestionFixtureAuthority: ingestionFixtureAuthority{catalogFixtureCommands{ledger: ledger}}}
	if v, err := guard.GetArtifactPoint(t.Context(), releasequery.ArtifactReadRequest{TenantID: a.TenantID, ID: a.ID, TenantWide: true}); err == nil || v != (releasequery.ArtifactPoint{}) {
		t.Fatal("failed grant commit returned identity/visibility", v, err)
	}
	if err := guard.ValidateArtifactReference(t.Context(), a.TenantID, a.ID, a.Digest); err == nil {
		t.Fatal("failed reference commit passed")
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed artifact reads wrote state", err)
	}
}

func TestArtifactNativeFixtureFailsClosedAndPreservesExplicitQuery(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	a, err := ledger.RegisterArtifact(t.Context(), owner.actor, "Cached artifact", "application/octet-stream", "sha256:"+strings.Repeat("a", 64), 42)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := server.artifactPointQuery.GetArtifact(t.Context(), owner.actor, a.ID); !errors.Is(err, app.ErrValidation) || v != (releasedomain.Artifact{}) {
		t.Fatal("missing query repository fell back to cache", v, err)
	}
	guard := repositoryIngestionFixtureAuthority{ingestionFixtureAuthority: ingestionFixtureAuthority{catalogFixtureCommands{ledger: ledger}}}
	if v, err := guard.GetArtifactPoint(t.Context(), releasequery.ArtifactReadRequest{TenantID: a.TenantID, ID: a.ID, TenantWide: true}); !errors.Is(err, app.ErrValidation) || v != (releasequery.ArtifactPoint{}) {
		t.Fatal("missing grant repository fell back to cache", v, err)
	}
	if err := guard.ValidateArtifactReference(t.Context(), a.TenantID, a.ID, a.Digest); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing identity repository fell back to cache", err)
	}
	mock := &artifactPointQueryFake{}
	server.artifactPointQuery = mock
	server.bindCatalogQueryFixturePorts(ledger)
	if server.artifactPointQuery != mock {
		t.Fatal("rebind replaced explicit artifact query port")
	}
}
