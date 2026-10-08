package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func seedCatalogNativeBuildCandidate(t *testing.T, ledger *app.Ledger, owner operationsFixtureScope) (domain.BuildRun, domain.ReleaseCandidate) {
	t.Helper()
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	j := domain.Project{ID: owner.product.ID + "-query-project", TenantID: owner.actor.TenantID, ProductID: owner.product.ID, Name: "Repository project", CreatedAt: at}
	b := domain.BuildRun{ID: owner.product.ID + "-query-build", TenantID: owner.actor.TenantID, ProjectID: j.ID, ReleaseID: owner.release.ID, Provider: "github", CommitSHA: "commit", Repository: "owner/repo", WorkflowRef: "workflow", RunID: "42", RunAttempt: 2, JobID: "job", Actor: "actor", Ref: "main", OIDCSubject: "subject", Status: "succeeded", StartedAt: at, FinishedAt: &at, ParametersHash: "parameters", EnvironmentHash: "environment", SourceIdentity: map[string]any{"nested": map[string]any{"items": []any{"original"}}}, Outputs: []domain.BuildOutput{{Digest: "sha256:" + strings.Repeat("a", 64)}}, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: at}
	c := domain.ReleaseCandidate{ID: owner.product.ID + "-query-candidate", TenantID: owner.actor.TenantID, ReleaseID: owner.release.ID, Name: "Repository candidate", Revision: 3, State: "promoted", BuildIDs: []string{b.ID}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}, SnapshotHash: "sha256:" + strings.Repeat("b", 64), SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: at, PromotedAt: &at, RejectedAt: &at}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.ReleaseCatalog.InsertProject(ctx, j); err != nil {
			return err
		}
		if err := r.Builds.InsertBuildRun(ctx, b); err != nil {
			return err
		}
		if err := r.ReleaseCatalog.InsertReleaseCandidate(ctx, c); err != nil {
			return err
		}
		second := c
		second.ID += "-next"
		return r.ReleaseCatalog.InsertReleaseCandidate(ctx, second)
	}); err != nil {
		t.Fatal(err)
	}
	return b, c
}

func TestCatalogBuildCandidateNativeQueriesUseRepositoryOnlyDTOsCurrentGrantsAndPages(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	b, c := seedCatalogNativeBuildCandidate(t, ledger, owner)
	fb, fc := seedCatalogNativeBuildCandidate(t, ledger, foreign)
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"build:read", "release:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
	auth := &configuredAuthenticator{actor: human}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path  string
		value any
	}{{"/v1/builds/" + b.ID, b}, {"/v1/release-candidates/" + c.ID, c}} {
		out := getRaw(t, server, "fixture", tc.path, http.StatusOK).Body.String()
		want, err := json.Marshal(map[string]any{"data": tc.value, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), out)
		auth.actor.ResourceGrants = nil
		getRaw(t, server, "fixture", tc.path, http.StatusForbidden)
		auth.actor = human
	}
	getRaw(t, server, "fixture", "/v1/builds/"+fb.ID, http.StatusNotFound)
	getRaw(t, server, "fixture", "/v1/release-candidates/"+fc.ID, http.StatusNotFound)
	var page struct {
		Data []domain.ReleaseCandidate `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	path := "/v1/release-candidates?release_id=" + owner.release.ID + "&page_size=1&sort=id&direction=asc"
	first := getRaw(t, server, "fixture", path, http.StatusOK)
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil || !reflect.DeepEqual(page.Data, []domain.ReleaseCandidate{c}) || page.Meta.NextCursor == "" {
		t.Fatal("native candidate page lost full fields or cursor", first.Body.String(), err)
	}
	next := getRaw(t, server, "fixture", path+"&cursor="+url.QueryEscape(page.Meta.NextCursor), http.StatusOK)
	wantNext := c
	wantNext.ID += "-next"
	page.Meta.NextCursor = ""
	if err := json.Unmarshal(next.Body.Bytes(), &page); err != nil || !reflect.DeepEqual(page.Data, []domain.ReleaseCandidate{wantNext}) || page.Meta.NextCursor != "" {
		t.Fatal("native candidate continuation changed", next.Body.String(), err)
	}
	auth.actor.ResourceGrants = nil
	page.Meta.NextCursor = ""
	if err := json.Unmarshal(getRaw(t, server, "fixture", path, http.StatusOK).Body.Bytes(), &page); err != nil || len(page.Data) != 0 || page.Meta.NextCursor != "" {
		t.Fatal("removed grant returned candidate page", page, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := server.buildPointQuery.GetBuildRun(ctx, human, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("build query ignored cancellation", err)
	}
	if _, err := server.releaseCandidateQuery.GetReleaseCandidate(ctx, human, c.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("candidate query ignored cancellation", err)
	}
	build, err := server.buildPointQuery.GetBuildRun(t.Context(), human, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := server.releaseCandidateQuery.GetReleaseCandidate(t.Context(), human, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	*build.FinishedAt = b.CreatedAt.Add(time.Hour)
	build.Outputs[0].Digest = "changed"
	build.SourceIdentity["nested"].(map[string]any)["items"].([]any)[0] = "changed"
	*candidate.PromotedAt, *candidate.RejectedAt = c.CreatedAt.Add(time.Hour), c.CreatedAt.Add(time.Hour)
	for _, ids := range [][]string{candidate.BuildIDs, candidate.ArtifactIDs, candidate.SBOMIDs, candidate.ScanIDs, candidate.VEXIDs, candidate.ContractIDs, candidate.BundleIDs} {
		ids[0] = "changed"
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("native catalog queries or result mutations changed state", err)
	}
}

func TestCatalogBuildCandidateNativeQueriesDiscardResultsOnCommitFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	b, c := seedCatalogNativeBuildCandidate(t, ledger, owner)
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	for _, path := range []string{"/v1/builds/" + b.ID, "/v1/release-candidates/" + c.ID, "/v1/release-candidates"} {
		rollbacks := factory.rollbacks
		out := getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
		var problem map[string]any
		if err := json.Unmarshal([]byte(out), &problem); err != nil {
			t.Fatal(err)
		}
		if factory.rollbacks != rollbacks+1 || problem["instance"] != path || problem["data"] != nil || strings.Contains(out, "private-query") || strings.Contains(out, "snapshot_hash") || strings.Contains(out, "source_identity") {
			t.Fatal("failed query leaked projection or transaction", out)
		}
	}
	if v, err := server.buildPointQuery.GetBuildRun(t.Context(), owner.actor, b.ID); err == nil || !reflect.DeepEqual(v, releasedomain.BuildRun{}) {
		t.Fatal("failed build commit returned partial metadata", v, err)
	}
	if v, err := server.releaseCandidateQuery.GetReleaseCandidate(t.Context(), owner.actor, c.ID); err == nil || !reflect.DeepEqual(v, releasedomain.ReleaseCandidate{}) {
		t.Fatal("failed candidate commit returned partial metadata", v, err)
	}
	if v, err := server.releaseCandidateQuery.ListPage(t.Context(), owner.actor, "", appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil); err == nil || v.Items != nil || v.Next != nil {
		t.Fatal("failed candidate page returned partial metadata", v, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed queries changed any state", err)
	}
}

func TestCatalogBuildCandidateNativeQueriesNeverFallBackToCachedLedgerRows(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	project, err := ledger.CreateProject(t.Context(), owner.actor, owner.product.ID, "Project")
	if err != nil {
		t.Fatal(err)
	}
	build, err := ledger.CreateBuildRun(t.Context(), owner.actor, app.CreateBuildRunInput{ProjectID: project.ID, ReleaseID: owner.release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := ledger.CreateReleaseCandidate(t.Context(), owner.actor, app.CreateReleaseCandidateInput{ReleaseID: owner.release.ID, Name: "Cached candidate"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := server.buildPointQuery.GetBuildRun(t.Context(), owner.actor, build.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, releasedomain.BuildRun{}) {
		t.Fatal("missing native build repository fell back to cached rows", v, err)
	}
	if v, err := server.releaseCandidateQuery.GetReleaseCandidate(t.Context(), owner.actor, candidate.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, releasedomain.ReleaseCandidate{}) {
		t.Fatal("missing native candidate repository fell back to cached rows", v, err)
	}
	if v, err := server.releaseCandidateQuery.ListPage(t.Context(), owner.actor, owner.release.ID, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil); !errors.Is(err, app.ErrValidation) || v.Items != nil || v.Next != nil {
		t.Fatal("missing native page repository fell back to cached list", v, err)
	}
	buildMock, candidateMock := &buildPointQueryFake{}, &releaseCandidateQueryFake{}
	server.buildPointQuery, server.releaseCandidateQuery = buildMock, candidateMock
	server.bindCatalogQueryFixturePorts(ledger)
	if server.buildPointQuery != buildMock || server.releaseCandidateQuery != candidateMock {
		t.Fatal("fixture rebinding replaced explicit query ports")
	}
}
