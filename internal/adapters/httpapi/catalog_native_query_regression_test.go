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
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

func TestCatalogNativeQueryFixturesSelectRepositoryOnlyDTOsAndCurrentGrants(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	p := owner.product
	p.ID, p.Name, p.Slug, p.CreatedAt = "repository-product", "Repository product", "repository", at
	j := domain.Project{ID: "repository-project", TenantID: p.TenantID, ProductID: p.ID, Name: "Repository project", CreatedAt: at}
	v := owner.release
	v.ID, v.ProductID, v.State, v.Revision, v.CreatedAt, v.FrozenAt, v.ApprovedAt = "repository-release", p.ID, "approved", 3, at, &at, &at
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.ReleaseCatalog.InsertProduct(ctx, p); err != nil {
			return err
		}
		if err := r.ReleaseCatalog.InsertProject(ctx, j); err != nil {
			return err
		}
		return r.ReleaseCatalog.InsertRelease(ctx, v)
	}); err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"product:read", "project:read", "release:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: p.ID, Scopes: []string{"*"}}}}
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
	}{{"/v1/products/" + p.ID, p}, {"/v1/projects/" + j.ID, j}, {"/v1/releases/" + v.ID, v}} {
		out := getRaw(t, server, "fixture", tc.path, http.StatusOK).Body.String()
		want, err := json.Marshal(map[string]any{"data": tc.value, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), out)
		if strings.Contains(out, foreign.actor.TenantID) {
			t.Fatal("point read exposed foreign ownership")
		}
		auth.actor.ResourceGrants = nil
		getRaw(t, server, "fixture", tc.path, http.StatusForbidden)
		auth.actor = human
	}
	list := getRaw(t, server, "fixture", "/v1/products?page_size=2", http.StatusOK).Body.String()
	var page struct {
		Data []domain.Product `json:"data"`
	}
	if err := json.Unmarshal([]byte(list), &page); err != nil || !reflect.DeepEqual(page.Data, []domain.Product{p}) {
		t.Fatal("native page did not apply current product grant before selection", page, err)
	}
	getRaw(t, server, "fixture", "/v1/products/"+foreign.product.ID, http.StatusNotFound)
	getRaw(t, server, "fixture", "/v1/releases/"+foreign.release.ID, http.StatusNotFound)
	auth.actor.ResourceGrants = nil
	list = getRaw(t, server, "fixture", "/v1/products", http.StatusOK).Body.String()
	if err := json.Unmarshal([]byte(list), &page); err != nil || len(page.Data) != 0 {
		t.Fatal("revoked product grant returned list metadata", page, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := server.catalogPointQuery.GetRelease(ctx, human, v.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("native release point ignored cancellation", err)
	}
	query := server.catalogPointQuery.(catalogQueryFixture)
	projected, err := query.GetRelease(t.Context(), human, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	*projected.FrozenAt, *projected.ApprovedAt = at.Add(time.Hour), at.Add(time.Hour)
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("native point/page/denied/cancelled reads changed any stored state", err)
	}
}

func TestCatalogNativeQueryFixturesDiscardProjectionOnCommitFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	project, err := ledger.CreateProject(t.Context(), owner.actor, owner.product.ID, "Project")
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	for _, path := range []string{"/v1/products", "/v1/products/" + owner.product.ID, "/v1/projects/" + project.ID, "/v1/releases/" + owner.release.ID} {
		rollbacks := factory.rollbacks
		out := getRaw(t, server, "fixture", path, http.StatusInternalServerError).Body.String()
		var problem map[string]any
		if err := json.Unmarshal([]byte(out), &problem); err != nil {
			t.Fatal(err)
		}
		// Problem Details deliberately includes the caller's public path in
		// instance, including its supplied ID. No projection may be returned.
		if factory.rollbacks != rollbacks+1 || problem["instance"] != path || problem["data"] != nil || strings.Contains(out, "private-query") || strings.Contains(out, owner.product.Name) || strings.Contains(out, `"created_at"`) {
			t.Fatal("failed query commit exposed metadata or leaked transaction", out)
		}
	}
	page, err := server.productQuery.ListProductsPage(t.Context(), owner.actor, appquery.PageRequest{PageSize: 50, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err == nil || page.Items != nil || page.Next != nil {
		t.Fatal("failed native page returned partial projection", page, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed native catalog reads committed state", err)
	}
}
