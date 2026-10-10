package query

import (
	"errors"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestCatalogPreflightAndTenantInventoryCannotIgnoreResourceClaims(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	for _, scope := range []string{"product:read", "project:read", "project:write", "release:read", "release:write", "build:read", "build:write"} {
		for _, request := range []application.AuthorizationRequest{
			{Scope: scope, ScopeOnly: true, Resources: application.ResourceReferences{ProductID: "product"}},
			{Scope: scope, TenantWide: true, Resources: application.ResourceReferences{ReleaseID: "release"}},
		} {
			if err := NewCatalogAuthorizer().Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
				t.Errorf("%s discarded a resource claim: %#v error=%v", scope, request, err)
			}
		}
	}
}

func TestCentralCatalogPolicyFiltersHumanInventoryBeforeReadAndRechecksRevocation(t *testing.T) {
	reader := &productPageReaderFake{result: appquery.Result[releasedomain.Product]{Items: []releasedomain.Product{{ID: "allowed", TenantID: "tenant"}}}}
	service, err := NewProducts(reader, NewCatalogAuthorizer())
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{"product:read"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: "allowed", Scopes: []string{"product:read"}},
		{ResourceType: "product", ResourceID: "wrong-capability", Scopes: []string{"release:read"}},
		{ResourceType: "release", ResourceID: "release", Scopes: []string{"product:read"}},
		{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
	}}
	page, err := service.ListProductsPage(t.Context(), actor, productPageRequest(), nil)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "allowed" || reader.calls != 1 || reader.request.TenantID != "tenant" || reader.request.TenantWide || len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "allowed" {
		t.Fatalf("central policy did not filter before read: page=%#v request=%#v calls=%d error=%v", page, reader.request, reader.calls, err)
	}
	actor.ResourceGrants = nil
	page, err = service.ListProductsPage(t.Context(), actor, productPageRequest(), nil)
	if err != nil || len(page.Items) != 0 || reader.calls != 1 {
		t.Fatalf("revoked inventory grant reached reader: page=%#v calls=%d error=%v", page, reader.calls, err)
	}
	for _, issued := range []identitydomain.Actor{{KeyID: "key"}, {KeyID: "collector-key", CollectorID: "collector"}} {
		issued.TenantID, issued.Scopes = "tenant", []string{"product:read"}
		page, err = service.ListProductsPage(t.Context(), issued, productPageRequest(), nil)
		if err != nil || len(page.Items) != 1 || !reader.request.TenantWide || reader.request.TenantID != "tenant" || len(reader.request.AllowedProductIDs) != 0 {
			t.Fatalf("issued inventory capability changed: page=%#v request=%#v error=%v", page, reader.request, err)
		}
	}
}

func TestCentralCatalogPointPolicyPreservesForeignMissingVisibilityAndCurrentGrant(t *testing.T) {
	reader := &productPageReaderFake{product: releasedomain.Product{ID: "product", TenantID: "tenant", Name: "owned"}}
	service, err := NewProducts(reader, NewCatalogAuthorizer())
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{"product:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"product:read"}}}}
	value, err := service.GetProduct(t.Context(), actor, "product")
	if err != nil || value.ID != "product" || value.Name != "owned" || reader.getTenant != "tenant" || reader.getID != "product" {
		t.Fatalf("resolved current grant failed: value=%#v tenant=%q id=%q error=%v", value, reader.getTenant, reader.getID, err)
	}
	actor.ResourceGrants = nil
	if value, err := service.GetProduct(t.Context(), actor, "product"); value.ID != "" || !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("revoked point grant exposed a result: value=%#v error=%v", value, err)
	}
	reader.product.TenantID = "foreign"
	if value, err := service.GetProduct(t.Context(), actor, "product"); value.ID != "" || !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign point visibility changed: value=%#v error=%v", value, err)
	}
	reader.getErr = ErrNotFound
	if value, err := service.GetProduct(t.Context(), actor, "missing"); value.ID != "" || !errors.Is(err, ErrNotFound) || reader.getTenant != "tenant" {
		t.Fatalf("missing point differs from foreign visibility: value=%#v tenant=%q error=%v", value, reader.getTenant, err)
	}
}
