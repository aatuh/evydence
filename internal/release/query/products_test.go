package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type productPageReaderFake struct {
	request ProductPageRequest
	result  appquery.Result[releasedomain.Product]
	calls   int
	err     error
}

func (f *productPageReaderFake) PageProducts(_ context.Context, request ProductPageRequest) (appquery.Result[releasedomain.Product], error) {
	f.calls++
	f.request = request
	return f.result, f.err
}

type productAuthorizerFake struct {
	tenantWide bool
	allowed    map[string]bool
	err        error
}

func (f productAuthorizerFake) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	if f.err != nil {
		return f.err
	}
	if request.Scope != "product:read" {
		return application.ErrForbidden
	}
	if request.ScopeOnly {
		return nil
	}
	if request.TenantWide {
		if f.tenantWide {
			return nil
		}
		return application.ErrForbidden
	}
	if f.tenantWide || f.allowed[request.Resources.ProductID] {
		return nil
	}
	return application.ErrForbidden
}

func productPageRequest() appquery.PageRequest {
	return appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
}

func TestListProductsPageUsesTenantBoundReaderForAPIKey(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	reader := &productPageReaderFake{result: appquery.Result[releasedomain.Product]{
		Items: []releasedomain.Product{{ID: "prod_1", TenantID: "ten_1", Name: "One", CreatedAt: now}},
	}}
	service, err := NewProducts(reader, productAuthorizerFake{tenantWide: true})
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:read"}}
	page, err := service.ListProductsPage(t.Context(), actor, productPageRequest(), nil)
	if err != nil || len(page.Items) != 1 || reader.calls != 1 || reader.request.TenantID != actor.TenantID || !reader.request.TenantWide {
		t.Fatalf("tenant-wide page=%#v reader=%#v error=%v", page, reader, err)
	}
}

func TestListProductsPageFiltersHumanGrantBeforeDatabaseQuery(t *testing.T) {
	reader := &productPageReaderFake{result: appquery.Result[releasedomain.Product]{Items: []releasedomain.Product{{ID: "prod_allowed", TenantID: "ten_1"}}}}
	service, err := NewProducts(reader, productAuthorizerFake{allowed: map[string]bool{"prod_allowed": true}})
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"product:read"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: "prod_allowed", Scopes: []string{"product:read"}},
		{ResourceType: "product", ResourceID: "prod_denied", Scopes: []string{"product:read"}},
		{ResourceType: "project", ResourceID: "proj_other", Scopes: []string{"product:read"}},
	}}
	page, err := service.ListProductsPage(t.Context(), actor, productPageRequest(), nil)
	if err != nil || len(page.Items) != 1 || reader.request.TenantWide || len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "prod_allowed" {
		t.Fatalf("scoped page=%#v request=%#v error=%v", page, reader.request, err)
	}
}

func TestListProductsPageFailsClosedOnForeignOrUnauthorizedProjection(t *testing.T) {
	for _, product := range []releasedomain.Product{
		{ID: "prod_foreign", TenantID: "ten_2"},
		{ID: "prod_denied", TenantID: "ten_1"},
	} {
		t.Run(product.ID, func(t *testing.T) {
			reader := &productPageReaderFake{result: appquery.Result[releasedomain.Product]{Items: []releasedomain.Product{product}}}
			service, err := NewProducts(reader, productAuthorizerFake{allowed: map[string]bool{"prod_allowed": true}})
			if err != nil {
				t.Fatal(err)
			}
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"product:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_allowed", Scopes: []string{"product:read"}}}}
			page, err := service.ListProductsPage(t.Context(), actor, productPageRequest(), nil)
			if err == nil || len(page.Items) != 0 {
				t.Fatalf("unsafe projection exposed: page=%#v error=%v", page, err)
			}
		})
	}
}

func TestListProductsPageRejectsCursorNotBoundToLastVisibleProduct(t *testing.T) {
	createdAt := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	wrong := appquery.RecordSortKey("prod_foreign", createdAt, appquery.SortCreatedAt)
	reader := &productPageReaderFake{result: appquery.Result[releasedomain.Product]{
		Items: []releasedomain.Product{{ID: "prod_allowed", TenantID: "ten_1", CreatedAt: createdAt}}, Next: &wrong,
	}}
	service, err := NewProducts(reader, productAuthorizerFake{tenantWide: true})
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.ListProductsPage(t.Context(), identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1"}, productPageRequest(), nil)
	if !errors.Is(err, ErrInvalidProjection) || len(page.Items) != 0 {
		t.Fatalf("foreign continuation leaked: page=%#v error=%v", page, err)
	}
}

func TestListProductsPageRejectsInvalidInputsAndPropagatesBackendFailure(t *testing.T) {
	reader := &productPageReaderFake{}
	service, err := NewProducts(reader, productAuthorizerFake{tenantWide: true})
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1"}
	if _, err := service.ListProductsPage(t.Context(), actor, appquery.PageRequest{PageSize: 501, Sort: appquery.SortID, Direction: appquery.Ascending}, nil); err == nil || reader.calls != 0 {
		t.Fatalf("invalid page reached backend: calls=%d error=%v", reader.calls, err)
	}
	if _, err := service.ListProductsPage(t.Context(), identitydomain.Actor{}, productPageRequest(), nil); err == nil || reader.calls != 0 {
		t.Fatalf("missing tenant reached backend: calls=%d error=%v", reader.calls, err)
	}
	backendErr := errors.New("backend unavailable")
	reader.err = backendErr
	if _, err := service.ListProductsPage(t.Context(), actor, productPageRequest(), nil); !errors.Is(err, backendErr) {
		t.Fatalf("backend error was suppressed: %v", err)
	}
}
