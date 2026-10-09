package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type portalAccessReaderStub struct {
	request PortalAccessPageRequest
	result  appquery.Result[PortalAccessPoint]
	calls   int
}

func (r *portalAccessReaderStub) PagePortalAccess(_ context.Context, request PortalAccessPageRequest) (appquery.Result[PortalAccessPoint], error) {
	r.calls++
	r.request = request
	return r.result, nil
}

func TestPortalAccessQueryScopesAndRedactsList(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	point := PortalAccessPoint{Access: packagedomain.CustomerPortalAccess{
		ID: "cpa_1", TenantID: "ten_1", PackageID: "pkg_1", CustomerName: "Customer",
		Prefix: "pref", ExpiresAt: now.Add(time.Hour), SchemaVersion: "customer-portal-access.v1.0.0", CreatedAt: now,
	}, ProductID: "prod_1", ReleaseID: "rel_1"}
	reader := &portalAccessReaderStub{result: appquery.Result[PortalAccessPoint]{Items: []PortalAccessPoint{point}}}
	service, err := NewPortalAccess(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "customer_security_package", ResourceID: "pkg_1", Scopes: []string{"package:read"}}}}
	result, err := service.ListPage(t.Context(), actor, " pkg_1 ", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].Hash != "" || reader.request.PackageID != "pkg_1" || reader.request.TenantWide || len(reader.request.AllowedPackageIDs) != 1 {
		t.Fatalf("package-granted page=%#v request=%#v error=%v", result, reader.request, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"package:read"}}
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); err != nil {
		t.Fatalf("product grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"package:read"}}
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); err != nil {
		t.Fatalf("release grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); !errors.Is(err, ErrPortalAccessProjection) {
		t.Fatalf("widened projection error=%v", err)
	}
	actor.ResourceGrants = nil
	reader.calls = 0
	if result, err := service.ListPage(t.Context(), actor, "", page, nil); err != nil || len(result.Items) != 0 || reader.calls != 0 {
		t.Fatalf("ungranted list=%#v calls=%d error=%v", result, reader.calls, err)
	}
	if _, err := service.ListPage(t.Context(), actor, "pkg_1", page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("ungranted filter calls=%d error=%v", reader.calls, err)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"package:read"}}
	reader.result.Items[0].Access.Hash = "private-token-hash"
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); !errors.Is(err, ErrPortalAccessProjection) {
		t.Fatalf("token hash projection error=%v", err)
	}
}

func TestPortalAccessQueryRejectsInvalidActorAndPageBeforeReading(t *testing.T) {
	reader := &portalAccessReaderStub{}
	service, _ := NewPortalAccess(reader)
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"package:read"}}
	actor.Scopes = nil
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing scope error=%v", err)
	}
	actor.KeyID = ""
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("missing identity error=%v", err)
	}
	actor.KeyID, actor.Scopes = "key_1", []string{"package:read"}
	page.PageSize = 0
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); !errors.Is(err, ErrPortalAccessValidation) {
		t.Fatalf("invalid page error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid input reached reader %d times", reader.calls)
	}
}
