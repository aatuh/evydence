package query

import (
	"context"
	"errors"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type sbomComponentReaderStub struct {
	request SBOMComponentPageRequest
	result  appquery.Result[SBOMComponentPoint]
	calls   int
}

func (s *sbomComponentReaderStub) PageSBOMComponents(_ context.Context, request SBOMComponentPageRequest) (appquery.Result[SBOMComponentPoint], error) {
	s.calls++
	s.request = request
	return s.result, nil
}

func TestSBOMComponentQueryAppliesScopeFilterAndPageBounds(t *testing.T) {
	point := SBOMComponentPoint{TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Record: evidencedomain.SBOMComponentRecord{
		ID: "sbom_1:0", SBOMID: "sbom_1", ReleaseID: "rel_1", Format: "cyclonedx", SpecVersion: "1.6",
		Component: evidencedomain.SBOMComponent{Name: "openssl", Version: "3.0", PURL: "pkg:generic/lib@3.0"},
	}}
	reader := &sbomComponentReaderStub{result: appquery.Result[SBOMComponentPoint]{Items: []SBOMComponentPoint{point}, Next: &appquery.SortKey{Value: "sbom_1:0", ID: "sbom_1:0"}}}
	service, err := NewSBOMComponents(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"evidence:read"}}}}
	filter := SBOMComponentFilter{SBOMID: " sbom_1 ", ReleaseID: " rel_1 ", Query: " OPEN ", PURL: " pkg:generic/lib@3.0 "}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	result, err := service.ListPage(t.Context(), actor, filter, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "sbom_1:0" || result.Next == nil || reader.request.TenantID != "ten_1" || reader.request.Filter.Query != "open" || reader.request.TenantWide || len(reader.request.AllowedProductIDs) != 1 {
		t.Fatalf("result=%#v request=%#v error=%v", result, reader.request, err)
	}
	reader.result.Items[0].TenantID = "ten_other"
	if _, err := service.ListPage(t.Context(), actor, filter, page, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign projection error=%v", err)
	}
	reader.result.Items[0].TenantID = "ten_1"
	reader.result.Items[0].ProductID = "prod_other"
	if _, err := service.ListPage(t.Context(), actor, filter, page, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong grant projection error=%v", err)
	}
	reader.result.Items[0].ProductID = "prod_1"
	reader.result.Items[0].Record.Component.Name = "unrelated"
	if _, err := service.ListPage(t.Context(), actor, filter, page, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong filter projection error=%v", err)
	}
	reader.result.Items[0].Record.Component.Name = "openssl"
	reader.result.Items[0].Record.Component.Name = ""
	withoutSearch := filter
	withoutSearch.Query = ""
	if _, err := service.ListPage(t.Context(), actor, withoutSearch, page, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("unnamed component projection error=%v", err)
	}
	reader.result.Items[0].Record.Component.Name = "openssl"
	noGrant := actor
	noGrant.ResourceGrants = nil
	before := reader.calls
	if _, err := service.ListPage(t.Context(), noGrant, filter, page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("no grant error=%v calls=%d", err, reader.calls)
	}
	badPage := appquery.PageRequest{PageSize: 501, Sort: appquery.SortID, Direction: appquery.Ascending}
	if _, err := service.ListPage(t.Context(), actor, filter, badPage, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid page error=%v", err)
	}
}
