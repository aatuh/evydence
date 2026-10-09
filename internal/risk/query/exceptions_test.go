package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type exceptionPageReaderStub struct {
	request ExceptionPageRequest
	result  ExceptionPage
	err     error
	calls   int
}

func (r *exceptionPageReaderStub) PageExceptions(_ context.Context, request ExceptionPageRequest) (ExceptionPage, error) {
	r.calls++
	r.request = request
	return r.result, r.err
}

func TestExceptionPageScopesFilteredReleaseAndValidatesRows(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	exception := riskdomain.Exception{ID: "ex_1", TenantID: "ten_1", ReleaseID: "rel_1", Reason: "accepted risk", Owner: "security", ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now}
	key := appquery.RecordSortKey(exception.ID, exception.CreatedAt, appquery.SortCreatedAt)
	reader := &exceptionPageReaderStub{result: ExceptionPage{FilterRelease: ReleaseScope{ID: "rel_1", ProductID: "prod_1"}, Page: appquery.Result[ExceptionPoint]{Items: []ExceptionPoint{{Exception: exception, ProductID: "prod_1"}}, Next: &key}}}
	service, err := NewExceptions(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"verify:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	result, err := service.ListPage(context.Background(), actor, "rel_1", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "ex_1" || result.Next == nil || reader.request.TenantWide || len(reader.request.AllowedProductIDs) != 1 {
		t.Fatalf("authorized page=%#v request=%#v error=%v", result, reader.request, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_2"
	if _, err := service.ListPage(context.Background(), actor, "rel_1", page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong product grant error=%v", err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_1"
	reader.result.Page.Items[0].Exception.TenantID = "ten_other"
	if _, err := service.ListPage(context.Background(), actor, "rel_1", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("cross-tenant row error=%v", err)
	}
	reader.result.Page.Items[0].Exception.TenantID = "ten_1"
	reader.result.Page.Items[0].Exception.ReleaseID = "rel_other"
	if _, err := service.ListPage(context.Background(), actor, "rel_1", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong-release row error=%v", err)
	}
	reader.err = ErrNotFound
	if _, err := service.ListPage(context.Background(), actor, "rel_missing", page, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing filtered release error=%v", err)
	}
	actor.Scopes = nil
	before := reader.calls
	if _, err := service.ListPage(context.Background(), actor, "rel_1", page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("missing scope error=%v reader calls=%d", err, reader.calls)
	}
}
