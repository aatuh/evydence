package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type collectorReaderFake struct {
	request CollectorPageRequest
	result  appquery.Result[integrationdomain.Collector]
	calls   int
}

func (f *collectorReaderFake) PageCollectors(_ context.Context, request CollectorPageRequest) (appquery.Result[integrationdomain.Collector], error) {
	f.calls++
	f.request = request
	return f.result, nil
}

func TestCollectorPagesRequireTenantWideReadGrant(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	status, _ := integrationdomain.ParseCollectorStatus(integrationdomain.CollectorStatusActiveValue)
	collector := integrationdomain.Collector{ID: "col_1", TenantID: "ten_1", APIKeyID: "key_1", Status: status, CreatedAt: now}
	reader := &collectorReaderFake{result: appquery.Result[integrationdomain.Collector]{Items: []integrationdomain.Collector{collector}}}
	service, err := NewCollectors(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"collector:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"collector:read"}}}}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("product-only inventory read error=%v calls=%d", err, reader.calls)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_other", Scopes: []string{"collector:read"}}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("foreign tenant grant error=%v calls=%d", err, reader.calls)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_1", Scopes: []string{"collector:read"}}
	result, err := service.ListPage(t.Context(), actor, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "col_1" || reader.request.TenantID != "ten_1" {
		t.Fatalf("tenant inventory=%#v request=%#v error=%v", result, reader.request, err)
	}
	actor.ResourceGrants = nil
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != 1 {
		t.Fatalf("revoked grant error=%v calls=%d", err, reader.calls)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"collector:read"}}
	if _, err := service.ListPage(t.Context(), actor, page, nil); err != nil || reader.calls != 2 {
		t.Fatalf("scoped credential error=%v calls=%d", err, reader.calls)
	}
	actor.Scopes = nil
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != 2 {
		t.Fatalf("missing scope error=%v calls=%d", err, reader.calls)
	}
}

func TestCollectorPagesRejectForeignAndMalformedProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	status, _ := integrationdomain.ParseCollectorStatus(integrationdomain.CollectorStatusActiveValue)
	collector := integrationdomain.Collector{ID: "col_1", TenantID: "ten_1", APIKeyID: "key_1", Status: status, CreatedAt: now}
	reader := &collectorReaderFake{result: appquery.Result[integrationdomain.Collector]{Items: []integrationdomain.Collector{collector}}}
	service, err := NewCollectors(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"collector:read"}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	reader.result.Items[0].TenantID = "ten_other"
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign collector error=%v", err)
	}
	reader.result.Items[0] = collector
	reader.result.Next = &appquery.SortKey{ID: "col_other", Value: now.Format(time.RFC3339Nano)}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong cursor error=%v", err)
	}
	if _, err := NewCollectors(nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
}
