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

type commercialCollectorReaderStub struct {
	request CommercialCollectorPageRequest
	result  appquery.Result[integrationdomain.CommercialCollectorDefinition]
	calls   int
}

func (r *commercialCollectorReaderStub) PageCommercialCollectors(_ context.Context, request CommercialCollectorPageRequest) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error) {
	r.calls++
	r.request = request
	return r.result, nil
}

func TestCommercialCollectorQueryRequiresTenantGrantAndBoundedProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	entry := integrationdomain.CommercialCollectorDefinition{ID: "commercial_1", TenantID: "ten_1", Name: "Scanner", Provider: "example", Version: "1", ManifestHash: "sha256:manifest", AllowedScopes: []string{"evidence:write"}, Status: "available", SchemaVersion: "commercial-collector.v1.0.0", CreatedAt: now}
	reader := &commercialCollectorReaderStub{result: appquery.Result[integrationdomain.CommercialCollectorDefinition]{Items: []integrationdomain.CommercialCollectorDefinition{entry}}}
	service, err := NewCommercialCollectors(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"collector:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"collector:read"}}}}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("product grant reached definition reader: %v calls=%d", err, reader.calls)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"collector:read"}}
	result, err := service.ListPage(t.Context(), actor, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != entry.ID || reader.request.TenantID != actor.TenantID {
		t.Fatalf("tenant page=%#v request=%#v error=%v", result, reader.request, err)
	}
	reader.result.Items[0].TenantID = "ten_other"
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign projection error=%v", err)
	}
	actor.ResourceGrants = nil
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("revoked grant error=%v", err)
	}
}

func TestCommercialCollectorQueryRejectsInvalidActorAndPage(t *testing.T) {
	reader := &commercialCollectorReaderStub{}
	service, _ := NewCommercialCollectors(reader)
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"collector:read"}}
	if _, err := service.ListPage(t.Context(), actor, appquery.PageRequest{}, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid page error=%v", err)
	}
	actor.KeyID = ""
	if _, err := service.ListPage(t.Context(), actor, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("missing identity error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid inputs reached reader %d times", reader.calls)
	}
}
