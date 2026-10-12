package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type apiKeyReaderFake struct {
	request APIKeyPageRequest
	result  appquery.Result[identitydomain.APIKey]
	calls   int
}

func (f *apiKeyReaderFake) PageAPIKeys(_ context.Context, request APIKeyPageRequest) (appquery.Result[identitydomain.APIKey], error) {
	f.calls++
	f.request = request
	return f.result, nil
}

func TestAPIKeyQueryRequiresTenantWideAdminBeforeRead(t *testing.T) {
	reader := &apiKeyReaderFake{}
	service, err := NewAPIKeys(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	for _, test := range []struct {
		actor identitydomain.Actor
		want  error
	}{
		{actor: identitydomain.Actor{}, want: application.ErrUnauthorized},
		{actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}}, want: application.ErrForbidden},
		{actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"admin"}}}}, want: application.ErrForbidden},
	} {
		if _, err := service.ListPage(t.Context(), test.actor, page, nil); !errors.Is(err, test.want) {
			t.Fatalf("actor=%#v error=%v, want %v", test.actor, err, test.want)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("unauthorized reader calls=%d", reader.calls)
	}
}

func TestAPIKeyQueryRedactsHashAndChecksTenantProjection(t *testing.T) {
	reader := &apiKeyReaderFake{}
	service, err := NewAPIKeys(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_admin", Scopes: []string{"admin"}}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	reader.result.Items = []identitydomain.APIKey{{ID: "key_1", TenantID: actor.TenantID, Name: "collector", Prefix: "evy_abcdefgh", Scopes: []string{"evidence:write"}, CreatedAt: now, Hash: "should-never-escape"}}
	result, err := service.ListPage(t.Context(), actor, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].Hash != "" || reader.request.TenantID != actor.TenantID || reader.request.Page != page {
		t.Fatalf("page=%#v request=%#v error=%v", result, reader.request, err)
	}
	reader.result.Items[0].TenantID = "ten_other"
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign key projection error=%v", err)
	}
	reader.result.Items[0].TenantID = actor.TenantID
	reader.result.Items[0].ID = ""
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("missing key id projection error=%v", err)
	}
}

func TestAPIKeyQueryRejectsInvalidPageBeforeRead(t *testing.T) {
	if _, err := NewAPIKeys(nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
	reader := &apiKeyReaderFake{}
	service, err := NewAPIKeys(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_admin", Scopes: []string{"admin"}}
	if _, err := service.ListPage(t.Context(), actor, appquery.PageRequest{PageSize: 0}, nil); !errors.Is(err, ErrValidation) || reader.calls != 0 {
		t.Fatalf("invalid page error=%v calls=%d", err, reader.calls)
	}
}
