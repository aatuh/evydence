package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signingKeyPageReaderStub struct {
	request SigningKeyPageRequest
	result  appquery.Result[verificationdomain.SigningKey]
	calls   int
}

func (r *signingKeyPageReaderStub) PageSigningKeys(_ context.Context, request SigningKeyPageRequest) (appquery.Result[verificationdomain.SigningKey], error) {
	r.calls++
	r.request = request
	return r.result, nil
}

func TestSigningKeyQueryRequiresTenantGrantAndRejectsLeakyProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	reader := &signingKeyPageReaderStub{result: appquery.Result[verificationdomain.SigningKey]{Items: []verificationdomain.SigningKey{{ID: "key_1", TenantID: "ten_1", KID: "kid_1", Version: 1, Provider: "local_ed25519", Algorithm: "Ed25519", Status: status, PublicKey: "public", ValidFrom: now, CreatedAt: now}}}}
	service, err := NewSigningKeys(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"verify:read"}}}}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("product grant reached key reader: %v, calls=%d", err, reader.calls)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"verify:read"}}
	result, err := service.ListPage(t.Context(), actor, page, nil)
	if err != nil || len(result.Items) != 1 || reader.request.TenantID != actor.TenantID {
		t.Fatalf("tenant query=%#v request=%#v error=%v", result, reader.request, err)
	}
	reader.result.Items[0].TenantID = "ten_other"
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrSigningKeyProjection) {
		t.Fatalf("cross-tenant projection error=%v", err)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "api_1", Scopes: []string{"verify:read"}}
	reader.result.Items[0].TenantID = actor.TenantID
	if _, err := service.ListPage(t.Context(), actor, page, nil); err != nil {
		t.Fatalf("issued credential query: %v", err)
	}
}

func TestSigningKeyQueryRejectsMalformedActorPageAndCursor(t *testing.T) {
	reader := &signingKeyPageReaderStub{}
	service, _ := NewSigningKeys(reader)
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Descending}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "api_1", Scopes: []string{"verify:read"}}
	if _, err := service.ListPage(t.Context(), actor, appquery.PageRequest{}, nil); !errors.Is(err, ErrSigningKeyValidation) {
		t.Fatalf("bad page error=%v", err)
	}
	actor.KeyID = ""
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("missing identity error=%v", err)
	}
	actor.KeyID, actor.Scopes = "api_1", nil
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing scope error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid requests reached reader %d times", reader.calls)
	}
	actor.Scopes = []string{"verify:read"}
	reader.result.Next = &appquery.SortKey{Value: "wrong", ID: "wrong"}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrSigningKeyProjection) {
		t.Fatalf("invalid continuation error=%v", err)
	}
}
