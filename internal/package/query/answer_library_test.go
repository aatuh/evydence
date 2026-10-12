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

type answerLibraryReaderStub struct {
	request AnswerLibraryPageRequest
	result  appquery.Result[AnswerLibraryPoint]
	calls   int
}

func (r *answerLibraryReaderStub) PageAnswerLibrary(_ context.Context, request AnswerLibraryPageRequest) (appquery.Result[AnswerLibraryPoint], error) {
	r.calls++
	r.request = request
	return r.result, nil
}

func TestAnswerLibraryQueryAppliesCurrentHumanVisibility(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &answerLibraryReaderStub{result: appquery.Result[AnswerLibraryPoint]{Items: []AnswerLibraryPoint{{Entry: packagedomain.QuestionnaireAnswerLibraryEntry{ID: "draft_1", TenantID: "ten_1", ProductID: "prod_1", Answer: "reviewed draft", SchemaVersion: packagedomain.QuestionnaireAnswerLibraryVersion, CreatedAt: now}, EffectiveProductID: "prod_1"}}}}
	service, err := NewAnswerLibrary(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"package:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	result, err := service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "draft_1" || reader.request.TenantWide || len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "prod_1" {
		t.Fatalf("scoped result=%#v request=%#v error=%v", result, reader.request, err)
	}
	reader.result.Items[0].Entry.ProductID = "prod_other"
	reader.result.Items[0].EffectiveProductID = "prod_other"
	if _, err := service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign product projection error=%v", err)
	}
	reader.result.Items[0].Entry.ProductID = ""
	reader.result.Items[0].EffectiveProductID = ""
	if _, err := service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("tenant-wide projection error=%v", err)
	}
	reader.result.Items[0].Entry.ProductID = "prod_1"
	reader.result.Items[0].EffectiveProductID = "prod_1"
	actor.ResourceGrants[0].ResourceID = "prod_other"
	result, err = service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, nil)
	if !errors.Is(err, ErrInvalidProjection) || len(result.Items) != 0 {
		t.Fatalf("stale grant result=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"package:read"}}
	if _, err := service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, nil); err != nil || !reader.request.TenantWide {
		t.Fatalf("tenant-wide request=%#v error=%v", reader.request, err)
	}
}

func TestAnswerLibraryQueryRejectsBadActorAndCursorBeforeReader(t *testing.T) {
	reader := &answerLibraryReaderStub{}
	service, err := NewAnswerLibrary(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"package:read"}}
	if _, err := service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, &appquery.SortKey{ID: "draft_1", Value: ""}); !errors.Is(err, ErrValidation) {
		t.Fatalf("bad cursor error=%v", err)
	}
	actor.Scopes = nil
	if _, err := service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing scope error=%v", err)
	}
	actor.KeyID = ""
	if _, err := service.ListPage(t.Context(), actor, AnswerLibraryFilter{}, page, nil); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("missing identity error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid requests reached reader %d times", reader.calls)
	}
}
