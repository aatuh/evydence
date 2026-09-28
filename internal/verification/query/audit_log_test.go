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

type auditLogReaderFake struct {
	request AuditPageRequest
	result  appquery.Result[verificationdomain.AuditChainEntry]
	calls   int
}

func (f *auditLogReaderFake) PageAuditLog(_ context.Context, request AuditPageRequest) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	f.request = request
	f.calls++
	return f.result, nil
}

func TestAuditLogQueryRequiresAdminAndTenantBeforeRead(t *testing.T) {
	reader := &auditLogReaderFake{}
	service, err := NewAuditLog(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Descending}
	for _, test := range []struct {
		actor identitydomain.Actor
		want  error
	}{
		{actor: identitydomain.Actor{}, want: application.ErrUnauthorized},
		{actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}}, want: application.ErrForbidden},
		{actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"admin"}}}}, want: application.ErrForbidden},
		{actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_2", Scopes: []string{"admin"}}}}, want: application.ErrForbidden},
	} {
		if _, err := service.ListPage(t.Context(), test.actor, AuditFilter{}, page, nil); !errors.Is(err, test.want) {
			t.Fatalf("actor=%#v error=%v, want %v", test.actor, err, test.want)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("unauthorized reader calls=%d", reader.calls)
	}
}

func TestAuditLogQueryScopesAndValidatesProjection(t *testing.T) {
	reader := &auditLogReaderFake{}
	service, err := NewAuditLog(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"admin"}}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Descending}
	reader.result.Items = []verificationdomain.AuditChainEntry{{ID: "ace_1", TenantID: actor.TenantID, SubjectType: "release", SubjectID: "rel_1", OccurredAt: now}}
	filter := AuditFilter{SubjectType: "release", SubjectID: "rel_1", Since: &now}
	result, err := service.ListPage(t.Context(), actor, filter, page, nil)
	if err != nil || len(result.Items) != 1 || reader.request.TenantID != actor.TenantID || reader.request.Filter.SubjectID != filter.SubjectID || reader.request.Page != page {
		t.Fatalf("result=%#v request=%#v error=%v", result, reader.request, err)
	}
	reader.result.Items[0].TenantID = "ten_2"
	if _, err := service.ListPage(t.Context(), actor, filter, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign projection error=%v", err)
	}
	reader.result.Items[0].TenantID = actor.TenantID
	reader.result.Items[0].ID = ""
	if _, err := service.ListPage(t.Context(), actor, filter, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("missing identity error=%v", err)
	}
}

func TestAuditLogQueryRejectsInvalidPageAndReader(t *testing.T) {
	if _, err := NewAuditLog(nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
	reader := &auditLogReaderFake{}
	service, err := NewAuditLog(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"admin"}}
	if _, err := service.ListPage(t.Context(), actor, AuditFilter{}, appquery.PageRequest{PageSize: 0}, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid page error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid page reached reader %d times", reader.calls)
	}
}
