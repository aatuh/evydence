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

type roleBindingReaderFake struct {
	request RoleBindingPageRequest
	result  appquery.Result[identitydomain.RoleBinding]
	calls   int
}

func (f *roleBindingReaderFake) PageRoleBindings(_ context.Context, request RoleBindingPageRequest) (appquery.Result[identitydomain.RoleBinding], error) {
	f.calls++
	f.request = request
	return f.result, nil
}

func TestRoleBindingQueryRequiresTenantWideIdentityAdminBeforeRead(t *testing.T) {
	reader := &roleBindingReaderFake{}
	service, err := NewRoleBindings(reader)
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
		{actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"identity:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"identity:admin"}}}}, want: application.ErrForbidden},
	} {
		if _, err := service.ListPage(t.Context(), test.actor, page, nil); !errors.Is(err, test.want) {
			t.Fatalf("actor=%#v error=%v, want %v", test.actor, err, test.want)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("unauthorized reader calls=%d", reader.calls)
	}
}

func TestRoleBindingQueryChecksTenantAndPageProjection(t *testing.T) {
	reader := &roleBindingReaderFake{}
	service, err := NewRoleBindings(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_admin", Scopes: []string{"identity:admin"}}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	reader.result.Items = []identitydomain.RoleBinding{{ID: "rbac_1", TenantID: actor.TenantID, SubjectType: "user", SubjectID: "usr_1", Role: "tenant_admin", SchemaVersion: "v1", CreatedAt: now}}
	result, err := service.ListPage(t.Context(), actor, page, nil)
	if err != nil || len(result.Items) != 1 || reader.request.TenantID != actor.TenantID || reader.request.Page != page {
		t.Fatalf("page=%#v request=%#v error=%v", result, reader.request, err)
	}
	reader.result.Items[0].TenantID = "ten_other"
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign binding projection error=%v", err)
	}
	reader.result.Items[0].TenantID = actor.TenantID
	reader.result.Next = &appquery.SortKey{Value: "wrong", ID: "rbac_1"}
	if _, err := service.ListPage(t.Context(), actor, page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("invalid next key error=%v", err)
	}
}

func TestRoleBindingQueryRejectsInvalidPageBeforeRead(t *testing.T) {
	if _, err := NewRoleBindings(nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
	reader := &roleBindingReaderFake{}
	service, err := NewRoleBindings(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_admin", Scopes: []string{"identity:admin"}}
	if _, err := service.ListPage(t.Context(), actor, appquery.PageRequest{PageSize: 0}, nil); !errors.Is(err, ErrValidation) || reader.calls != 0 {
		t.Fatalf("invalid page error=%v calls=%d", err, reader.calls)
	}
}
