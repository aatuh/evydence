package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

type roleBindingQueryFake struct {
	actor identitydomain.Actor
	page  appquery.PageRequest
	calls int
	err   error
}

func (f *roleBindingQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, page appquery.PageRequest, _ *appquery.SortKey) (appquery.Result[identitydomain.RoleBinding], error) {
	f.actor, f.page = actor, page
	f.calls++
	if f.err != nil {
		return appquery.Result[identitydomain.RoleBinding]{}, f.err
	}
	return appquery.Result[identitydomain.RoleBinding]{Items: []identitydomain.RoleBinding{{
		ID: "rbac_database", TenantID: actor.TenantID, SubjectType: "user", SubjectID: "usr_database",
		Role: "tenant_admin", ResourceType: "tenant", ResourceID: actor.TenantID,
		SchemaVersion: "v1", CreatedAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
	}}}, nil
}

func TestRoleBindingHandlerUsesFocusedQueryAndRejectsMalformedPagination(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	query := &roleBindingQueryFake{}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{RoleBindingQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	response := getRaw(t, server, secret, "/v1/role-bindings?page_size=1&sort=id&direction=desc", http.StatusOK)
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			PageSize int `json:"page_size"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 || page.Data[0].ID != "rbac_database" || page.Meta.PageSize != 1 || query.calls != 1 || query.actor.TenantID == "" || query.page.Sort != appquery.SortID {
		t.Fatalf("focused binding response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/role-bindings?page_size=1&page_size=2",
		"/v1/role-bindings?sort=unknown",
		"/v1/role-bindings?cursor=forged",
		"/v1/role-bindings?limit=1",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/role-bindings", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthorized or malformed inputs reached binding query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{err: application.ErrForbidden, status: http.StatusForbidden},
		{err: identityquery.ErrValidation, status: http.StatusBadRequest},
	} {
		query.err = test.err
		getRaw(t, server, secret, "/v1/role-bindings", test.status)
	}
}
