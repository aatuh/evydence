package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

type apiKeyQueryFake struct {
	actor identitydomain.Actor
	page  appquery.PageRequest
	calls int
	err   error
}

func (f *apiKeyQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, page appquery.PageRequest, _ *appquery.SortKey) (appquery.Result[identitydomain.APIKey], error) {
	f.actor, f.page = actor, page
	f.calls++
	if f.err != nil {
		return appquery.Result[identitydomain.APIKey]{}, f.err
	}
	return appquery.Result[identitydomain.APIKey]{Items: []identitydomain.APIKey{{
		ID: "key_database", TenantID: actor.TenantID, Name: "Database key", Prefix: "evy_abcdefgh",
		Scopes: []string{"evidence:read"}, Hash: "should-not-escape", CreatedAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
	}}}, nil
}

func TestAPIKeyHandlerUsesFocusedQueryAndRejectsMalformedPagination(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	query := &apiKeyQueryFake{}
	server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), ledger, ServerOptions{APIKeyQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	response := getRaw(t, server, secret, "/v1/api-keys?page_size=1&sort=id&direction=desc", http.StatusOK)
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			PageSize int `json:"page_size"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 || page.Data[0].ID != "key_database" || page.Meta.PageSize != 1 || query.calls != 1 || query.actor.TenantID == "" || query.page.Sort != appquery.SortID || strings.Contains(response.Body.String(), "should-not-escape") || strings.Contains(response.Body.String(), `"hash"`) {
		t.Fatalf("focused key response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/api-keys?page_size=1&page_size=2",
		"/v1/api-keys?sort=unknown",
		"/v1/api-keys?cursor=forged",
		"/v1/api-keys?limit=1",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/api-keys", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthorized or malformed inputs reached key query %d times", query.calls)
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
		getRaw(t, server, secret, "/v1/api-keys", test.status)
	}
}
