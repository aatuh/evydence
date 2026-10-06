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
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type commercialCollectorQueryFake struct {
	calls int
	err   error
}

func (f *commercialCollectorQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, _ appquery.PageRequest, _ *appquery.SortKey) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error) {
	f.calls++
	if f.err != nil {
		return appquery.Result[integrationdomain.CommercialCollectorDefinition]{}, f.err
	}
	return appquery.Result[integrationdomain.CommercialCollectorDefinition]{Items: []integrationdomain.CommercialCollectorDefinition{{ID: "commercial_database", TenantID: actor.TenantID, Name: "Scanner", Provider: "example", Version: "1", ManifestHash: "sha256:manifest", AllowedScopes: []string{"evidence:write"}, Status: "available", SchemaVersion: "commercial-collector.v1.0.0", CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}}}, nil
}

func TestCommercialCollectorHandlerUsesFocusedQueryAndValidatesPagination(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	query := &commercialCollectorQueryFake{}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{CommercialCollectorQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	response := getRaw(t, server, secret, "/v1/commercial-collectors?page_size=1&sort=id&direction=desc", http.StatusOK)
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			PageSize int `json:"page_size"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 || page.Data[0].ID != "commercial_database" || page.Meta.PageSize != 1 || query.calls != 1 {
		t.Fatalf("focused commercial collector response=%s calls=%d error=%v", response.Body.String(), query.calls, err)
	}
	for _, path := range []string{"/v1/commercial-collectors?page_size=1&page_size=2", "/v1/commercial-collectors?sort=unknown", "/v1/commercial-collectors?cursor=forged", "/v1/commercial-collectors?limit=1"} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/commercial-collectors", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("invalid requests reached commercial query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{application.ErrForbidden, http.StatusForbidden},
		{integrationquery.ErrValidation, http.StatusBadRequest},
		{integrationquery.ErrInvalidProjection, http.StatusConflict},
	} {
		query.err = test.err
		getRaw(t, server, secret, "/v1/commercial-collectors", test.status)
	}
}
