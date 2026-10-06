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
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type marketplaceCollectorQueryFake struct {
	listCalls, healthCalls int
	err                    error
}

func (f *marketplaceCollectorQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, _ appquery.PageRequest, _ *appquery.SortKey) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	f.listCalls++
	if f.err != nil {
		return appquery.Result[experimentaldomain.MarketplaceCollector]{}, f.err
	}
	return appquery.Result[experimentaldomain.MarketplaceCollector]{Items: []experimentaldomain.MarketplaceCollector{{ID: "market_1", TenantID: actor.TenantID, Name: "Scanner", Provider: "example", Version: "1", Publisher: "example", ManifestHash: "sha256:manifest", State: "published", SchemaVersion: "marketplace-collector.v1.0.0", CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}}}, nil
}

func (f *marketplaceCollectorQueryFake) Health(_ context.Context, _ identitydomain.Actor, id string) (experimentaldomain.MarketplaceCollectorHealthReport, error) {
	f.healthCalls++
	if f.err != nil {
		return experimentaldomain.MarketplaceCollectorHealthReport{}, f.err
	}
	return experimentaldomain.MarketplaceCollectorHealthReport{ReportType: "marketplace_collector_health", CollectorID: id, SupplyChainStatus: "incomplete", Checks: []experimentaldomain.VerificationCheck{{Name: "manifest_digest", Result: "passed"}}}, nil
}

func TestMarketplaceCollectorHandlersUseFocusedQueryAndValidatePagination(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	query := &marketplaceCollectorQueryFake{}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{MarketplaceCollectorQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	response := getRaw(t, server, secret, "/v1/marketplace-collectors?page_size=1&sort=id&direction=desc", http.StatusOK)
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 || page.Data[0].ID != "market_1" || query.listCalls != 1 {
		t.Fatalf("marketplace page=%s calls=%d error=%v", response.Body.String(), query.listCalls, err)
	}
	response = getRaw(t, server, secret, "/v1/marketplace-collectors/market_1/health", http.StatusOK)
	var health struct {
		Data struct {
			CollectorID       string `json:"collector_id"`
			SupplyChainStatus string `json:"supply_chain_status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil || health.Data.CollectorID != "market_1" || health.Data.SupplyChainStatus != "incomplete" || query.healthCalls != 1 {
		t.Fatalf("marketplace health=%s calls=%d error=%v", response.Body.String(), query.healthCalls, err)
	}
	for _, path := range []string{"/v1/marketplace-collectors?page_size=1&page_size=2", "/v1/marketplace-collectors?sort=unknown", "/v1/marketplace-collectors?cursor=forged", "/v1/marketplace-collectors?limit=1"} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/marketplace-collectors", http.StatusUnauthorized)
	getRawNoAuth(t, server, "/v1/marketplace-collectors/market_1/health", http.StatusUnauthorized)
	if query.listCalls != 1 || query.healthCalls != 1 {
		t.Fatalf("invalid requests reached query: list=%d health=%d", query.listCalls, query.healthCalls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{application.ErrForbidden, http.StatusForbidden}, {experimentalquery.ErrValidation, http.StatusBadRequest}, {experimentalquery.ErrInvalidProjection, http.StatusConflict},
	} {
		query.err = test.err
		getRaw(t, server, secret, "/v1/marketplace-collectors", test.status)
	}
	query.err = experimentalquery.ErrNotFound
	getRaw(t, server, secret, "/v1/marketplace-collectors/missing/health", http.StatusNotFound)
}
