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
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type controlEvidenceQueryFake struct {
	calls  int
	filter riskquery.ControlEvidenceFilter
	err    error
}

func (f *controlEvidenceQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, filter riskquery.ControlEvidenceFilter, _ appquery.PageRequest, _ *appquery.SortKey) (appquery.Result[riskdomain.ControlEvidence], error) {
	f.calls++
	f.filter = filter
	if f.err != nil {
		return appquery.Result[riskdomain.ControlEvidence]{}, f.err
	}
	return appquery.Result[riskdomain.ControlEvidence]{Items: []riskdomain.ControlEvidence{{ID: "link_1", TenantID: actor.TenantID, ControlID: "control_1", EvidenceType: "artifact", SubjectType: "evidence", SubjectID: "ev_1", ProductID: "product_1", Confidence: "high", SchemaVersion: "control-evidence.v1.0.0", CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}}}, nil
}

func TestControlEvidenceHandlerUsesFocusedQueryAndValidatesFilters(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	query := &controlEvidenceQueryFake{}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{ControlEvidenceQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	response := getRaw(t, server, secret, "/v1/control-evidence?product_id=product_1&page_size=1", http.StatusOK)
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 || page.Data[0].ID != "link_1" || query.calls != 1 || query.filter.ProductID != "product_1" {
		t.Fatalf("focused control evidence response=%s calls=%d filter=%#v error=%v", response.Body.String(), query.calls, query.filter, err)
	}
	for _, path := range []string{"/v1/control-evidence?product_id=a&product_id=b", "/v1/control-evidence?sort=unknown", "/v1/control-evidence?cursor=forged", "/v1/control-evidence?limit=1"} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/control-evidence", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("invalid requests reached control evidence query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{application.ErrForbidden, http.StatusForbidden},
		{riskquery.ErrValidation, http.StatusBadRequest},
		{riskquery.ErrInvalidProjection, http.StatusConflict},
	} {
		query.err = test.err
		getRaw(t, server, secret, "/v1/control-evidence", test.status)
	}
}
