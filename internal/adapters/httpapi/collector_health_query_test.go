package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type collectorHealthQueryFake struct {
	calls int
	err   error
}

func (f *collectorHealthQueryFake) Report(_ context.Context, _ identitydomain.Actor, id string) (integrationdomain.CollectorHealthReport, error) {
	f.calls++
	if f.err != nil {
		return integrationdomain.CollectorHealthReport{}, f.err
	}
	return integrationdomain.CollectorHealthReport{ReportType: "collector_health", CollectorID: id, CollectorStatus: "active", SupplyChainStatus: "missing_release_evidence", Checks: []integrationdomain.VerificationCheck{{Name: "collector_release", Result: "failed"}}}, nil
}

func TestCollectorHealthHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &collectorHealthQueryFake{}
	server.collectorHealthQuery = query
	response := getRaw(t, server, secret, "/v1/collectors/col_1/health", http.StatusOK)
	var payload struct {
		Data struct {
			CollectorID       string `json:"collector_id"`
			SupplyChainStatus string `json:"supply_chain_status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Data.CollectorID != "col_1" || payload.Data.SupplyChainStatus != "missing_release_evidence" || query.calls != 1 {
		t.Fatalf("health=%s calls=%d error=%v", response.Body.String(), query.calls, err)
	}
	getRawNoAuth(t, server, "/v1/collectors/col_1/health", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{integrationquery.ErrNotFound, http.StatusNotFound},
		{integrationquery.ErrInvalidProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response = getRaw(t, server, secret, "/v1/collectors/col_1/health", test.status)
		if strings.Contains(response.Body.String(), "private-database-detail") {
			t.Fatalf("database detail leaked: %s", response.Body.String())
		}
	}
}
