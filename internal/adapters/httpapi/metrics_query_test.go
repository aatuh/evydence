package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type metricsQueryFake struct {
	tenantID string
	result   map[string]any
}

func (f *metricsQueryFake) Snapshot(_ context.Context, actor domain.Actor) (map[string]any, error) {
	f.tenantID = actor.TenantID
	return f.result, nil
}

func TestMetricsHandlerUsesFocusedQueryWithoutLedgerState(t *testing.T) {
	server, secret := testServer(t)
	query := &metricsQueryFake{result: map[string]any{
		"tenant_id": "ten_database", "resource_counts": map[string]int{"evidence": 2},
		"customer_portal_failed_access_count":  3,
		"customer_portal_revoked_access_count": 1,
	}}
	server.metricsQuery = query
	body := getJSON(t, server, secret, "/v1/metrics", http.StatusOK)
	if query.tenantID == "" || !strings.Contains(body, `"evidence":2`) || strings.Contains(body, "payload") {
		t.Fatalf("focused metrics response=%s tenant=%q", body, query.tenantID)
	}
	plain := getRawWithAccept(t, server, secret, "/v1/metrics", "text/plain", http.StatusOK)
	if !strings.Contains(plain.Body.String(), `evydence_resource_count{resource="evidence"} 2`) ||
		!strings.Contains(plain.Body.String(), "evydence_customer_portal_failed_access_count 3") {
		t.Fatalf("focused Prometheus metrics=%s", plain.Body.String())
	}
}
