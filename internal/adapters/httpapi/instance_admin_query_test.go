package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type instanceCountsHTTPFake struct {
	counts operationsquery.InstanceCounts
	calls  int
	err    error
}

func (f *instanceCountsHTTPFake) ReadInstanceCounts(context.Context) (operationsquery.InstanceCounts, error) {
	f.calls++
	return f.counts, f.err
}

func TestInstanceAdminHandlerUsesFocusedCountsAndPreservesExplicitScope(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, tenantSecret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "tenant-admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, instanceSecret, err := ledger.BootstrapTenant(t.Context(), "Instance", "instance-admin", []string{"instance:admin"})
	if err != nil {
		t.Fatal(err)
	}
	reader := &instanceCountsHTTPFake{counts: operationsquery.InstanceCounts{Tenants: 2, Users: 3, Collectors: 4, Evidence: 5}}
	query, err := operationsquery.NewInstanceAdmin(reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), ledger, ServerOptions{InstanceAdminQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	getRaw(t, server, tenantSecret, "/v1/admin/instance", http.StatusForbidden)
	getRawNoAuth(t, server, "/v1/admin/instance", http.StatusUnauthorized)
	if reader.calls != 0 {
		t.Fatalf("unauthorized request reached reader %d times", reader.calls)
	}
	response := getRaw(t, server, instanceSecret, "/v1/admin/instance", http.StatusOK)
	var payload struct {
		Data struct {
			TenantCount    int            `json:"tenant_count"`
			ResourceCounts map[string]int `json:"resource_counts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Data.TenantCount != 2 || payload.Data.ResourceCounts["evidence"] != 5 || reader.calls != 1 {
		t.Fatalf("snapshot=%s calls=%d error=%v", response.Body.String(), reader.calls, err)
	}
	reader.counts.Evidence = -1
	getRaw(t, server, instanceSecret, "/v1/admin/instance", http.StatusConflict)
	reader.counts.Evidence = 5
	reader.err = errors.New("private-database-detail")
	response = getRaw(t, server, instanceSecret, "/v1/admin/instance", http.StatusInternalServerError)
	if strings.Contains(response.Body.String(), "private-database-detail") {
		t.Fatalf("database detail leaked: %s", response.Body.String())
	}
}
