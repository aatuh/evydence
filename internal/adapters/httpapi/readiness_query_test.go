package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func TestReadinessHandlersUseFocusedProbeWithoutLedgerConfiguration(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "test", UnitOfWork: factory})
	bootstrap := tenantBootstrapNativeFixture{factory, fixtureSessionCredentials("test"), providerVerificationFixtureClock()}
	_, _, tenantSecret, err := bootstrap.BootstrapTenant(t.Context(), "Tenant", "tenant-admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, instanceSecret, err := bootstrap.BootstrapTenant(t.Context(), "Instance", "instance-admin", []string{app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	server.readinessQuery, err = operationsquery.NewReadiness([]operationsquery.ReadinessCheck{{
		Name: "postgres", Timeout: time.Second, FailureDetail: "database connectivity is unavailable",
		Check: func(context.Context) error { return errors.New("postgres://user:top-secret@database.internal") },
	}})
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewRecorder()
	server.Handler().ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/v1/ready", nil))
	if public.Code != http.StatusServiceUnavailable || !strings.Contains(public.Body.String(), `"status":"unavailable"`) {
		t.Fatalf("public readiness status=%d body=%s", public.Code, public.Body.String())
	}
	for _, forbidden := range []string{"top-secret", "database.internal", "database connectivity"} {
		if strings.Contains(public.Body.String(), forbidden) {
			t.Fatalf("public readiness leaked %q: %s", forbidden, public.Body.String())
		}
	}
	getJSON(t, server, tenantSecret, "/v1/admin/readiness", http.StatusForbidden)
	diagnostics := getJSON(t, server, instanceSecret, "/v1/admin/readiness", http.StatusOK)
	if !strings.Contains(diagnostics, "database connectivity is unavailable") || strings.Contains(diagnostics, "top-secret") {
		t.Fatalf("unsafe or missing operator readiness: %s", diagnostics)
	}
}
