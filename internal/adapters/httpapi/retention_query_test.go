package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type retentionQueryHTTPFake struct {
	calls     int
	scopeType string
	scopeID   string
	err       error
}

func (f *retentionQueryHTTPFake) Report(_ context.Context, actor identitydomain.Actor, scopeType, scopeID string) (operationsdomain.RetentionReport, error) {
	f.calls++
	f.scopeType, f.scopeID = scopeType, scopeID
	if f.err != nil {
		return operationsdomain.RetentionReport{}, f.err
	}
	return operationsdomain.RetentionReport{
		ReportType: "retention", ScopeType: scopeType, ScopeID: scopeID,
		LegalHolds:  []operationsdomain.LegalHold{{ID: "hold_focused", TenantID: actor.TenantID, ScopeType: scopeType, ScopeID: scopeID, Reason: "review", Owner: "legal", SchemaVersion: "legal-hold.v1", CreatedAt: time.Now().UTC()}},
		Limitations: []string{"Retention reports describe Evydence records and do not replace external storage lifecycle verification."},
		GeneratedAt: time.Now().UTC(),
	}, nil
}

func TestRetentionReportHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &retentionQueryHTTPFake{}
	server.retentionQuery = query
	response := getRaw(t, server, secret, "/v1/reports/retention?scope_type=release&scope_id=rel_a", http.StatusOK)
	if !strings.Contains(response.Body.String(), "hold_focused") || query.calls != 1 || query.scopeType != "release" || query.scopeID != "rel_a" {
		t.Fatalf("focused report=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, "/v1/reports/retention", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthorized request reached query %d times", query.calls)
	}
	for _, path := range []string{
		"/v1/reports/retention?scope_type=release&scope_type=evidence",
		"/v1/reports/retention?unknown=value",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	if query.calls != 1 {
		t.Fatalf("invalid query reached report %d times", query.calls)
	}
	query.err = application.ErrForbidden
	getRaw(t, server, secret, "/v1/reports/retention", http.StatusForbidden)
	query.err = errors.New("private-retention-database-detail")
	response = getRaw(t, server, secret, "/v1/reports/retention", http.StatusInternalServerError)
	if strings.Contains(response.Body.String(), "private-retention-database-detail") {
		t.Fatalf("database detail leaked: %s", response.Body.String())
	}
}
