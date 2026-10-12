package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type securityUpdateHTTPFake struct {
	calls   int
	product string
	release string
	err     error
}

func (f *securityUpdateHTTPFake) Report(_ context.Context, _ identitydomain.Actor, product, release string) (packagedomain.SecurityUpdateEvidenceReport, error) {
	f.calls++
	f.product, f.release = product, release
	if f.err != nil {
		return packagedomain.SecurityUpdateEvidenceReport{}, f.err
	}
	return packagedomain.SecurityUpdateEvidenceReport{
		ReportType: "security_update_evidence", TemplateVersion: "security-update-evidence.v1.0.0",
		ProductID: product, ReleaseID: release, Summary: map[string]int{"incidents_total": 1},
		Incidents:   []packagedomain.IncidentSnapshot{{ID: "inc_focused", ProductID: product, ReleaseID: release, Status: "open"}},
		Assumptions: []string{"Recorded evidence only."}, Limitations: []string{"No legal conclusion."},
	}, nil
}

func TestSecurityUpdateEvidenceHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &securityUpdateHTTPFake{}
	server.securityUpdateEvidenceQuery = query
	path := "/v1/reports/security-update-evidence?product_id=prod_a&release_id=rel_a"
	response := getRaw(t, server, secret, path, http.StatusOK)
	if !strings.Contains(response.Body.String(), "inc_focused") || query.calls != 1 || query.product != "prod_a" || query.release != "rel_a" {
		t.Fatalf("report=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, path, http.StatusUnauthorized)
	for _, bad := range []string{
		path + "&product_id=prod_b", path + "&unknown=1",
		"/v1/reports/security-update-evidence?product_id=&release_id=rel_a",
		"/v1/reports/security-update-evidence?product_id=prod_a&release_id=%GG",
	} {
		getRaw(t, server, secret, bad, http.StatusBadRequest)
	}
	if query.calls != 1 {
		t.Fatalf("invalid request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{packagequery.ErrSecurityUpdateNotFound, http.StatusNotFound},
		{packagequery.ErrSecurityUpdateProjection, http.StatusConflict},
		{packagequery.ErrSecurityUpdateCapacity, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-update-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response = getRaw(t, server, secret, path, test.status)
		if strings.Contains(response.Body.String(), "private-update-database-detail") {
			t.Fatalf("database detail leaked: %s", response.Body.String())
		}
	}
}
