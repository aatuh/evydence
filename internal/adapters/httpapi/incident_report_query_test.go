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

type incidentReportHTTPFake struct {
	calls int
	id    string
	err   error
}

func (f *incidentReportHTTPFake) Report(_ context.Context, _ identitydomain.Actor, id string) (packagedomain.IncidentReport, error) {
	f.calls++
	f.id = id
	if f.err != nil {
		return packagedomain.IncidentReport{}, f.err
	}
	return packagedomain.IncidentReport{
		ReportType: "incident_package", TemplateVersion: "incident-package.v1.0.0",
		IncidentID: id, Result: "open",
		Timeline:    []packagedomain.IncidentTimelineEventSnapshot{{ID: "event_focused", IncidentID: id}},
		Tasks:       []packagedomain.RemediationTaskSnapshot{},
		Assumptions: []string{"Incident evidence is limited to records stored in this Evydence tenant."},
		Limitations: []string{"This report organizes incident evidence and does not prove root cause completeness or remediation sufficiency."},
	}, nil
}

func TestIncidentReportHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &incidentReportHTTPFake{}
	server.incidentReportQuery = query
	response := getRaw(t, server, secret, "/v1/reports/incident-package?incident_id=inc_a", http.StatusOK)
	if !strings.Contains(response.Body.String(), "event_focused") || query.calls != 1 || query.id != "inc_a" {
		t.Fatalf("report=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, "/v1/reports/incident-package?incident_id=inc_a", http.StatusUnauthorized)
	for _, path := range []string{
		"/v1/reports/incident-package?incident_id=inc_a&incident_id=inc_b",
		"/v1/reports/incident-package?incident_id=",
		"/v1/reports/incident-package?unknown=1",
		"/v1/reports/incident-package?incident_id=%GG",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	if query.calls != 1 {
		t.Fatalf("invalid request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{packagequery.ErrIncidentReportNotFound, http.StatusNotFound},
		{packagequery.ErrIncidentReportProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-incident-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response = getRaw(t, server, secret, "/v1/reports/incident-package?incident_id=inc_a", test.status)
		if strings.Contains(response.Body.String(), "private-incident-database-detail") {
			t.Fatalf("database detail leaked: %s", response.Body.String())
		}
	}
}
