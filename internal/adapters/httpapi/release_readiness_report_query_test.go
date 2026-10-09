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

type readinessReportHTTPFake struct {
	calls int
	err   error
}

func (f *readinessReportHTTPFake) Report(_ context.Context, _ identitydomain.Actor, releaseID string) (packagedomain.ReleaseReadinessReport, error) {
	f.calls++
	return packagedomain.ReleaseReadinessReport{ReportType: "release_readiness", TemplateVersion: packagedomain.ReleaseReadinessTemplateVersion, ReleaseID: releaseID, Result: "failed", Checks: []packagedomain.PolicyCheckSnapshot{{Name: "release_requires_sbom", Result: "failed", Missing: []string{"sbom"}}}, Sections: []packagedomain.ReadinessSection{{ID: "release_evidence", Questions: []packagedomain.ReadinessQuestion{{ID: "sbom", Status: "missing_evidence"}}}}, BlockingFindings: []packagedomain.BlockingFinding{{FindingID: "finding_1", ScanID: "scan_1", ReleaseID: releaseID}}, AcceptedExceptions: []packagedomain.AcceptedExceptionSnapshot{{ID: "exception_1", Reason: "reviewed risk"}}}, f.err
}

func TestReleaseReadinessReportHandlerUsesFocusedQuery(t *testing.T) {
	server, secret := testServer(t)
	query := &readinessReportHTTPFake{}
	server.releaseReadinessReportQuery = query
	path := "/v1/reports/release-readiness?release_id=rel_1"
	response := getRaw(t, server, secret, path, http.StatusOK)
	for _, field := range []string{`"report_type":"release_readiness"`, `"release_id":"rel_1"`, `"finding_id":"finding_1"`, `"reason":"reviewed risk"`, `"missing_evidence"`, `"release_requires_sbom"`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Fatalf("missing %s in %s", field, response.Body.String())
		}
	}
	for _, bad := range []string{"/v1/reports/release-readiness", path + "&release_id=rel_2", path + "&unknown=1", "/v1/reports/release-readiness?release_id=%20"} {
		getRaw(t, server, secret, bad, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, path, http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("invalid request reached query: %d", query.calls)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{packagequery.ErrReleaseReadinessValidation, http.StatusBadRequest}, {packagequery.ErrReleaseReadinessNotFound, http.StatusNotFound}, {packagequery.ErrReleaseReadinessProjection, http.StatusConflict}, {application.ErrForbidden, http.StatusForbidden}, {errors.New("private-readiness-report-db-detail"), http.StatusInternalServerError},
	} {
		query.err = tc.err
		response = getRaw(t, server, secret, path, tc.status)
		if strings.Contains(response.Body.String(), "private-readiness-report-db-detail") {
			t.Fatal("internal detail leaked")
		}
	}
}
