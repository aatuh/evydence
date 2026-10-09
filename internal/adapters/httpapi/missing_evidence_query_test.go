package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type missingEvidenceHTTPFake struct {
	calls int
	err   error
}

func (f *missingEvidenceHTTPFake) Report(_ context.Context, _ identitydomain.Actor, releaseID string) (map[string]any, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return map[string]any{"report_type": "missing_evidence", "release_id": releaseID, "missing": []string{"sbom"}}, nil
}

func TestMissingEvidenceHandlerUsesFocusedQueryAndRejectsBadFilters(t *testing.T) {
	server, secret := testServer(t)
	query := &missingEvidenceHTTPFake{}
	server.missingEvidenceQuery = query
	path := "/v1/reports/missing-evidence?release_id=rel_1"
	response := getRaw(t, server, secret, path, http.StatusOK)
	if !strings.Contains(response.Body.String(), `"release_id":"rel_1"`) || query.calls != 1 {
		t.Fatalf("report=%s calls=%d", response.Body.String(), query.calls)
	}
	for _, bad := range []string{"/v1/reports/missing-evidence", path + "&release_id=rel_2", path + "&unknown=1", "/v1/reports/missing-evidence?release_id=%20"} {
		getRaw(t, server, secret, bad, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, path, http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("invalid request reached query %d times", query.calls)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{riskquery.ErrNotFound, http.StatusNotFound}, {riskquery.ErrInvalidProjection, http.StatusConflict}, {packagequery.ErrInvalidProjection, http.StatusConflict}, {application.ErrForbidden, http.StatusForbidden}, {errors.New("private-readiness-db-detail"), http.StatusInternalServerError}} {
		query.err = tc.err
		response = getRaw(t, server, secret, path, tc.status)
		if strings.Contains(response.Body.String(), "private-readiness-db-detail") {
			t.Fatalf("internal detail leaked: %s", response.Body.String())
		}
	}
}
