package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type securitySummaryHTTPFake struct {
	calls int
	err   error
}

func (f *securitySummaryHTTPFake) Summary(_ context.Context, _ identitydomain.Actor, releaseID string) (riskdomain.ReleaseSecuritySummary, error) {
	f.calls++
	if f.err != nil {
		return riskdomain.ReleaseSecuritySummary{}, f.err
	}
	return riskdomain.ReleaseSecuritySummary{
		Product:         riskdomain.ReleaseSecurityProductSummary{ID: "prod_focus", Name: "Focused", Slug: "focused"},
		Release:         riskdomain.ReleaseSecurityReleaseSummary{ID: releaseID, Version: "1", State: "draft"},
		ReadinessStatus: "failed", SchemaVersion: riskdomain.ReleaseSecuritySummaryVersion,
	}, nil
}

func TestReleaseSecuritySummaryHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &securitySummaryHTTPFake{}
	server.releaseSecuritySummaryQuery = query
	path := "/v1/releases/rel_focus/security-summary"
	response := getRaw(t, server, secret, path, http.StatusOK)
	if !strings.Contains(response.Body.String(), `"id":"rel_focus"`) || !strings.Contains(response.Body.String(), `"schema_version":"release-security-summary.v1.0.0"`) || query.calls != 1 {
		t.Fatalf("summary=%s calls=%d", response.Body.String(), query.calls)
	}
	getRawNoAuth(t, server, path, http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated request reached query %d times", query.calls)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{riskquery.ErrValidation, http.StatusBadRequest}, {riskquery.ErrNotFound, http.StatusNotFound}, {riskquery.ErrInvalidProjection, http.StatusConflict}, {application.ErrForbidden, http.StatusForbidden}, {errors.New("private-summary-db-detail"), http.StatusInternalServerError}} {
		query.err = tc.err
		response = getRaw(t, server, secret, path, tc.status)
		if strings.Contains(response.Body.String(), "private-summary-db-detail") {
			t.Fatalf("internal detail leaked: %s", response.Body.String())
		}
	}
}
