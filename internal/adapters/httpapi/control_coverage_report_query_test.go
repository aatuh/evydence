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

type controlReportHTTPFake struct {
	calls  int
	filter packagequery.ControlCoverageFilter
	err    error
}

func (f *controlReportHTTPFake) Coverage(_ context.Context, _ identitydomain.Actor, filter packagequery.ControlCoverageFilter) (packagedomain.ControlCoverageReport, error) {
	f.calls++
	f.filter = filter
	if f.err != nil {
		return packagedomain.ControlCoverageReport{}, f.err
	}
	return packagedomain.ControlCoverageReport{ReportType: "control_coverage", FrameworkID: filter.FrameworkID, ProductID: filter.ProductID, ReleaseID: filter.ReleaseID, Controls: []packagedomain.ControlCoverageItem{{ControlID: "ctrl_focused", Status: "satisfied"}}}, nil
}

func (f *controlReportHTTPFake) CRAReadiness(_ context.Context, _ identitydomain.Actor, productID, releaseID string) (packagedomain.CRAReadinessReport, error) {
	f.calls++
	f.filter = packagequery.ControlCoverageFilter{ProductID: productID, ReleaseID: releaseID}
	if f.err != nil {
		return packagedomain.CRAReadinessReport{}, f.err
	}
	return packagedomain.CRAReadinessReport{ReportType: "cra_readiness", ProductID: productID, ReleaseID: releaseID, Controls: []packagedomain.ControlCoverageItem{{ControlID: "ctrl_cra_focused", Status: "satisfied"}}}, nil
}

func TestControlReportHandlersUseFocusedQueryAndRejectBadFilters(t *testing.T) {
	server, secret := testServer(t)
	query := &controlReportHTTPFake{}
	server.controlCoverageQuery = query
	coverage := "/v1/reports/control-coverage?framework_id=fw_a&product_id=prod_a&release_id=rel_a"
	response := getRaw(t, server, secret, coverage, http.StatusOK)
	if !strings.Contains(response.Body.String(), `"control_id":"ctrl_focused"`) || strings.Contains(response.Body.String(), `"ControlID"`) || query.calls != 1 || query.filter.FrameworkID != "fw_a" || query.filter.ProductID != "prod_a" || query.filter.ReleaseID != "rel_a" {
		t.Fatalf("coverage=%s query=%#v", response.Body.String(), query)
	}
	cra := "/v1/reports/cra-readiness?product_id=prod_a&release_id=rel_a"
	response = getRaw(t, server, secret, cra, http.StatusOK)
	if !strings.Contains(response.Body.String(), "ctrl_cra_focused") || query.calls != 2 {
		t.Fatalf("CRA=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, coverage, http.StatusUnauthorized)
	for _, bad := range []string{
		coverage + "&framework_id=fw_b", coverage + "&unknown=1",
		"/v1/reports/control-coverage?product_id=", "/v1/reports/control-coverage?release_id=%GG",
		cra + "&product_id=prod_b", cra + "&unknown=1", "/v1/reports/cra-readiness?release_id=rel_a",
	} {
		getRaw(t, server, secret, bad, http.StatusBadRequest)
	}
	if query.calls != 2 {
		t.Fatalf("invalid filters reached query %d times", query.calls)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{packagequery.ErrControlCoverageNotFound, http.StatusNotFound},
		{packagequery.ErrControlCoverageProjection, http.StatusConflict},
		{packagequery.ErrControlCoverageCapacity, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-control-database-detail"), http.StatusInternalServerError},
	} {
		query.err = tc.err
		response = getRaw(t, server, secret, coverage, tc.status)
		if strings.Contains(response.Body.String(), "private-control-database-detail") {
			t.Fatalf("database detail leaked: %s", response.Body.String())
		}
	}
}
