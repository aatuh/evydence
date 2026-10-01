package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type customerPackageAccessHTTPFake struct {
	calls int
	err   error
}

func (f *customerPackageAccessHTTPFake) AccessCustomerSecurityPackage(_ context.Context, _ identitydomain.Actor, id string) (packagedomain.CustomerSecurityPackage, error) {
	f.calls++
	return packagedomain.CustomerSecurityPackage{ID: id, ProductID: "prod_1", ReleaseID: "rel_1", AccessCount: 1, Manifest: map[string]any{"evidence_ids": []string{"ev_1"}}}, f.err
}
func (f *customerPackageAccessHTTPFake) SecurityReviewPackageReport(_ context.Context, _ identitydomain.Actor, id string) (packagedomain.SecurityReviewPackageReport, error) {
	f.calls++
	return packagedomain.SecurityReviewPackageReport{ReportType: "security_review_package", PackageID: id, ProductID: "prod_1", ReleaseID: "rel_1", EvidenceIDs: []string{"ev_1"}}, f.err
}

func TestCustomerPackageHandlersUseFocusedAuditedAccess(t *testing.T) {
	server, secret := testServer(t)
	commands := &customerPackageAccessHTTPFake{}
	server.customerPackageAccessCommands = commands
	for _, path := range []string{"/v1/customer-packages/csp_1", "/v1/reports/security-review-package?package_id=csp_1"} {
		response := getRaw(t, server, secret, path, http.StatusOK)
		if !strings.Contains(response.Body.String(), `"ev_1"`) {
			t.Fatalf("response=%s", response.Body.String())
		}
	}
	path := "/v1/reports/security-review-package?package_id=csp_1"
	for _, bad := range []string{"/v1/reports/security-review-package", path + "&package_id=csp_2", path + "&unknown=1", "/v1/reports/security-review-package?package_id=%20"} {
		getRaw(t, server, secret, bad, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, path, http.StatusUnauthorized)
	if commands.calls != 2 {
		t.Fatal("invalid request reached access command")
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{packageapp.ErrNotFound, http.StatusNotFound}, {packageapp.ErrConflict, http.StatusConflict}, {packageapp.ErrValidation, http.StatusBadRequest}, {application.ErrForbidden, http.StatusForbidden}, {errors.New("private-package-db-detail"), http.StatusInternalServerError},
	} {
		commands.err = tc.err
		response := getRaw(t, server, secret, path, tc.status)
		if strings.Contains(response.Body.String(), "private-package-db-detail") {
			t.Fatal("internal detail leaked")
		}
	}
}
