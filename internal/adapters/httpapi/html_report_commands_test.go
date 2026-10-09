package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type htmlReportHTTPFake struct {
	calls int
	err   error
}

func (f *htmlReportHTTPFake) CRAReadinessHTMLPackage(_ context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.HTMLReportPackage, error) {
	f.calls++
	return packagedomain.HTMLReportPackage{ID: "html_1", TenantID: actor.TenantID, ProductID: productID, ReleaseID: releaseID, HTML: "<p>bounded-report</p>"}, f.err
}

func TestCRAHTMLHandlerUsesFocusedCommandsAndValidatesFilters(t *testing.T) {
	server, secret := testServer(t)
	commands := &htmlReportHTTPFake{}
	server.htmlReportCommands = commands
	path := "/v1/reports/cra-readiness-html?product_id=prod_1&release_id=rel_1"
	response := getRaw(t, server, secret, path, http.StatusOK)
	if !strings.Contains(response.Body.String(), "bounded-report") {
		t.Fatal(response.Body.String())
	}
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "tenant_id", "report_type", "product_id", "release_id", "html", "hash", "schema_version", "created_at"} {
		if envelope.Data[field] == nil {
			t.Fatalf("missing public JSON field %s: %s", field, response.Body.String())
		}
	}
	if len(envelope.Data) != 9 {
		t.Fatal("unexpected JSON fields")
	}
	getRaw(t, server, secret, "/v1/reports/cra-readiness-html?product_id=prod_1", http.StatusOK)
	for _, bad := range []string{"/v1/reports/cra-readiness-html", path + "&product_id=prod_2", path + "&release_id=rel_2", path + "&framework_id=fw_1", path + "&unknown=1", "/v1/reports/cra-readiness-html?product_id=%20", path + "&release_id=%zz"} {
		getRaw(t, server, secret, bad, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, path, http.StatusUnauthorized)
	if commands.calls != 2 {
		t.Fatal("invalid request reached persisted report command")
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{packageapp.ErrValidation, http.StatusBadRequest}, {packageapp.ErrNotFound, http.StatusNotFound}, {packageapp.ErrConflict, http.StatusConflict}, {packagequery.ErrControlCoverageCapacity, http.StatusConflict}, {application.ErrForbidden, http.StatusForbidden}, {errors.New("private-html-database-detail"), http.StatusInternalServerError},
	} {
		commands.err = tc.err
		response := getRaw(t, server, secret, path, tc.status)
		if strings.Contains(response.Body.String(), "private-html-database-detail") {
			t.Fatal("private error exposed")
		}
	}
}
