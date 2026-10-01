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

type bundleImportHTTPFake struct {
	calls int
	err   error
}

func (f *bundleImportHTTPFake) ImportEvidenceBundle(_ context.Context, actor identitydomain.Actor, bundle packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	f.calls++
	return packagedomain.EvidenceBundleImport{ID: "ebi_focused", TenantID: actor.TenantID, BundleHash: bundle.ManifestHash, Result: "accepted", ImportedCount: len(bundle.EvidenceIDs)}, f.err
}

func TestBundleImportHandlerUsesFocusedCommandAndReplaysReceipt(t *testing.T) {
	server, secret := testServer(t)
	commands := &bundleImportHTTPFake{}
	server.bundleImportCommand = commands
	path := "/v1/evidence-bundles/import"
	input := map[string]any{"manifest": map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "evidence_ids": []string{"ev_1"}}, "manifest_hash": "sha256:input", "evidence_ids": []string{"ev_1"}}
	response := postJSON(t, server, secret, path, "bundle-import-focused", input, http.StatusCreated)
	if dataField(t, response, "id") != "ebi_focused" || dataField(t, response, "bundle_hash") != "sha256:input" || !strings.Contains(response, `"imported_count":1`) {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, path, "bundle-import-focused", input, http.StatusCreated); replay != response || commands.calls != 1 {
		t.Fatal("replay reran import")
	}
	for i, bad := range []string{`{"manifest":[],"manifest_hash":"hash"}`, `{"manifest_hash":"a","manifest_hash":"b"}`, `{"unknown":true}`, `[]`, `{"manifest":{}} {}`} {
		postRaw(t, server, secret, path, "bundle-import-bad-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.calls != 1 {
		t.Fatal("malformed request reached import command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, http.StatusBadRequest}, {packageapp.ErrConflict, http.StatusConflict}, {application.ErrForbidden, http.StatusForbidden}, {errors.New("private-import-db-detail"), http.StatusInternalServerError}} {
		commands.err = tc.err
		response := postJSON(t, server, secret, path, "bundle-import-error-"+string(rune('a'+i)), input, tc.status)
		if strings.Contains(response, "private-import-db-detail") {
			t.Fatal("private error exposed")
		}
	}
}
