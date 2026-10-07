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
	calls    int
	guards   int
	guardErr error
	err      error
}

func (f *bundleImportHTTPFake) AuthorizeBundleImport(context.Context, identitydomain.Actor, packagedomain.EvidenceBundle) error {
	f.guards++
	return f.guardErr
}

func TestBundleImportRequiresNativeReplayAndCurrentAuthority(t *testing.T) {
	base, secret := testServer(t)
	f := &bundleImportHTTPFake{}
	if s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BundleImportCommand: f}); err == nil || s != nil {
		t.Error("import receipt accepted aggregate replay")
	}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BundleImportCommand: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.packages = nil, nil
	body := `{"manifest":{"bundle_version":"evidence-bundle.v1.0.0","evidence_ids":[]},"evidence_ids":[],"manifest_hash":"sha256:` + strings.Repeat("a", 64) + `"}`
	one := postRaw(t, s, secret, "/v1/evidence-bundles/import", "original", []byte(body), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/evidence-bundles/import", "original", []byte(body), 201))
	f.guardErr = application.ErrForbidden
	postRaw(t, s, secret, "/v1/evidence-bundles/import", "original", []byte(body), 403)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("import replay bypassed current target authority", f)
	}
}

func (f *bundleImportHTTPFake) ImportEvidenceBundle(_ context.Context, actor identitydomain.Actor, bundle packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	f.calls++
	return packagedomain.EvidenceBundleImport{ID: "ebi_focused", TenantID: actor.TenantID, BundleHash: bundle.ManifestHash, Result: "accepted", ImportedCount: len(bundle.EvidenceIDs)}, f.err
}

func TestBundleImportHandlerUsesFocusedCommandAndReplaysReceipt(t *testing.T) {
	base, secret := testServer(t)
	commands := &bundleImportHTTPFake{}
	server, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{BundleImportCommand: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/evidence-bundles/import"
	input := map[string]any{"manifest": map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "evidence_ids": []string{"ev_1"}}, "manifest_hash": "sha256:input", "evidence_ids": []string{"ev_1"}}
	response := postJSON(t, server, secret, path, "bundle-import-focused", input, http.StatusCreated)
	if dataField(t, response, "id") != "ebi_focused" || dataField(t, response, "bundle_hash") != "sha256:input" || !strings.Contains(response, `"imported_count":1`) {
		t.Fatal(response)
	}
	assertTrustHTTPReplay(t, response, postJSON(t, server, secret, path, "bundle-import-focused", input, http.StatusCreated))
	if commands.calls != 1 {
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
