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

type exportBundleHTTPFake struct {
	calls int
	err   error
}

func (f *exportBundleHTTPFake) ExportEvidenceBundle(_ context.Context, actor identitydomain.Actor, releaseID string, ids []string) (packagedomain.EvidenceBundle, error) {
	f.calls++
	return packagedomain.EvidenceBundle{ID: "eb_focused", TenantID: actor.TenantID, ReleaseID: releaseID, EvidenceIDs: ids, Manifest: map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion}, ManifestHash: "sha256:focused", SignatureRefs: []string{"sig_focused"}, SchemaVersion: packagedomain.EvidenceBundleSchemaVersion}, f.err
}
func TestEvidenceBundleExportUsesFocusedCommandAndReplay(t *testing.T) {
	server, secret := testServer(t)
	commands := &exportBundleHTTPFake{}
	server.evidenceBundleCommands = commands
	input := map[string]any{"release_id": "release", "evidence_ids": []string{"ev_1"}}
	response := postJSON(t, server, secret, "/v1/evidence-bundles", "focused-export", input, http.StatusCreated)
	if dataField(t, response, "id") != "eb_focused" || dataField(t, response, "manifest_hash") != "sha256:focused" {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, "/v1/evidence-bundles", "focused-export", input, http.StatusCreated); replay != response || commands.calls != 1 {
		t.Fatal("replay reran export")
	}
	for i, bad := range []string{`{"release_id":null}`, `{"evidence_ids":null}`, `null`, `{"evidence_ids":[null]}`, `{"evidence_ids":[""]}`, `{"evidence_ids":[" "]}`, `{"evidence_ids":1}`, `{"release_id":"a","release_id":"b"}`, `{"unknown":true}`, `[]`, `{} {}`} {
		postRaw(t, server, secret, "/v1/evidence-bundles", "bad-export-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.calls != 1 {
		t.Fatal("malformed request reached export")
	}
	postJSON(t, server, secret, "/v1/evidence-bundles", "omitted-export", map[string]any{}, http.StatusCreated)
	for i, tc := range []struct {
		err    error
		status int
	}{{application.ErrForbidden, http.StatusForbidden}, {packageapp.ErrNotFound, http.StatusNotFound}, {packageapp.ErrConflict, http.StatusConflict}, {errors.New("private SQL and signing material"), http.StatusInternalServerError}} {
		commands.err = tc.err
		response := postJSON(t, server, secret, "/v1/evidence-bundles", "error-export-"+string(rune('a'+i)), input, tc.status)
		if strings.Contains(response, "private SQL") || strings.Contains(response, "eb_focused") {
			t.Fatal("failed export leaked internal/output data", response)
		}
	}
}
