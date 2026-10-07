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
	calls, guards, replayGuards int
	err, guardErr, replayErr    error
	replayed                    []string
}

func (f *exportBundleHTTPFake) AuthorizeEvidenceBundleExport(context.Context, identitydomain.Actor, string, []string) error {
	f.guards++
	return f.guardErr
}
func (f *exportBundleHTTPFake) AuthorizeEvidenceBundleReplay(_ context.Context, _ identitydomain.Actor, _ string, ids []string) error {
	f.replayGuards++
	f.replayed = append([]string(nil), ids...)
	return f.replayErr
}

func (f *exportBundleHTTPFake) ExportEvidenceBundle(_ context.Context, actor identitydomain.Actor, releaseID string, ids []string) (packagedomain.EvidenceBundle, error) {
	f.calls++
	if len(ids) == 0 {
		ids = []string{"historical-selection"}
	}
	return packagedomain.EvidenceBundle{ID: "eb_focused", TenantID: actor.TenantID, ReleaseID: releaseID, EvidenceIDs: ids, Manifest: map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion}, ManifestHash: "sha256:focused", SignatureRefs: []string{"sig_focused"}, SchemaVersion: packagedomain.EvidenceBundleSchemaVersion}, f.err
}

func TestEvidenceBundleExportRequiresNativeHistoricalReplayAuthority(t *testing.T) {
	base, secret := testServer(t)
	f := &exportBundleHTTPFake{}
	if s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceBundleCommands: f}); err == nil || s != nil {
		t.Error("focused export accepted aggregate replay")
	}
	if s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceBundleCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}}); err == nil || s != nil {
		t.Error("export accepted an executor without saved-selection authorization")
	}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceBundleCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.packages, s.localEvidenceBundles = nil, nil, nil
	s.idempotency = nil
	path, body := "/v1/evidence-bundles", []byte(`{}`)
	one := postRaw(t, s, secret, path, "original", body, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "original", body, 201))
	if f.calls != 1 || f.guards != 2 || f.replayGuards != 1 || strings.Join(f.replayed, ",") != "historical-selection" {
		t.Fatal("replay did not authorize original server-selected IDs", f)
	}
	f.replayErr = application.ErrForbidden
	postRaw(t, s, secret, path, "original", body, 403)
	if f.calls != 1 {
		t.Fatal("denial reselected or signed again")
	}
	f.replayErr = nil
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "original", body, 201))
	before := f.replayGuards
	postRaw(t, s, secret, path, "original", append(body, ' '), 409)
	if f.replayGuards != before {
		t.Fatal("conflicting intent reached saved-selection guard")
	}
}
func TestEvidenceBundleExportUsesFocusedCommandAndReplay(t *testing.T) {
	base, secret := testServer(t)
	commands := &exportBundleHTTPFake{}
	server, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceBundleCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"release_id": "release", "evidence_ids": []string{"ev_1"}}
	response := postJSON(t, server, secret, "/v1/evidence-bundles", "focused-export", input, http.StatusCreated)
	if dataField(t, response, "id") != "eb_focused" || dataField(t, response, "manifest_hash") != "sha256:focused" {
		t.Fatal(response)
	}
	assertTrustHTTPReplay(t, response, postJSON(t, server, secret, "/v1/evidence-bundles", "focused-export", input, http.StatusCreated))
	if commands.calls != 1 {
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
