package httpapi

import (
	"context"
	"net/http"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type releaseBundleHTTPFake struct{ calls int }

func (f *releaseBundleHTTPFake) CreateReleaseBundle(_ context.Context, actor identitydomain.Actor, releaseID string) (packagedomain.ReleaseBundle, error) {
	f.calls++
	state, _ := packagedomain.ParseBundleState("generated")
	return packagedomain.ReleaseBundle{ID: "rb_focused", TenantID: actor.TenantID, ReleaseID: releaseID, State: state, Manifest: map[string]any{"version": "preserved"}, ManifestHash: "sha256:focused", SignatureRefs: []string{"sig_focused"}}, nil
}
func TestReleaseBundleHandlerUsesFocusedCommandAndReplay(t *testing.T) {
	server, secret := testServer(t)
	commands := &releaseBundleHTTPFake{}
	server.releaseBundleCommands = commands
	input := map[string]any{"release_id": "release"}
	response := postJSON(t, server, secret, "/v1/release-bundles", "focused-release-bundle", input, http.StatusCreated)
	if dataField(t, response, "id") != "rb_focused" || dataField(t, response, "state") != "generated" || dataField(t, response, "manifest_hash") != "sha256:focused" {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, "/v1/release-bundles", "focused-release-bundle", input, http.StatusCreated); replay != response || commands.calls != 1 {
		t.Fatal("bundle replay reran command")
	}
	for i, bad := range []string{`{"release_id":null}`, `{"release_id":""}`, `{"release_id":" "}`, `{"release_id":1}`, `{"release_id":"a","release_id":"b"}`, `{"unknown":true}`, `[]`, `{} {}`} {
		postRaw(t, server, secret, "/v1/release-bundles", "bad-bundle-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.calls != 1 {
		t.Fatal("malformed request reached command")
	}
}
