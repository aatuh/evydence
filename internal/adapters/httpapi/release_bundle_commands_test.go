package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type releaseBundleHTTPFake struct {
	calls, guards int
	err           error
}

func TestReleaseBundleHTTPBothProfilesCookiesAndLocalReplayGrant(t *testing.T) {
	for _, native := range []bool{false, true} {
		base, secret := testServer(t)
		product := postJSON(t, base, secret, "/v1/products", "bundle-product", map[string]any{"name": "Product", "slug": "bundle-product"}, 201)
		p := dataField(t, product, "id")
		release := postJSON(t, base, secret, "/v1/releases", "bundle-release", map[string]any{"product_id": p, "version": "1"}, 201)
		id := dataField(t, release, "id")
		f := &releaseBundleHTTPFake{}
		if native {
			base.releaseBundleCommands = f
			base.durableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
		}
		body := `{"release_id":"` + id + `"}`
		for _, origin := range []string{"", "https://evil.example", "http://api.example"} {
			r := httptest.NewRequest("POST", "https://api.example/v1/release-bundles", strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", origin)
			r.Header.Set("Idempotency-Key", "unsafe-bundle")
			w := httptest.NewRecorder()
			base.Handler().ServeHTTP(w, r)
			if w.Code != 403 || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("unsafe cookie bundle accepted", w.Code, w.Body.String())
			}
		}
		for _, bad := range []string{`{"release_id":null}`, `{"RELEASE_ID":"` + id + `"}`, `{"release_id":"` + strings.Repeat(" ", 1024) + id + `"}`, `{"release_id":"bad\u0000"}`, strings.Repeat(" ", 65537)} {
			postRaw(t, base, secret, "/v1/release-bundles", "malformed", []byte(bad), 400)
		}
		if f.guards+f.calls != 0 {
			t.Fatal("invalid body/cookie reached bundle service")
		}
		for i, bearer := range []bool{false, true} {
			r := httptest.NewRequest("POST", "https://api.example/v1/release-bundles", strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", "https://api.example")
			r.Header.Set("Idempotency-Key", "safe-bundle-"+string(rune('a'+i)))
			if bearer {
				r.Header.Set("Origin", "https://evil.example")
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			base.Handler().ServeHTTP(w, r)
			if w.Code != 201 {
				t.Fatal("safe cookie/bearer bundle denied", w.Code, w.Body.String())
			}
		}
		if !native {
			a, err := base.authn.Authenticate(t.Context(), secret)
			if err != nil {
				t.Fatal(err)
			}
			a.KeyID = ""
			a.UserID = "user"
			a.Scopes = []string{"bundle:write"}
			a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: p, Scopes: a.Scopes}}
			auth := &configuredAuthenticator{actor: a}
			s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
			if err != nil {
				t.Fatal(err)
			}
			in := map[string]any{"release_id": id}
			one := postJSON(t, s, secret, "/v1/release-bundles", "local-grant", in, 201)
			assertTrustHTTPReplay(t, one, postJSON(t, s, secret, "/v1/release-bundles", "local-grant", in, 201))
			auth.actor.ResourceGrants = nil
			postJSON(t, s, secret, "/v1/release-bundles", "local-grant", in, 403)
		}
	}
}

func TestReleaseBundleCreationOpenAPIRequestBounds(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Components struct {
			Schemas map[string]struct {
				Description string
				Properties  map[string]map[string]any
			}
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	schema := v.Components.Schemas["CreateReleaseBundleRequest"]
	if schema.Properties["release_id"]["maxLength"] != float64(1024) {
		t.Fatal("release request bound missing")
	}
	for _, claim := range []string{"before reservation", "64 KiB", "does not"} {
		if !strings.Contains(schema.Description, claim) {
			t.Fatal("bundle replay/limit/nonclaim missing", claim)
		}
	}
}

func (f *releaseBundleHTTPFake) AuthorizeReleaseBundleCreation(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.err
}

func (f *releaseBundleHTTPFake) CreateReleaseBundle(_ context.Context, actor identitydomain.Actor, releaseID string) (packagedomain.ReleaseBundle, error) {
	f.calls++
	state, _ := packagedomain.ParseBundleState("generated")
	return packagedomain.ReleaseBundle{ID: "rb_focused", TenantID: actor.TenantID, ReleaseID: releaseID, State: state, Manifest: map[string]any{"version": "preserved"}, ManifestHash: "sha256:focused", SignatureRefs: []string{"sig_focused"}}, nil
}
func TestReleaseBundleHandlerUsesFocusedCommandAndReplay(t *testing.T) {
	base, secret := testServer(t)
	commands := &releaseBundleHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{ReleaseBundleCommands: commands}); err == nil {
		t.Fatal("native bundle accepted Ledger replay")
	}
	server, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{ReleaseBundleCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	server.ledger, server.idempotency, server.packages = nil, nil, nil
	input := map[string]any{"release_id": "release"}
	response := postJSON(t, server, secret, "/v1/release-bundles", "focused-release-bundle", input, http.StatusCreated)
	if dataField(t, response, "id") != "rb_focused" || dataField(t, response, "state") != "generated" || dataField(t, response, "manifest_hash") != "sha256:focused" {
		t.Fatal(response)
	}
	assertTrustHTTPReplay(t, response, postJSON(t, server, secret, "/v1/release-bundles", "focused-release-bundle", input, http.StatusCreated))
	if commands.calls != 1 || commands.guards != 2 {
		t.Fatalf("bundle replay reran command or skipped guard: calls=%d guards=%d", commands.calls, commands.guards)
	}
	for i, bad := range []string{`{"release_id":null}`, `{"release_id":""}`, `{"release_id":" "}`, `{"release_id":1}`, `{"release_id":"a","release_id":"b"}`, `{"release_id":"a","RELEASE_ID":"b"}`, `{"release_id":"bad\u0000"}`, `{"unknown":true}`, `[]`, `{} {}`, `{"release_id":"` + strings.Repeat(" ", 1024) + `release"}`, strings.Repeat(" ", 65537)} {
		postRaw(t, server, secret, "/v1/release-bundles", "bad-bundle-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.calls != 1 {
		t.Fatal("malformed request reached command")
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{application.ErrForbidden, 403}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {errors.New("private-bundle SQL password=secret"), 500}} {
		commands.err = tc.err
		out := postJSON(t, server, secret, "/v1/release-bundles", "focused-release-bundle", input, tc.status)
		if commands.calls != 1 || strings.Contains(out, "private-bundle") || strings.Contains(out, `"data"`) {
			t.Fatal("replay bypassed current bundle guard", out)
		}
	}
}
