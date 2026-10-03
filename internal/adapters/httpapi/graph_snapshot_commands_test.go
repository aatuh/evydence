package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestGraphHTTPLocalReplayRechecksCurrentGrant(t *testing.T) {
	base, secret := testServer(t)
	p := postRaw(t, base, secret, "/v1/products", "product", []byte(`{"name":"Product","slug":"product"}`), 201)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID = ""
	a.UserID = "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: dataField(t, p, "id"), Scopes: []string{"evidence:read"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(fmt.Sprintf(`{"product_id":%q}`, dataField(t, p, "id")))
	postRaw(t, s, secret, "/v1/evidence-graph-snapshots", "graph", body, 201)
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/evidence-graph-snapshots", "graph", body, 403)
}

type graphHTTPFake struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *graphHTTPFake) AuthorizeCreateGraphSnapshot(context.Context, identitydomain.Actor, packageapp.CreateGraphSnapshotInput) error {
	f.guards++
	return f.guardErr
}
func (f *graphHTTPFake) CreateGraphSnapshot(_ context.Context, a identitydomain.Actor, in packageapp.CreateGraphSnapshotInput) (packagedomain.EvidenceGraphSnapshot, error) {
	f.calls++
	return packagedomain.EvidenceGraphSnapshot{ID: "graph", TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Nodes: []packagedomain.GraphNode{{ID: "release", Type: "release", Label: "1"}}, Edges: []packagedomain.GraphEdge{}, GraphHash: "sha256:hash", SchemaVersion: packagedomain.EvidenceGraphSnapshotVersion}, f.runErr
}
func TestGraphHTTPFocusedStrictInputAndPrivateErrorMapping(t *testing.T) {
	base, secret := testServer(t)
	f := &graphHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{GraphSnapshotCommands: f}); err == nil {
		t.Fatal("focused graph lacks durable replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{GraphSnapshotCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/evidence-graph-snapshots"
	for i, bad := range []string{`null`, `[]`, `{}`, `{"product_id":null}`, `{"release_id":null}`, `{"product_id":"p","Product_ID":"p"}`, `{"product_id":"p","product_id":"p"}`, `{"unknown":true}`, `{} {}`, `{"product_id":"p\u0000"}`, `{"product_id":"` + string([]byte{255}) + `"}`, `{"release_id":"` + strings.Repeat("x", 1025) + `"}`} {
		postRaw(t, s, secret, path, fmt.Sprint(i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid input reached graph command")
	}
	body := []byte(`{"release_id":"release"}`)
	postRaw(t, s, "", path, "unauth", body, 401)
	out := postRaw(t, s, secret, path, "valid", body, 201)
	if f.guards != 1 || f.calls != 1 || !strings.Contains(out, `"graph_hash"`) || !strings.Contains(out, `"edges":[]`) || strings.Contains(out, `"product_id"`) || strings.Contains(out, `"GraphHash"`) {
		t.Fatal("graph public shape differs", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private graph SQL"), 500}} {
		for _, stage := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if stage == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, path, fmt.Sprintf("%s-%d", stage, i), body, ec.status)
			if strings.Contains(out, "private graph SQL") || strings.Contains(out, `"graph_hash"`) || stage == "guard" && f.calls != before {
				t.Fatal("failure exposed graph or skipped guard", out)
			}
		}
	}
}
func TestGraphHTTPCookieOriginBothProfiles(t *testing.T) {
	base, _ := testServer(t)
	for _, focused := range []bool{false, true} {
		f := &graphHTTPFake{}
		opts := ServerOptions{}
		if focused {
			opts.GraphSnapshotCommands = f
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := NewServerWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/evidence-graph-snapshots", strings.NewReader(`{"product_id":"product"}`))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid"})
		r.Header.Set("Idempotency-Key", "origin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 || f.guards+f.calls != 0 {
			t.Fatal("cookie mutation bypassed same-origin guard", w.Code)
		}
	}
}
