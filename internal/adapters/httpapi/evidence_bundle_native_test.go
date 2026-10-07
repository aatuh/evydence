package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestEvidenceBundleExportStrictPreflightAndBothProfileCookies(t *testing.T) {
	base, secret := testServer(t)
	f := &exportBundleHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceBundleCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.packages, s.localEvidenceBundles = nil, nil, nil
	bad := []string{"", " ", "{", "null", "[]", `{"Release_ID":"id"}`, `{"evidence_ids":[null]}`, `{"evidence_ids":["id\u0000"]}`, `{"release_id":"x\u0000"}`, `{"release_id":"` + strings.Repeat(" ", 1024) + `x"}`, `{"evidence_ids":["` + strings.Repeat(" ", 1024) + `x"]}`}
	for n, body := range bad {
		postRaw(t, s, secret, "/v1/evidence-bundles", fmt.Sprintf("invalid-%d", n), []byte(body), 400)
		if f.calls+f.guards+f.replayGuards != 0 {
			t.Fatal("invalid selection reached commands", n, f)
		}
	}
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			base, secret := testServer(t)
			server := base
			if native {
				var err error
				server, err = newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{EvidenceBundleCommands: &exportBundleHTTPFake{}, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, tc := range []struct {
				origin string
				bearer bool
				want   int
			}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
				r := httptest.NewRequest("POST", "https://api.example/v1/evidence-bundles", strings.NewReader(`{}`))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Idempotency-Key", "cookie-export")
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				server.Handler().ServeHTTP(w, r)
				if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" {
					t.Fatal("unsafe export cookie mutation", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestEvidenceBundleLocalReplayAuthorizesOriginalSelectionUnderChangedGrants(t *testing.T) {
	base, secret := testServer(t)
	owner, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := base.ledger.CreateProduct(t.Context(), owner, "Original", "original")
	if err != nil {
		t.Fatal(err)
	}
	other, err := base.ledger.CreateProduct(t.Context(), owner, "Other", "other")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := base.ledger.CreateEvidence(t.Context(), owner, app.CreateEvidenceInput{ProductID: product.ID, Type: "document", Title: "Public label", PayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	auth := &configuredAuthenticator{actor: domain.Actor{TenantID: owner.TenantID, UserID: "local-user", Scopes: []string{"bundle:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: product.ID, Scopes: []string{"bundle:read"}}}}}
	s, err := newLegacyServerFixtureWithOptions(base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	one := postRaw(t, s, secret, "/v1/evidence-bundles", "original", []byte(`{}`), 201)
	if !strings.Contains(one, `"evidence_ids":["`+evidence.ID+`"]`) {
		t.Fatal("local export lost scope filtering", one)
	}
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/evidence-bundles", "original", []byte(`{}`), 201))
	auth.actor.ResourceGrants[0].ResourceID = other.ID
	postRaw(t, s, secret, "/v1/evidence-bundles", "original", []byte(`{}`), 403)
	auth.actor.ResourceGrants[0].ResourceID = product.ID
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/evidence-bundles", "original", []byte(`{}`), 201))
}

func TestEvidenceBundleReplaySelectionFailsClosedWithoutReadingManifest(t *testing.T) {
	a := domain.Actor{TenantID: "tenant"}
	in := evidenceBundleExportRequest{}
	good := map[string]any{"tenant_id": "tenant", "evidence_ids": []any{"original"}, "manifest": func() { panic("manifest must not be inspected") }}
	if ids, err := evidenceBundleReplaySelection(a, in, good); err != nil || strings.Join(ids, ",") != "original" {
		t.Fatal("safe selection was not preserved", ids, err)
	}
	for _, bad := range []any{nil, map[string]any{"tenant_id": "other", "evidence_ids": []any{}}, map[string]any{"tenant_id": "tenant", "evidence_ids": nil}, map[string]any{"tenant_id": "tenant", "evidence_ids": []any{1}}, map[string]any{"tenant_id": "tenant", "evidence_ids": []any{"id\x00"}}, map[string]any{"tenant_id": "tenant", "release_id": "other", "evidence_ids": []any{}}} {
		if _, err := evidenceBundleReplaySelection(a, in, bad); err == nil {
			t.Fatal("unsupported saved selection was authorized", bad)
		}
	}
	in.EvidenceIDs = []string{"different"}
	if _, err := evidenceBundleReplaySelection(a, in, good); err == nil {
		t.Fatal("saved explicit selection differed from matching intent")
	}
}
