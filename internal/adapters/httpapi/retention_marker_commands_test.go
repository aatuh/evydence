package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type markerHTTPFake struct {
	guards, writes int
	err            error
}

func (f *markerHTTPFake) AuthorizeRetentionMarker(context.Context, identitydomain.Actor, string, string) error {
	f.guards++
	return f.err
}
func (f *markerHTTPFake) CreateLegalHold(_ context.Context, a identitydomain.Actor, in operationsapp.RetentionMarkerInput) (operationsdomain.LegalHold, error) {
	f.writes++
	return operationsdomain.LegalHold{ID: "hold_native", TenantID: a.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner}, nil
}
func (f *markerHTTPFake) CreateRetentionOverride(_ context.Context, a identitydomain.Actor, in operationsapp.RetentionOverrideInput) (operationsdomain.RetentionOverride, error) {
	f.writes++
	return operationsdomain.RetentionOverride{ID: "override_native", TenantID: a.TenantID, RetentionUntil: in.RetentionUntil}, nil
}
func markerHTTPBody(tenant string, override bool) map[string]any {
	v := map[string]any{"scope_type": "tenant", "scope_id": tenant, "reason": "review", "owner": "legal"}
	if override {
		v["retention_until"] = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return v
}

func TestRetentionMarkerHTTPNativeReplayAndGuardErrors(t *testing.T) {
	base, secret := testServer(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	f := &markerHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{RetentionMarkerCommands: f}); err == nil {
		t.Fatal("native marker accepted Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{RetentionMarkerCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)
	for _, override := range []bool{false, true} {
		path := "/v1/legal-holds"
		wantID := "hold_native"
		if override {
			path = "/v1/retention-overrides"
			wantID = "override_native"
		}
		in := markerHTTPBody(a.TenantID, override)
		one := postJSON(t, s, secret, path, path, in, 201)
		if dataField(t, one, "id") != wantID {
			t.Fatal("marker fell back")
		}
		assertTrustHTTPReplay(t, one, postJSON(t, s, secret, path, path, in, 201))
	}
	if f.writes != 2 || f.guards != 4 {
		t.Fatal("replay bypassed guard or reran mutation")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{operationsapp.ErrValidation, 400}, {operationsapp.ErrNotFound, 404}, {operationsapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private-marker SQL password=secret"), 500}} {
		f.err = tc.err
		before := f.writes
		out := postJSON(t, s, secret, "/v1/legal-holds", fmt.Sprintf("err-%d", i), markerHTTPBody(a.TenantID, false), tc.status)
		if f.writes != before || strings.Contains(out, "private-marker") || strings.Contains(out, `"data"`) {
			t.Fatal("guard leak", out)
		}
	}
}

func TestRetentionMarkerHTTPStrictBodiesCookiesAndLocalReplayAuthority(t *testing.T) {
	for _, native := range []bool{false, true} {
		base, secret := operationsTestServer(t)
		a, err := base.authn.Authenticate(t.Context(), secret)
		if err != nil {
			t.Fatal(err)
		}
		f := &markerHTTPFake{}
		if native {
			base.retentionMarkerCommands = f
			base.durableCommandExecutor = newTrustHTTPReplayExecutor(t, base, secret)
		}
		for _, override := range []bool{false, true} {
			path := "/v1/legal-holds"
			if override {
				path = "/v1/retention-overrides"
			}
			in := markerHTTPBody(a.TenantID, override)
			raw, _ := json.Marshal(in)
			bad := []string{`null`, `[]`, `{} {}`, `42`, `"text"`, strings.Repeat(" ", 65537), strings.TrimSuffix(string(raw), "}") + `,"OWNER":"shadow"}`, strings.TrimSuffix(string(raw), "}") + `,"owner":"duplicate"}`}
			for _, field := range []string{"scope_type", "scope_id", "reason", "owner"} {
				v := map[string]any{}
				for k, val := range in {
					v[k] = val
				}
				v[field] = nil
				b, _ := json.Marshal(v)
				bad = append(bad, string(b))
			}
			for _, tc := range []struct {
				field string
				value any
			}{{"scope_id", strings.Repeat(" ", 1024) + a.TenantID}, {"scope_type", "unknown"}, {"owner", "bad\x00"}, {"reason", " "}, {"owner", strings.Repeat("x", 65537)}} {
				v := map[string]any{}
				for k, val := range in {
					v[k] = val
				}
				v[tc.field] = tc.value
				b, _ := json.Marshal(v)
				bad = append(bad, string(b))
			}
			if override {
				v := markerHTTPBody(a.TenantID, true)
				v["retention_until"] = nil
				b, _ := json.Marshal(v)
				bad = append(bad, string(b))
				v["retention_until"] = "not-a-date"
				b, _ = json.Marshal(v)
				bad = append(bad, string(b))
			}
			for i, body := range bad {
				postRaw(t, base, secret, path, fmt.Sprintf("bad-%d", i), []byte(body), 400)
			}
			for _, origin := range []string{"", "https://evil.example", "http://api.example"} {
				r := httptest.NewRequest("POST", "https://api.example"+path, strings.NewReader(string(raw)))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", origin)
				r.Header.Set("Idempotency-Key", "unsafe-cookie")
				w := httptest.NewRecorder()
				base.Handler().ServeHTTP(w, r)
				if w.Code != 403 || w.Header().Get("Set-Cookie") != "" {
					t.Fatal("unsafe marker cookie accepted", w.Code)
				}
			}
			if f.writes+f.guards != 0 {
				t.Fatal("invalid marker input reached focused service")
			}
			for i, bearer := range []bool{false, true} {
				r := httptest.NewRequest("POST", "https://api.example"+path, strings.NewReader(string(raw)))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", "https://api.example")
				r.Header.Set("Idempotency-Key", fmt.Sprintf("safe-cookie-%d", i))
				if bearer {
					r.Header.Set("Origin", "https://evil.example")
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				base.Handler().ServeHTTP(w, r)
				if w.Code != 201 {
					t.Fatal("same-origin or explicit bearer marker denied", w.Code, w.Body.String())
				}
			}
			f.guards, f.writes = 0, 0
		}
	}
	base, secret := operationsTestServer(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	in := markerHTTPBody(a.TenantID, false)
	one := postJSON(t, s, secret, "/v1/legal-holds", "local", in, 201)
	assertTrustHTTPReplay(t, one, postJSON(t, s, secret, "/v1/legal-holds", "local", in, 201))
	auth.actor.ResourceGrants = nil
	postJSON(t, s, secret, "/v1/legal-holds", "local", in, 403)
}

func TestRetentionMarkerOpenAPIRequestBoundsDoNotRestrictHistoricalRecords(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties  map[string]map[string]any `json:"properties"`
				Description string                    `json:"description"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CreateLegalHoldRequest", "CreateRetentionOverrideRequest"} {
		v := doc.Components.Schemas[name]
		if v.Properties["scope_id"]["maxLength"] != float64(1024) || len(v.Properties["scope_type"]["enum"].([]any)) != 5 || v.Properties["owner"]["maxLength"] != float64(operationsapp.MaxRetentionMarkerTextBytes) {
			t.Fatal("request bounds missing", name)
		}
		for _, claim := range []string{"before reservation", "64 KiB", "does not"} {
			if !strings.Contains(v.Description, claim) {
				t.Fatal("replay/limits/nonclaim missing", name)
			}
		}
	}
	for _, name := range []string{"LegalHold", "RetentionOverride"} {
		if doc.Components.Schemas[name].Properties["owner"]["maxLength"] != nil {
			t.Fatal("historical record newly restricted")
		}
	}
}
