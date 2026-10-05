package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlCreationHTTPFake struct {
	frameworks, controls, guards int
	guardErr                     error
}

func (f *controlCreationHTTPFake) AuthorizeControlFrameworkCreation(context.Context, identitydomain.Actor, riskapp.CreateControlFrameworkInput) error {
	f.guards++
	return f.guardErr
}
func (f *controlCreationHTTPFake) AuthorizeSecurityControlCreation(context.Context, identitydomain.Actor, riskapp.CreateSecurityControlInput) error {
	f.guards++
	return f.guardErr
}
func (f *controlCreationHTTPFake) CreateControlFramework(_ context.Context, a identitydomain.Actor, in riskapp.CreateControlFrameworkInput) (riskdomain.ControlFramework, error) {
	f.frameworks++
	return riskdomain.ControlFramework{ID: "focused-framework", TenantID: a.TenantID, Name: in.Name, Slug: in.Slug, Version: in.Version, SchemaVersion: riskdomain.ControlFrameworkSchemaVersion}, nil
}
func (f *controlCreationHTTPFake) CreateSecurityControl(_ context.Context, a identitydomain.Actor, in riskapp.CreateSecurityControlInput) (riskdomain.SecurityControl, error) {
	f.controls++
	return riskdomain.SecurityControl{ID: "focused-control", TenantID: a.TenantID, FrameworkID: in.FrameworkID, Code: in.Code, Title: in.Title, Objective: in.Objective, SchemaVersion: riskdomain.SecurityControlSchemaVersion}, nil
}

func TestControlCreationRequiresDurableExecutor(t *testing.T) {
	s, _ := testServer(t)
	if v, err := NewServerWithOptions(s.ledger, ServerOptions{ControlCommands: &controlCreationHTTPFake{}}); err == nil || v != nil {
		t.Fatal("manual creation accepted Ledger replay")
	}
}

func TestControlCreationChecksCurrentGuardBeforeReplay(t *testing.T) {
	for _, tc := range []struct{ path, body string }{{"/v1/control-frameworks", `{"name":"F","version":"1"}`}, {"/v1/controls", `{"framework_id":"fw","code":"C","title":"T","objective":"O"}`}} {
		t.Run(tc.path, func(t *testing.T) {
			s, secret := testServer(t)
			f := &controlCreationHTTPFake{}
			s.controlCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
			one := postRaw(t, s, secret, tc.path, "create", []byte(tc.body), 201)
			assertTrustHTTPReplay(t, one, postRaw(t, s, secret, tc.path, "create", []byte(tc.body), 201))
			for _, bad := range []struct {
				err    error
				status int
			}{{riskapp.ErrForbidden, 403}, {riskapp.ErrNotFound, 404}, {errors.New("private-control password=secret"), 500}} {
				f.guardErr = bad.err
				out := postRaw(t, s, secret, tc.path, "create", []byte(tc.body), bad.status)
				if f.frameworks+f.controls != 1 || strings.Contains(out, "private-control") || strings.Contains(out, `"data"`) {
					t.Fatal("manual replay skipped guard", out, f)
				}
			}
			if f.guards != 5 {
				t.Fatal("manual creation skipped guard", f.guards)
			}
		})
	}
}

func TestControlCreationBoundsRawInputsOverHTTP(t *testing.T) {
	for i, tc := range []struct{ path, body string }{{"/v1/control-frameworks", `{"name":"F","version":"1","slug":"` + strings.Repeat(" ", 1025) + `f"}`}, {"/v1/controls", `{"framework_id":"` + strings.Repeat(" ", 1025) + `fw","code":"C","title":"T","objective":"O"}`}} {
		s, secret := testServer(t)
		postRaw(t, s, secret, tc.path, fmt.Sprintf("raw-%d", i), []byte(tc.body), 400)
	}
}

func TestControlCreationNativeHandlersDoNotUseLedger(t *testing.T) {
	base, secret := testServer(t)
	f := &controlCreationHTTPFake{}
	s, err := NewServerWithOptions(base.ledger, ServerOptions{ControlCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.idempotency = nil, nil
	for _, tc := range []struct{ path, body string }{{"/v1/control-frameworks", `{"name":"F","version":"1"}`}, {"/v1/controls", `{"framework_id":"fw","code":"C","title":"T","objective":"O","evidence_requirements":[{"type":"build","required":false}]}`}} {
		one := postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 201)
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, tc.path, "native", []byte(tc.body), 201))
		postRaw(t, s, secret, tc.path, "native", []byte(tc.body+" "), 409)
	}
	if f.frameworks != 1 || f.controls != 1 || f.guards != 6 {
		t.Fatal("native creation fell back to Ledger", f)
	}
}

func TestControlCreationCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		fw := postJSON(t, s, secret, "/v1/control-frameworks", "seed", map[string]string{"name": "Seed", "version": "1"}, 201)
		f := &controlCreationHTTPFake{}
		if native {
			s.controlCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
			s.ledger, s.idempotency = nil, nil
		}
		for _, tc := range []struct{ path, body string }{{"/v1/control-frameworks", `{"name":"Fresh","version":"1"}`}, {"/v1/controls", `{"framework_id":"` + dataField(t, fw, "id") + `","code":"C","title":"T","objective":"O"}`}} {
			for i, bad := range []struct {
				origin string
				bearer bool
				want   int
			}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
				body := strings.Replace(tc.body, `"1"`, fmt.Sprintf(`"%d"`, i+1), 1)
				if strings.Contains(tc.path, "/controls") {
					body = strings.Replace(tc.body, `"C"`, fmt.Sprintf(`"C%d"`, i), 1)
				}
				r := httptest.NewRequest("POST", "https://api.example"+tc.path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
				r.Header.Set("Origin", bad.origin)
				r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
				if bad.bearer {
					r.Header.Set("Authorization", "Bearer "+secret)
				}
				w := httptest.NewRecorder()
				before := f.guards + f.frameworks + f.controls
				s.Handler().ServeHTTP(w, r)
				if w.Code != bad.want || w.Header().Get("Set-Cookie") != "" || bad.want == 403 && f.guards+f.frameworks+f.controls != before {
					t.Fatal("unsafe cookie control mutation", native, tc.path, w.Code, w.Body.String())
				}
			}
		}
	}
}

func TestControlCreationNativeRejectsMalformedBodiesBeforeGuard(t *testing.T) {
	for _, control := range []bool{false, true} {
		s, secret := testServer(t)
		f := &controlCreationHTTPFake{}
		s.controlCommands = f
		s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		s.ledger, s.idempotency = nil, nil
		path := "/v1/control-frameworks"
		if control {
			path = "/v1/controls"
		}
		bad := []string{"", " ", "{", "[]", "null", "{} {}", string([]byte{0xff}), strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1)}
		if control {
			bad = append(bad, `{"framework_id":"fw","code":"C","title":"T","objective":"O","evidence_requirements":[{"type":"sbom"}]}`, `{"framework_id":"fw","code":"C","title":"T","objective":"O","evidence_requirements":[{"type":"sbom","required":null}]}`, `{"framework_id":"fw","code":"C","title":"T","objective":"O","applicability":[null]}`, `{"framework_id":"fw","code":"C","title":"T","objective":"O","objective":"Duplicate"}`)
		} else {
			bad = append(bad, `{"name":"F","version":"1","name":"Duplicate"}`, `{"name":"F","version":"1","tenant_id":"other"}`, `{"name":"F","version":"1","slug":null}`, `{"name":"bad\u0000","version":"1"}`)
		}
		for i, body := range bad {
			out := postRaw(t, s, secret, path, fmt.Sprintf("bad-%d", i), []byte(body), 400)
			if f.guards+f.frameworks+f.controls != 0 || strings.Contains(out, `"data"`) {
				t.Fatal("bad manual creation crossed guard", out, f)
			}
		}
	}
}
