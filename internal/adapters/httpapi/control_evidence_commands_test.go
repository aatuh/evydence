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

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlEvidenceCommandFake struct {
	calls    int
	guards   int
	guardErr error
	actor    identitydomain.Actor
	id       string
	input    riskapp.LinkControlEvidenceInput
	err      error
	value    riskdomain.ControlEvidence
}

func (f *controlEvidenceCommandFake) AuthorizeControlEvidenceLink(context.Context, identitydomain.Actor, string, riskapp.LinkControlEvidenceInput) error {
	f.guards++
	return f.guardErr
}

func TestControlEvidenceHTTPRequiresDurableReplay(t *testing.T) {
	s, _ := testServer(t)
	if v, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(s), ServerOptions{ControlEvidenceCommands: &controlEvidenceCommandFake{}}); err == nil || v != nil {
		t.Fatal("focused control linking accepted Ledger replay")
	}
}

func TestControlEvidenceHTTPChecksCurrentGuardBeforeReplay(t *testing.T) {
	s, secret := testServer(t)
	f := &controlEvidenceCommandFake{value: riskdomain.ControlEvidence{ID: "link", ControlID: "control", EvidenceType: "sbom", SubjectType: "product", SubjectID: "product", Confidence: "high", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion}}
	s.controlEvidenceCommands = f
	s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
	path, body := "/v1/controls/control/evidence", []byte(`{"evidence_type":"sbom","subject_type":"product","subject_id":"product","confidence":"high"}`)
	one := postRaw(t, s, secret, path, "link", body, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "link", body, 201))
	for _, tc := range []struct {
		err    error
		status int
	}{{application.ErrForbidden, 403}, {riskapp.ErrNotFound, 404}, {errors.New("private-link password=secret"), 500}} {
		f.guardErr = tc.err
		out := postRaw(t, s, secret, path, "link", body, tc.status)
		if f.calls != 1 || strings.Contains(out, "private-link") || strings.Contains(out, `"data"`) {
			t.Fatal("link replay bypassed current authority", out, f)
		}
	}
	if f.guards != 5 {
		t.Fatal("link replay skipped guard", f.guards)
	}
}

func TestControlEvidencePathBoundsRawBeforeTrim(t *testing.T) {
	if err := validateControlEvidencePathID(strings.Repeat(" ", 1025) + "control"); err == nil {
		t.Fatal("raw control path bypassed budget")
	}
}

func TestControlEvidenceNativeHTTPRunsWithoutLedgerAndRejectsBadBodyBeforeGuard(t *testing.T) {
	base, secret := testServer(t)
	f := &controlEvidenceCommandFake{value: riskdomain.ControlEvidence{ID: "link", ControlID: "control", SubjectType: "product", SubjectID: "product", EvidenceType: "sbom", Confidence: "high", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion}}
	s, err := newLegacyServerFixtureWithOptions(legacyFixtureLedger(base), ServerOptions{ControlEvidenceCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)
	path, body := "/v1/controls/control/evidence", `{"evidence_type":"sbom","subject_type":"product","subject_id":"product","confidence":"high"}`
	one := postRaw(t, s, secret, path, "native", []byte(body), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "native", []byte(body), 201))
	postRaw(t, s, secret, path, "native", []byte(body+" "), 409)
	for i, bad := range []string{"", " ", "{", "[]", "null", body + " {}", string([]byte{0xff}), strings.Replace(body, `"product"`, `null`, 1), strings.Replace(body, `"high"`, `"high","notes":null`, 1), strings.Replace(body, `"high"`, `"high","notes":"x","notes":"y"`, 1), strings.Replace(body, `"high"`, `"high","tenant_id":"other"`, 1), strings.Replace(body, `"high"`, `"high","notes":"bad\u0000"`, 1), strings.Replace(body, `"subject_id":"product"`, `"subject_id":"`+strings.Repeat(" ", 1025)+`product"`, 1), strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1)} {
		out := postRaw(t, s, secret, path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
		if f.calls != 1 || f.guards != 3 || strings.Contains(out, `"data"`) {
			t.Fatal("bad input crossed native link guard", out, f)
		}
	}
}

func TestControlEvidenceCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &controlEvidenceCommandFake{value: riskdomain.ControlEvidence{ID: "link", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion}}
		if native {
			s.controlEvidenceCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
			assertNoAggregateServerDependencies(t, s)
		}
		body := `{"evidence_type":"sbom","subject_type":"product","subject_id":"missing","confidence":"high"}`
		for i, tc := range []struct {
			origin string
			bearer bool
			want   int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 404}, {"https://attacker.example", true, 404}} {
			want := tc.want
			if native && want == 404 {
				want = 201
			}
			r := httptest.NewRequest("POST", "https://api.example/v1/controls/control/evidence", strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.guards + f.calls
			s.Handler().ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Set-Cookie") != "" || want == 403 && f.guards+f.calls != before {
				t.Fatal("unsafe cookie link mutation", native, w.Code, w.Body.String())
			}
		}
	}
}

func (f *controlEvidenceCommandFake) LinkControlEvidence(_ context.Context, actor identitydomain.Actor, id string, in riskapp.LinkControlEvidenceInput) (riskdomain.ControlEvidence, error) {
	f.calls++
	f.actor, f.id, f.input = actor, id, in
	return f.value, f.err
}

func TestControlEvidenceHTTPUsesNarrowCommandAndMapsDTOAndErrors(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	tenant, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	value := riskdomain.ControlEvidence{ID: "link", TenantID: tenant.ID, ControlID: "control", EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom", ProductID: "product", ReleaseID: "release", Confidence: "medium", Notes: "reviewed", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion, CreatedAt: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	commands := &controlEvidenceCommandFake{value: value}
	base, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), ledger, ServerOptions{ControlEvidenceCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/controls/control/evidence"
	body := `{"evidence_type":"sbom","subject_type":"sbom","subject_id":"sbom","product_id":"product","release_id":"release","confidence":"medium","notes":"reviewed"}`
	var envelope struct {
		Data domain.ControlEvidence `json:"data"`
	}
	if err := json.Unmarshal([]byte(postRaw(t, server, secret, path, "link", []byte(body), 201)), &envelope); err != nil || envelope.Data != controlEvidenceFromQuery(value) || commands.calls != 1 || commands.actor.TenantID != tenant.ID || commands.actor.KeyID == "" || commands.id != "control" || commands.input != (riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom", ProductID: "product", ReleaseID: "release", Confidence: "medium", Notes: "reviewed"}) {
		t.Fatal("focused command lost principal, inputs, or DTO", envelope, commands, err)
	}
	for i, bad := range []string{"{", "[]", "null", body + " {}", strings.ReplaceAll(body, `"notes":"reviewed"`, `"notes":null`), strings.ReplaceAll(body, `"product_id":"product"`, `"product_id":null`), strings.ReplaceAll(body, `"release_id":"release"`, `"release_id":null`), strings.ReplaceAll(body, `"notes":"reviewed"`, `"notes":1`), strings.ReplaceAll(body, `"notes":"reviewed"`, `"notes":"a","notes":"b"`), strings.ReplaceAll(body, `"notes":"reviewed"`, `"tenant_id":"foreign"`)} {
		postRaw(t, server, secret, path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
	}
	for i, id := range []string{"bad%00id", "%FF", strings.Repeat("x", 1025)} {
		postRaw(t, server, secret, "/v1/controls/"+id+"/evidence", fmt.Sprintf("bad-id-%d", i), []byte(body), 400)
	}
	postRaw(t, server, "", path, "no-auth", []byte(body), 401)
	if commands.calls != 1 {
		t.Fatal("invalid requests reached focused command", commands.calls)
	}
	for i, test := range []struct {
		err    error
		status int
	}{{riskapp.ErrValidation, 400}, {riskapp.ErrNotFound, 404}, {riskapp.ErrConflict, 409}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {errors.New("private control linking details"), 500}} {
		commands.err = fmt.Errorf("wrapped: %w", test.err)
		response := postRaw(t, server, secret, path, fmt.Sprintf("error-%d", i), []byte(body), test.status)
		if strings.Contains(response, "private control linking details") {
			t.Fatal("private command error leaked", response)
		}
	}
	if commands.calls != 7 {
		t.Fatal("command errors not exercised", commands.calls)
	}
}
