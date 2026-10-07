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
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type subjectVerificationHTTPFake struct {
	calls            int
	err              error
	kind, id, tenant string
	guards           int
	guardErr         error
}

func (f *subjectVerificationHTTPFake) AuthorizeSubjectVerification(_ context.Context, _ identitydomain.Actor, _, _ string) error {
	f.guards++
	return f.guardErr
}

func TestSubjectVerificationRequiresDurableExecutor(t *testing.T) {
	local, _ := testServer(t)
	if s, err := newLegacyServerFixtureWithOptions(local.ledger, ServerOptions{SubjectVerification: &subjectVerificationHTTPFake{}}); err == nil || s != nil {
		t.Fatal("generic verification accepted Ledger-only replay")
	}
}

func (f *subjectVerificationHTTPFake) VerifySubject(_ context.Context, a identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	f.calls++
	f.kind, f.id, f.tenant = kind, id, a.TenantID
	state, _ := verificationdomain.ParseVerificationState(verificationdomain.VerificationStatePassed)
	if errors.Is(f.err, verificationapp.ErrVerificationFailed) {
		state, _ = verificationdomain.ParseVerificationState(verificationdomain.VerificationStateFailed)
	}
	return verificationdomain.VerificationResult{ID: "focused_subject_receipt", TenantID: a.TenantID, SubjectType: kind, SubjectID: id, Result: state, SchemaVersion: verificationdomain.VerificationResultSchemaVersion}, f.err
}

func TestSubjectVerificationHandlerUsesComposedPortWithoutLedgerFallback(t *testing.T) {
	local, secret := testServer(t)
	postJSON(t, local, secret, "/v1/verify", "legacy-unsupported-subject", map[string]any{"subject_type": "unknown", "subject_id": "id"}, http.StatusBadRequest)
	f := &subjectVerificationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(local.ledger, ServerOptions{SubjectVerification: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	// A legacy verifier cannot be reached, even for unknown types or failures.
	s.ledger, s.idempotency = nil, nil
	for i, kind := range []string{"audit_chain", "evidence_item", "release_bundle", "build_attestation", "artifact_signature", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest"} {
		id := "subject"
		if kind == "audit_chain" {
			id = ""
		}
		input := map[string]any{"subject_type": kind, "subject_id": id}
		key := fmt.Sprintf("composed-subject-%d", i)
		body := postJSON(t, s, secret, "/v1/verify", key, input, http.StatusOK)
		if !strings.Contains(body, `"id":"focused_subject_receipt"`) || f.kind != kind || f.id != id || f.tenant == "" || f.calls != i+1 {
			t.Fatal(body, f)
		}
		assertTrustHTTPReplay(t, body, postJSON(t, s, secret, "/v1/verify", key, input, http.StatusOK))
		if f.calls != i+1 || f.guards != 2*(i+1) {
			t.Fatal("replay dispatched again", f)
		}
	}
	before := f.calls
	for i, bad := range []string{`null`, `[]`, `{}`, `{"subject_type":null,"subject_id":"id"}`, `{"subject_type":" ","subject_id":"id"}`, `{"subject_type":"backup_manifest"}`, `{"subject_type":"backup_manifest","subject_id":null}`, `{"subject_type":"backup_manifest","subject_id":1}`, `{"subject_type":"backup_manifest","subject_id":" "}`, `{"subject_type":"audit_chain","subject_id":"id"}`, `{"subject_type":"audit_chain","subject_id":null}`, `{"subject_type":"audit_chain","extra":1}`, `{"subject_type":"audit_chain","subject_type":"backup_manifest"}`, `{"subject_type":"audit_chain"} {}`} {
		postRaw(t, s, secret, "/v1/verify", fmt.Sprintf("invalid-composed-%d", i), []byte(bad), http.StatusBadRequest)
	}
	if f.calls != before {
		t.Fatal("malformed input reached dispatcher", f)
	}
	postJSON(t, s, secret, "/v1/verify", "composed-audit-omitted-id", map[string]any{"subject_type": "audit_chain"}, http.StatusOK)
	for i, tc := range []struct {
		err    error
		kind   string
		status int
	}{
		{verificationapp.ErrValidation, "unknown", http.StatusBadRequest},
		{verificationapp.ErrNotFound, "backup_manifest", http.StatusNotFound},
		{verificationapp.ErrForbidden, "backup_manifest", http.StatusForbidden},
		{verificationapp.ErrConflict, "backup_manifest", http.StatusConflict},
		{verificationapp.ErrVerificationFailed, "backup_manifest", http.StatusUnprocessableEntity},
		{errors.New("private SQL signing material"), "backup_manifest", http.StatusInternalServerError},
	} {
		f.err = tc.err
		before = f.calls
		body := postJSON(t, s, secret, "/v1/verify", fmt.Sprintf("failed-composed-%d", i), map[string]any{"subject_type": tc.kind, "subject_id": "id"}, tc.status)
		wantCalls := before + 1
		if tc.kind == "unknown" {
			wantCalls = before
		}
		if f.calls != wantCalls || strings.Contains(body, "private SQL") || strings.Contains(body, "focused_subject_receipt") {
			t.Fatal(body, f)
		}
	}
}

func TestSubjectVerificationStrictRawInputBeforeGuardForFixtureAndNativeCommands(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &subjectVerificationHTTPFake{}
		if native {
			s.subjectVerification = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, body := range []string{
			"", `null`, `[]`, `true`, `{}`, `{"Subject_type":"audit_chain"}`,
			`{"subject_type":"audit_chain","Subject_id":""}`, `{"subject_type":"audit_chain","extra":1}`,
			`{"subject_type":"audit_chain","subject_type":"audit_chain"}`, `{"subject_type":"audit_chain","subject_id":null}`,
			`{"subject_type":"unknown","subject_id":"id"}`, `{"subject_type":"backup_manifest"}`, `{"subject_type":"audit_chain"} {}`,
			`{"subject_type":"` + strings.Repeat(" ", 65) + `audit_chain"}`, `{"subject_type":"audit_chain","subject_id":"` + strings.Repeat(" ", 1025) + `"}`,
			`{"subject_type":"backup_manifest","subject_id":"` + strings.Repeat(" ", 1025) + `id"}`,
			`{"subject_type":"audit_chain","subject_id":"\u0000"}`, `{"subject_type":"audit_chain","subject_id":"` + string([]byte{255}) + `"}`,
			strings.Repeat(" ", 65537),
		} {
			postRaw(t, s, secret, "/v1/verify", fmt.Sprintf("bad-subject-%d", i), []byte(body), 400)
		}
		if f.calls+f.guards != 0 {
			t.Fatal("invalid input reached generic verification", f)
		}
	}
}

func TestSubjectVerificationCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &subjectVerificationHTTPFake{}
		if native {
			s.subjectVerification = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{
			{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 404}, {"https://attacker.example", true, 404},
		} {
			want := tc.status
			if native && want == 404 {
				want = 200
			}
			r := httptest.NewRequest("POST", "https://api.example/v1/verify", strings.NewReader(`{"subject_type":"backup_manifest","subject_id":"missing"}`))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.calls + f.guards
			s.Handler().ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Set-Cookie") != "" || want == 403 && f.calls+f.guards != before {
				t.Fatal("unsafe generic cookie mutation", native, w.Code, w.Body.String())
			}
		}
	}
}

func TestSubjectVerificationReplayChecksCurrentGuardAndSafeErrors(t *testing.T) {
	s, secret := testServer(t)
	f := &subjectVerificationHTTPFake{}
	s.subjectVerification = f
	s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
	input := []byte(`{"subject_type":"backup_manifest","subject_id":"backup"}`)
	one := postRaw(t, s, secret, "/v1/verify", "guard", input, 200)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/verify", "guard", input, 200))
	for _, tc := range []struct {
		err    error
		status int
	}{
		{verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private-subject SQL password=secret"), 500},
	} {
		f.guardErr = tc.err
		out := postRaw(t, s, secret, "/v1/verify", "guard", input, tc.status)
		if f.calls != 1 || strings.Contains(out, "private-subject") || strings.Contains(out, `"data"`) {
			t.Fatal("replay bypassed current authority", out, f)
		}
	}
	if f.guards != 7 {
		t.Fatal("guard skipped on replay", f.guards)
	}
}

// Transport-only adapter for each dedicated command fake. Real current-scope
// policy is exercised with the composed PostgreSQL services, not this fake.
type subjectHTTPTestPort struct {
	kind string
	run  func(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
}

func (p subjectHTTPTestPort) AuthorizeSubjectVerification(context.Context, identitydomain.Actor, string, string) error {
	return nil
}
func (p subjectHTTPTestPort) VerifySubject(ctx context.Context, a identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	if kind != p.kind {
		return verificationdomain.VerificationResult{}, verificationapp.ErrValidation
	}
	return p.run(ctx, a, id)
}
func bindSubjectHTTPTestPort(t *testing.T, s *Server, secret, kind string, run func(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)) {
	t.Helper()
	s.subjectVerification = subjectHTTPTestPort{kind, run}
	s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
}
