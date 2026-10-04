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

type dsseVerificationHTTPFake struct {
	bundleVerificationHTTPFake
	guards   int
	guardErr error
}

func (f *dsseVerificationHTTPFake) AuthorizeDSSEVerification(context.Context, identitydomain.Actor, string) error {
	f.guards++
	return f.guardErr
}

func TestDecodeDSSEVerificationRequestBoundsRawIDs(t *testing.T) {
	for _, raw := range []string{"attestation", " attestation ", strings.Repeat("é", 512)} {
		id, err := decodeDSSEVerificationRequest([]byte(`{}`), raw)
		if err != nil || id != strings.TrimSpace(raw) {
			t.Fatal("valid DSSE ID normalization changed", err)
		}
	}
	for _, raw := range []string{"", " ", strings.Repeat(" ", 1024) + "attestation", strings.Repeat("é", 513), "bad\x00id", string([]byte{255})} {
		if _, err := decodeDSSEVerificationRequest([]byte(`{}`), raw); err == nil {
			t.Fatal("invalid raw DSSE ID accepted")
		}
	}
}

func TestDSSEHTTPRequiresNativeReplayAndNoLedgerDependencies(t *testing.T) {
	base, secret := testServer(t)
	f := &dsseVerificationHTTPFake{}
	if _, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{DSSEVerification: f}); err == nil {
		t.Fatal("focused DSSE accepted Ledger replay")
	}
	s, err := NewServerWithOptionsContext(t.Context(), base.ledger, ServerOptions{DSSEVerification: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.verification, s.idempotency = nil, nil, nil
	path := "/v1/build-attestations/not-in-ledger/verify-signature"
	one := postRaw(t, s, secret, path, "native", []byte(`{}`), 200)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "native", []byte(`{}`), 200))
	postRaw(t, s, secret, path, "native", []byte(`{} `), 409)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("replay reran DSSE inspection or skipped current guard", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrNotFound, 404}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private-dsse SQL password=secret"), 500}} {
		f.guardErr = tc.err
		before := f.calls
		out := postRaw(t, s, secret, path, fmt.Sprintf("guard-%d", i), []byte(`{}`), tc.status)
		if f.calls != before || strings.Contains(out, "private-dsse") || strings.Contains(out, `"data"`) {
			t.Fatal("DSSE guard failed open or leaked", out)
		}
	}
}

func TestDSSEHTTPStrictEmptyInputBeforeGuardInBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &dsseVerificationHTTPFake{}
		if native {
			s.dsseVerification = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, body := range []string{"", `null`, `[]`, `true`, `{"unknown":true}`, `{"Unknown":true}`, `{"unknown":1,"unknown":2}`, `{} {}`, `{"invalid":"` + string([]byte{255}) + `"}`, strings.Repeat(" ", 65537)} {
			postRaw(t, s, secret, "/v1/build-attestations/not-in-ledger/verify-signature", fmt.Sprintf("invalid-%d", i), []byte(body), 400)
		}
		if f.calls+f.guards != 0 {
			t.Fatal("invalid DSSE request reached subject resolver", f)
		}
	}
}

func TestDSSEHTTPCookieMutationAndBearerPrecedenceInBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &dsseVerificationHTTPFake{}
		if native {
			s.dsseVerification = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 404}, {"https://attacker.example", true, 404}} {
			want := tc.status
			if native && want == 404 {
				want = 200
			}
			r := httptest.NewRequest("POST", "https://api.example/v1/build-attestations/not-in-ledger/verify-signature", strings.NewReader(`{}`))
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
				t.Fatal("unsafe cookie DSSE mutation", native, w.Code, w.Body.String())
			}
		}
	}
}

func (f *dsseVerificationHTTPFake) VerifyDSSEAttestationSignature(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	result, err := f.VerifyReleaseBundle(ctx, actor, id)
	result.SubjectType = "build_attestation"
	result.Checks[0].Name = "dsse_pae_signature"
	return result, err
}

func TestDSSEVerificationHandlersUseFocusedCommandsAndReplay(t *testing.T) {
	server, secret := testServer(t)
	commands := &dsseVerificationHTTPFake{}
	server.dsseVerification = commands
	bindSubjectHTTPTestPort(t, server, secret, "build_attestation", commands.VerifyDSSEAttestationSignature)
	path := "/v1/build-attestations/not-in-ledger/verify-signature"
	first := postJSON(t, server, secret, path, "focused-dsse", map[string]any{}, http.StatusOK)
	if !strings.Contains(first, `"id":"durable_receipt"`) || !strings.Contains(first, `"subject_type":"build_attestation"`) {
		t.Fatal(first)
	}
	assertTrustHTTPReplay(t, first, postJSON(t, server, secret, path, "focused-dsse", map[string]any{}, http.StatusOK))
	if commands.calls != 1 {
		t.Fatal("dedicated replay reran inspection")
	}
	input := map[string]any{"subject_type": "build_attestation", "subject_id": "not-in-ledger"}
	first = postJSON(t, server, secret, "/v1/verify", "generic-dsse", input, http.StatusOK)
	assertTrustHTTPReplay(t, first, postJSON(t, server, secret, "/v1/verify", "generic-dsse", input, http.StatusOK))
	if commands.calls != 2 {
		t.Fatal("generic replay reran inspection")
	}
	commands.err = verificationapp.ErrVerificationFailed
	postJSON(t, server, secret, path, "failed-dsse", map[string]any{}, http.StatusUnprocessableEntity)
	postJSON(t, server, secret, "/v1/verify", "generic-failed-dsse", input, http.StatusUnprocessableEntity)
	before := commands.calls
	for n, bad := range []string{`null`, `[]`, `{"extra":1}`, `{} {}`} {
		postRaw(t, server, secret, path, "bad-dsse-"+string(rune('a'+n)), []byte(bad), http.StatusBadRequest)
	}
	for n, bad := range []string{`{"subject_type":"build_attestation","subject_id":null}`, `{"subject_type":"build_attestation","subject_id":" "}`, `{"subject_type":"build_attestation","subject_id":2}`, `{"subject_type":"build_attestation","subject_id":"a","subject_id":"b"}`, `{"subject_type":"build_attestation","subject_id":"a","extra":1}`} {
		postRaw(t, server, secret, "/v1/verify", "bad-generic-dsse-"+string(rune('a'+n)), []byte(bad), http.StatusBadRequest)
	}
	if commands.calls != before {
		t.Fatal("invalid request reached inspection")
	}
	commands.err = errors.New("private object location and provider error")
	body := postJSON(t, server, secret, path, "backend-dsse", map[string]any{}, http.StatusInternalServerError)
	if strings.Contains(body, "private object") || strings.Contains(body, `"data"`) {
		t.Fatal("unsafe error", body)
	}
}
