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

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type cosignVerificationHTTPFake struct {
	calls, guards int
	err, guardErr error
	input         verificationapp.VerifyCosignInput
}

func (f *cosignVerificationHTTPFake) AuthorizeCosignVerification(_ context.Context, _ identitydomain.Actor, i verificationapp.VerifyCosignInput) error {
	f.guards++
	f.input = i
	return f.guardErr
}

func TestCosignHTTPRequiresNativeReplayAndNoLedgerDependencies(t *testing.T) {
	base, secret := testServer(t)
	f := &cosignVerificationHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{CosignVerification: f}); err == nil {
		t.Fatal("focused Cosign accepted Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{CosignVerification: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	assertNoAggregateServerDependencies(t, s)
	path, body := "/v1/artifact-signatures/not-in-ledger/verify-cosign", `{"mode":"key","offline":true}`
	one := postRaw(t, s, secret, path, "native", []byte(body), 200)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, path, "native", []byte(body), 200))
	postRaw(t, s, secret, path, "native", []byte(body+" "), 409)
	if f.calls != 1 || f.guards != 3 || f.input.ArtifactSignatureID != "not-in-ledger" || f.input.Mode != verificationapp.CosignVerificationModeKey || !f.input.Offline {
		t.Fatal("replay reran inspection or skipped current guard", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrNotFound, 404}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private-cosign SQL password=secret"), 500}} {
		f.guardErr = tc.err
		before := f.calls
		out := postRaw(t, s, secret, path, fmt.Sprintf("guard-%d", i), []byte(body), tc.status)
		if f.calls != before || strings.Contains(out, "private-cosign") || strings.Contains(out, `"data"`) {
			t.Fatal("guard failed open or leaked", out)
		}
	}
}

func TestCosignHTTPStrictPolicyBeforeGuardForFixtureAndNativeCommands(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &cosignVerificationHTTPFake{}
		if native {
			s.cosignVerification = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, body := range []string{"", `null`, `[]`, `true`, `{}`, `{"mode":"key","offline":false}`, `{"mode":"unknown","offline":true}`, `{"mode":"keyless","offline":true}`, `{"mode":"key","offline":true,"expected_issuer":"issuer"}`, `{"Mode":"key","offline":true}`, `{"mode":"key","offline":true,"extra":1}`, `{"mode":"key","mode":"keyless","offline":true}`, `{"mode":"key","offline":null}`, `{"mode":"key","offline":true} {}`, `{"mode":"keyless","offline":true,"expected_identity":"` + string([]byte{255}) + `","expected_issuer":"issuer"}`, `{"mode":"keyless","offline":true,"expected_identity":"` + strings.Repeat(" ", 4097) + `identity","expected_issuer":"issuer"}`, strings.Repeat(" ", 65537)} {
			postRaw(t, s, secret, "/v1/artifact-signatures/not-in-ledger/verify-cosign", fmt.Sprintf("invalid-%d", i), []byte(body), 400)
		}
		if f.calls+f.guards != 0 {
			t.Fatal("bad policy reached inspection or guard", f)
		}
	}
}

func TestCosignHTTPCookieMutationAndBearerPrecedenceForFixtureAndNativeCommands(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &cosignVerificationHTTPFake{}
		if native {
			s.cosignVerification = f
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
			r := httptest.NewRequest("POST", "https://api.example/v1/artifact-signatures/not-in-ledger/verify-cosign", strings.NewReader(`{"mode":"key","offline":true}`))
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
				t.Fatal("unsafe cookie Cosign mutation", native, w.Code, w.Body.String())
			}
		}
	}
}

func TestCosignLocalCompletedReplayStillNeedsCurrentTenantVerificationGrant(t *testing.T) {
	base, secret := testServer(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"verify:read"}}}
	path, body := "/v1/artifact-signatures/signature/verify-cosign", `{"mode":"key","offline":true}`
	// Seed the local compatibility replay algorithm with a historical receipt;
	// the route must authorize it even though fresh inspection is not invoked.
	if _, _, err := legacyFixtureLedger(base).WithIdempotency(t.Context(), a, "POST", path, "local", []byte(body), func(context.Context, *app.Ledger) (int, any, error) {
		return 200, domain.CosignVerification{ID: "historical-cosign", TenantID: a.TenantID, ArtifactSignatureID: "signature", Result: "passed"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	one := postRaw(t, s, secret, path, "local", []byte(body), 200)
	if !strings.Contains(one, `"id":"historical-cosign"`) {
		t.Fatal("did not replay original local receipt", one)
	}
	for _, grant := range []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "unrelated", Scopes: []string{"verify:read"}}, {ResourceType: "tenant", ResourceID: "other", Scopes: []string{"verify:read"}}} {
		auth.actor.ResourceGrants = []identitydomain.ResourceGrant{grant}
		postRaw(t, s, secret, path, "local", []byte(body), 403)
	}
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, path, "local", []byte(body), 403)
}

func TestCosignOpenAPIDeclaresNativeReplayAndBoundedOfflinePolicy(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/artifact-signatures/{id}/verify-cosign", "post")
	description, _ := op["description"].(string)
	for _, claim := range []string{"offline", "Rekor", "before reservation", "64 KiB", "1024", "4096", "4 MiB", "original", "requires PostgreSQL", "422"} {
		if !strings.Contains(description, claim) {
			t.Fatal("missing verified contract or limit", claim, description)
		}
	}
}

func (f *cosignVerificationHTTPFake) VerifyCosign(_ context.Context, a identitydomain.Actor, i verificationapp.VerifyCosignInput) (verificationdomain.CosignVerification, error) {
	f.calls++
	return verificationdomain.CosignVerification{ID: "durable_cosign", TenantID: a.TenantID, ArtifactSignatureID: i.ArtifactSignatureID, Result: "passed", VerifierLibraryVersion: "library", TrustRootVersion: "root", VerificationMode: string(i.Mode)}, f.err
}
func TestCosignHandlerUsesFocusedCommandsAndReplay(t *testing.T) {
	s, secret := testServer(t)
	f := &cosignVerificationHTTPFake{}
	s.cosignVerification = f
	s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
	path := "/v1/artifact-signatures/not-in-ledger/verify-cosign"
	input := map[string]any{"mode": "key", "offline": true}
	first := postJSON(t, s, secret, path, "focused-cosign", input, http.StatusOK)
	if !strings.Contains(first, `"id":"durable_cosign"`) || !strings.Contains(first, `"verifier_library_version":"library"`) {
		t.Fatal(first)
	}
	assertTrustHTTPReplay(t, first, postJSON(t, s, secret, path, "focused-cosign", input, http.StatusOK))
	if f.calls != 1 {
		t.Fatal("replayed inspection")
	}
	f.err = verificationapp.ErrFullVerificationUnavailable
	body := postJSON(t, s, secret, path, "unavailable-cosign", input, http.StatusUnprocessableEntity)
	if !strings.Contains(body, "COSIGN_FULL_VERIFICATION_UNAVAILABLE") {
		t.Fatal(body)
	}
	f.err = verificationapp.ErrVerificationFailed
	postJSON(t, s, secret, path, "failed-cosign", input, http.StatusUnprocessableEntity)
	before := f.calls
	for n, bad := range []string{`null`, `[]`, `{"mode":"key","offline":true,"extra":1}`, `{"mode":"key","offline":true} {}`, `{"mode":"key","offline":null}`, `{"mode":"key","mode":"keyless","offline":true}`, `{"mode":2,"offline":true}`} {
		postRaw(t, s, secret, path, "bad-cosign-"+string(rune('a'+n)), []byte(bad), http.StatusBadRequest)
	}
	if before != f.calls {
		t.Fatal("bad input reached verification")
	}
	f.err = errors.New("private signing endpoint and key path")
	body = postJSON(t, s, secret, path, "backend-cosign", input, http.StatusInternalServerError)
	if strings.Contains(body, "private signing") {
		t.Fatal(body)
	}
}
