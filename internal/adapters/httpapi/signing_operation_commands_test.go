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
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signingOperationHTTPCommands struct {
	guards, calls    int
	guardErr, runErr error
}

func (f *signingOperationHTTPCommands) AuthorizeCreateSigningOperation(context.Context, identitydomain.Actor, verificationapp.SigningOperationInput) error {
	f.guards++
	return f.guardErr
}
func (f *signingOperationHTTPCommands) CreateSigningOperation(_ context.Context, a identitydomain.Actor, in verificationapp.SigningOperationInput) (verificationdomain.SigningOperation, error) {
	f.calls++
	return verificationdomain.SigningOperation{ID: "operation", TenantID: a.TenantID, ProviderID: in.ProviderID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash, Result: "passed", Checks: []verificationdomain.VerifyCheck{}, SchemaVersion: verificationdomain.SigningOperationVersion}, f.runErr
}
func TestSigningOperationHTTPFocusedStrictInputsAndPrivateFailures(t *testing.T) {
	base, secret := testServer(t)
	f := &signingOperationHTTPCommands{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{SigningOperationCommands: f}); err == nil {
		t.Fatal("focused signing bypassed durable replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{SigningOperationCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	valid := fmt.Sprintf(`{"provider_id":"provider","subject_type":"release","subject_id":"release","payload_hash":%q}`, hash)
	for i, bad := range []string{`null`, `[]`, `{}`, strings.Replace(valid, `"provider"`, `null`, 1), strings.Replace(valid, `"provider_id"`, `"Provider_id"`, 1), strings.TrimSuffix(valid, "}") + `,"provider_id":"provider"}`, strings.TrimSuffix(valid, "}") + `,"external_signature":"caller-receipt"}`, valid + ` {}`, strings.Replace(valid, `"release"`, `"unsupported"`, 1), strings.Replace(valid, `"provider"`, `"p\u0000"`, 1), strings.Replace(valid, `"provider"`, `"`+string([]byte{255})+`"`, 1), strings.Replace(valid, `"provider"`, `"`+strings.Repeat("p", 1025)+`"`, 1), strings.Replace(valid, hash, "sha256:bad", 1)} {
		postRaw(t, s, secret, "/v1/signing-operations", fmt.Sprint(i), []byte(bad), 400)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("invalid input reached signing ports")
	}
	oversized := postRaw(t, s, secret, "/v1/signing-operations", "body-limit", []byte(strings.TrimSuffix(valid, "}")+`,"padding":"`+strings.Repeat("x", 128<<10)+`"}`), 400)
	if !strings.Contains(oversized, `"field":"/body"`) || !strings.Contains(oversized, `"code":"invalid_size"`) {
		t.Fatal("route body limit was not enforced", oversized)
	}
	if f.guards+f.calls != 0 {
		t.Fatal("over-limit body reached signing ports")
	}
	postRaw(t, s, "", "/v1/signing-operations", "unauth", []byte(valid), 401)
	out := postRaw(t, s, secret, "/v1/signing-operations", "valid", []byte(valid), 201)
	if f.guards != 1 || f.calls != 1 || !strings.Contains(out, `"result":"passed"`) || strings.Contains(out, `"ProviderID"`) || strings.Contains(out, `"provider_request_id"`) {
		t.Fatal("signing response casing or omission changed", out)
	}
	for i, ec := range []struct {
		err    error
		status int
	}{{verificationapp.ErrValidation, 400}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {verificationapp.ErrVerificationFailed, 422}, {app.ErrRetryableSigning, 503}, {errors.New("private signing SQL"), 500}} {
		for _, phase := range []string{"guard", "run"} {
			f.guardErr, f.runErr = nil, nil
			if phase == "guard" {
				f.guardErr = ec.err
			} else {
				f.runErr = ec.err
			}
			before := f.calls
			out := postRaw(t, s, secret, "/v1/signing-operations", fmt.Sprintf("%s-%d", phase, i), []byte(valid), ec.status)
			if strings.Contains(out, "private signing SQL") || strings.Contains(out, `"result":"passed"`) || phase == "guard" && f.calls != before {
				t.Fatal("failed signing leaked receipt or bypassed guard", out)
			}
		}
	}
}

type signingOperationHTTPLocalSigner struct{ calls int }

func (f *signingOperationHTTPLocalSigner) Sign(_ context.Context, r app.SigningRequest) (app.SigningResult, error) {
	f.calls++
	return app.SigningResult{Signature: "signature", Algorithm: "external-aws_kms", ProviderID: r.ProviderID, ProviderType: r.ProviderType, KeyRef: r.KeyRef, CanonicalPayloadHash: r.CanonicalPayloadHash, RequestID: r.RequestID}, nil
}
func localSigningOperationHTTPFixture(t *testing.T) (*Server, string, string, *signingOperationHTTPLocalSigner) {
	t.Helper()
	f := &signingOperationHTTPLocalSigner{}
	l := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", Signer: f})
	tenant, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.CreateSigningProvider(t.Context(), a, app.CreateSigningProviderInput{Name: "Provider", Type: "aws_kms", KeyRef: "key", Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newLegacyServerFixture(l)
	if err != nil {
		t.Fatal(err)
	}
	return s, secret, fmt.Sprintf(`{"provider_id":%q,"subject_type":"tenant","subject_id":%q,"payload_hash":"sha256:%s"}`, p.ID, tenant.ID, strings.Repeat("a", 64)), f
}
func TestSigningOperationHTTPLocalStrictJSONAndCurrentGrantReplay(t *testing.T) {
	base, secret, body, f := localSigningOperationHTTPFixture(t)
	for i, bad := range []string{strings.TrimSuffix(body, "}") + `,"payload_hash":"sha256:bad"}`, strings.TrimSuffix(body, "}") + `,"unknown":true}`, strings.Replace(body, `"provider_id"`, `"Provider_id"`, 1)} {
		postRaw(t, base, secret, "/v1/signing-operations", fmt.Sprint(i), []byte(bad), 400)
	}
	if f.calls != 0 {
		t.Fatal("ambiguous local JSON invoked signer")
	}
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"keys:admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	postRaw(t, s, secret, "/v1/signing-operations", "signing", []byte(body), 201)
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/signing-operations", "signing", []byte(body), 403)
	if f.calls != 1 {
		t.Fatal("cached local replay invoked signer")
	}
}
func TestSigningOperationHTTPCookieOriginAndBearerPrecedence(t *testing.T) {
	base, secret, body, _ := localSigningOperationHTTPFixture(t)
	for _, focused := range []bool{false, true} {
		opts := ServerOptions{}
		if focused {
			opts.SigningOperationCommands = &signingOperationHTTPCommands{}
			opts.DurableCommandExecutor = &decisionHTTPExecutorFake{}
		}
		s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, bearer := range []bool{false, true} {
			r := httptest.NewRequest("POST", "https://api.example.test/v1/signing-operations", strings.NewReader(body))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "invalid"})
			r.Header.Set("Idempotency-Key", fmt.Sprintf("origin-%t-%t", focused, bearer))
			r.Header.Set("Content-Type", "application/json")
			want := 403
			if bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
				want = 201
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("signing cookie origin or bearer precedence differs", focused, bearer, w.Code, w.Body.String())
			}
		}
	}
}
