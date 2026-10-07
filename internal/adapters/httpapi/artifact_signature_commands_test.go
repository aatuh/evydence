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

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type artifactSignatureCommandHTTPFake struct {
	calls    int
	err      error
	input    verificationapp.CreateArtifactSignatureInput
	guards   int
	guardErr error
}

func (f *artifactSignatureCommandHTTPFake) AuthorizeArtifactSignatureCreation(context.Context, identitydomain.Actor, verificationapp.CreateArtifactSignatureInput) error {
	f.guards++
	return f.guardErr
}

func TestArtifactSignatureCreationRequiresDurableExecutor(t *testing.T) {
	s, _ := testServer(t)
	if server, err := newLegacyServerFixtureWithOptions(s.ledger, ServerOptions{ArtifactSignatureCommands: &artifactSignatureCommandHTTPFake{}}); err == nil || server != nil {
		t.Fatal("artifact signature creation accepted Ledger replay")
	}
}

func TestArtifactSignatureCreationOpenAPIDeclaresRecordingAndAtomicStaging(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	op := operationMap(t, asStringAnyMap(t, doc["paths"]), "/v1/artifact-signatures", "post")
	description, _ := op["description"].(string)
	for _, required := range []string{"recorded", "does not verify cryptographic trust", "same transaction", "1024 bytes", "PostgreSQL is required for local evaluation."} {
		if !strings.Contains(description, required) {
			t.Fatal("missing creation contract", description)
		}
	}
}
func (f *artifactSignatureCommandHTTPFake) CreateArtifactSignature(_ context.Context, a identitydomain.Actor, in verificationapp.CreateArtifactSignatureInput) (verificationdomain.ArtifactSignature, error) {
	f.calls++
	f.input = in
	return verificationdomain.ArtifactSignature{ID: "focused_signature", TenantID: a.TenantID, ArtifactID: in.ArtifactID, SubjectDigest: "sha256:artifact", Algorithm: in.Algorithm, Signature: in.Signature, VerificationStatus: "recorded", SchemaVersion: verificationdomain.ArtifactSignatureSchemaVersion}, f.err
}
func TestArtifactSignatureCreationHTTPUsesFocusedCommandAndReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &artifactSignatureCommandHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(local.ledger, ServerOptions{ArtifactSignatureCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.idempotency = nil, nil
	input := map[string]any{"artifact_id": "not-in-ledger", "algorithm": "cosign", "signature": "recorded", "key_id": "public-id", "payload": map[string]any{"bundle": "opaque"}, "payload_media_type": "application/json"}
	body := postJSON(t, s, secret, "/v1/artifact-signatures", "signature-replay", input, 201)
	if !strings.Contains(body, `"id":"focused_signature"`) || f.calls != 1 || f.input.ArtifactID != "not-in-ledger" || f.input.KeyID != "public-id" || string(f.input.RawPayload) != `{"bundle":"opaque"}` {
		t.Fatal(body, f)
	}
	assertTrustHTTPReplay(t, body, postJSON(t, s, secret, "/v1/artifact-signatures", "signature-replay", input, 201))
	if f.calls != 1 || f.guards != 2 {
		t.Fatal("replay reran command", f)
	}
	for i, raw := range []string{`null`, `[]`, `{"unknown":true}`, `{"signature":null}`, `{"payload":null}`, `{"payload":[]}`, `{"payload":3}`, `{"signature":"a","signature":"b"}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/artifact-signatures", fmt.Sprintf("bad-signature-%d", i), []byte(raw), 400)
	}
	if f.calls != 1 {
		t.Fatal("malformed input reached command", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrValidation, 400}, {verificationapp.ErrForbidden, 403}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {errors.New("private SQL or staging error"), 500}} {
		f.err = tc.err
		body := postJSON(t, s, secret, "/v1/artifact-signatures", fmt.Sprintf("failed-signature-%d", i), input, tc.status)
		if strings.Contains(body, "private SQL") || strings.Contains(body, "focused_signature") {
			t.Fatal(body)
		}
	}
}

func TestArtifactSignatureCreationStrictInputBeforeGuardInBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &artifactSignatureCommandHTTPFake{}
		if native {
			s.artifactSignatureCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, body := range []string{"", `null`, `[]`, `{}`, `{"Artifact_id":"artifact","algorithm":"cosign","signature":"value"}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","signature":"other"}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","key_id":null}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","payload":[]}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","payload":null}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","payload":3}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","extra":1}`, `{"artifact_id":"` + strings.Repeat(" ", 1025) + `artifact","algorithm":"cosign","signature":"value"}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","key_id":"` + strings.Repeat(" ", 1025) + `key"}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"value","payload_media_type":"` + strings.Repeat(" ", 4097) + `application/json"}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"\u0000"}`, `{"artifact_id":"artifact","algorithm":"cosign","signature":"` + string([]byte{255}) + `"}`, `{} {}`, strings.Repeat(" ", 65537)} {
			postRaw(t, s, secret, "/v1/artifact-signatures", fmt.Sprintf("bad-create-%d", i), []byte(body), 400)
		}
		if f.calls+f.guards != 0 {
			t.Fatal("invalid signature creation reached guard/stager", f)
		}
	}
}

func TestArtifactSignatureCreationCookieOriginAndBearerPrecedence(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &artifactSignatureCommandHTTPFake{}
		if native {
			s.artifactSignatureCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 404}, {"https://attacker.example", true, 404}} {
			want := tc.status
			if native && want == 404 {
				want = 201
			}
			r := httptest.NewRequest("POST", "https://api.example/v1/artifact-signatures", strings.NewReader(`{"artifact_id":"missing","algorithm":"cosign","signature":"recorded"}`))
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
				t.Fatal("unsafe signature cookie mutation", w.Code, w.Body.String())
			}
		}
	}
}

func TestArtifactSignatureCreationReplayRequiresCurrentGuard(t *testing.T) {
	s, secret := testServer(t)
	f := &artifactSignatureCommandHTTPFake{}
	s.artifactSignatureCommands = f
	s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
	body := []byte(`{"artifact_id":"artifact","algorithm":"cosign","signature":"recorded"}`)
	one := postRaw(t, s, secret, "/v1/artifact-signatures", "current", body, 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/artifact-signatures", "current", body, 201))
	for _, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrForbidden, 403}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {errors.New("private-signature-creation SQL password=secret"), 500}} {
		f.guardErr = tc.err
		out := postRaw(t, s, secret, "/v1/artifact-signatures", "current", body, tc.status)
		if f.calls != 1 || strings.Contains(out, "private-signature-creation") || strings.Contains(out, `"data"`) {
			t.Fatal("signature replay bypassed current scope", out, f)
		}
	}
	if f.guards != 6 {
		t.Fatal("signature replay skipped guard", f.guards)
	}
}
