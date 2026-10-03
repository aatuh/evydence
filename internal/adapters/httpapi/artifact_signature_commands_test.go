package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type artifactSignatureCommandHTTPFake struct {
	calls int
	err   error
	input verificationapp.CreateArtifactSignatureInput
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
	for _, required := range []string{"recorded", "does not verify cryptographic trust", "same transaction", "1024 bytes"} {
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
	s, err := NewServerWithOptions(local.ledger, ServerOptions{ArtifactSignatureCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"artifact_id": "not-in-ledger", "algorithm": "cosign", "signature": "recorded", "key_id": "public-id", "payload": map[string]any{"bundle": "opaque"}, "payload_media_type": "application/json"}
	body := postJSON(t, s, secret, "/v1/artifact-signatures", "signature-replay", input, 201)
	if !strings.Contains(body, `"id":"focused_signature"`) || f.calls != 1 || f.input.ArtifactID != "not-in-ledger" || f.input.KeyID != "public-id" || string(f.input.RawPayload) != `{"bundle":"opaque"}` {
		t.Fatal(body, f)
	}
	if replay := postJSON(t, s, secret, "/v1/artifact-signatures", "signature-replay", input, 201); replay != body || f.calls != 1 {
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
