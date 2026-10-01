package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type dsseVerificationHTTPFake struct{ bundleVerificationHTTPFake }

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
	path := "/v1/build-attestations/not-in-ledger/verify-signature"
	first := postJSON(t, server, secret, path, "focused-dsse", map[string]any{}, http.StatusOK)
	if !strings.Contains(first, `"id":"durable_receipt"`) || !strings.Contains(first, `"subject_type":"build_attestation"`) {
		t.Fatal(first)
	}
	if replay := postJSON(t, server, secret, path, "focused-dsse", map[string]any{}, http.StatusOK); replay != first || commands.calls != 1 {
		t.Fatal("dedicated replay reran inspection")
	}
	input := map[string]any{"subject_type": "build_attestation", "subject_id": "not-in-ledger"}
	first = postJSON(t, server, secret, "/v1/verify", "generic-dsse", input, http.StatusOK)
	if replay := postJSON(t, server, secret, "/v1/verify", "generic-dsse", input, http.StatusOK); replay != first || commands.calls != 2 {
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
