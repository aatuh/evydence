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

type cosignVerificationHTTPFake struct {
	calls int
	err   error
}

func (f *cosignVerificationHTTPFake) VerifyCosign(_ context.Context, a identitydomain.Actor, i verificationapp.VerifyCosignInput) (verificationdomain.CosignVerification, error) {
	f.calls++
	return verificationdomain.CosignVerification{ID: "durable_cosign", TenantID: a.TenantID, ArtifactSignatureID: i.ArtifactSignatureID, Result: "passed", VerifierLibraryVersion: "library", TrustRootVersion: "root", VerificationMode: string(i.Mode)}, f.err
}
func TestCosignHandlerUsesFocusedCommandsAndReplay(t *testing.T) {
	s, secret := testServer(t)
	f := &cosignVerificationHTTPFake{}
	s.cosignVerification = f
	path := "/v1/artifact-signatures/not-in-ledger/verify-cosign"
	input := map[string]any{"mode": "key", "offline": true}
	first := postJSON(t, s, secret, path, "focused-cosign", input, http.StatusOK)
	if !strings.Contains(first, `"id":"durable_cosign"`) || !strings.Contains(first, `"verifier_library_version":"library"`) {
		t.Fatal(first)
	}
	if replay := postJSON(t, s, secret, path, "focused-cosign", input, http.StatusOK); replay != first || f.calls != 1 {
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
