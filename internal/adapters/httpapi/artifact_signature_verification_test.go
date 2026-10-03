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

type signatureMetadataHTTPFake struct{ bundleVerificationHTTPFake }

func (f *signatureMetadataHTTPFake) VerifyArtifactSignature(ctx context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	r, e := f.VerifyReleaseBundle(ctx, a, id)
	r.SubjectType = "artifact_signature"
	r.Result, _ = verificationdomain.ParseVerificationState("limited")
	return r, e
}
func TestArtifactSignatureVerificationHandlerUsesDurableMetadataAndReplay(t *testing.T) {
	s, secret := testServer(t)
	f := &signatureMetadataHTTPFake{}
	s.artifactSignatureVerification = f
	body := map[string]any{"subject_type": "artifact_signature", "subject_id": "not-in-ledger"}
	first := postJSON(t, s, secret, "/v1/verify", "focused-signature-metadata", body, http.StatusOK)
	if !strings.Contains(first, `"subject_type":"artifact_signature"`) || !strings.Contains(first, `"result":"limited"`) {
		t.Fatal(first)
	}
	if replay := postJSON(t, s, secret, "/v1/verify", "focused-signature-metadata", body, http.StatusOK); replay != first || f.calls != 1 {
		t.Fatal("replayed metadata assessment")
	}
	before := f.calls
	for n, bad := range []string{`null`, `[]`, `{"subject_type":"artifact_signature","subject_id":null}`, `{"subject_type":"artifact_signature","subject_id":" "}`, `{"subject_type":"artifact_signature","subject_id":1}`, `{"subject_type":"artifact_signature","subject_id":"a","subject_id":"b"}`, `{"subject_type":"artifact_signature","subject_id":"a","extra":1}`, `{"subject_type":"artifact_signature","subject_id":"a"} {}`} {
		postRaw(t, s, secret, "/v1/verify", "bad-signature-metadata-"+string(rune('a'+n)), []byte(bad), http.StatusBadRequest)
	}
	if f.calls != before {
		t.Fatal("invalid request reached metadata assessment")
	}
	f.err = verificationapp.ErrVerificationFailed
	postJSON(t, s, secret, "/v1/verify", "failed-signature-metadata", body, http.StatusUnprocessableEntity)
	f.err = errors.New("private database error and signature payload")
	response := postJSON(t, s, secret, "/v1/verify", "backend-signature-metadata", body, http.StatusInternalServerError)
	if strings.Contains(response, "private database") || strings.Contains(response, `"data"`) {
		t.Fatal("unsafe metadata error", response)
	}
}
