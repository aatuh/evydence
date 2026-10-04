package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type merkleCheckpointHTTPFake struct{ bundleVerificationHTTPFake }

func (f *merkleCheckpointHTTPFake) VerifyMerkleCheckpoint(ctx context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	r, e := f.VerifyReleaseBundle(ctx, a, id)
	r.SubjectType = "audit_chain_checkpoint"
	return r, e
}
func TestMerkleCheckpointVerificationHandlerUsesFocusedCommand(t *testing.T) {
	s, secret := testServer(t)
	f := &merkleCheckpointHTTPFake{}
	s.merkleCheckpointVerification = f
	bindSubjectHTTPTestPort(t, s, secret, "audit_chain_checkpoint", f.VerifyMerkleCheckpoint)
	body := map[string]any{"subject_type": "audit_chain_checkpoint", "subject_id": "batch"}
	first := postJSON(t, s, secret, "/v1/verify", "checkpoint-replay", body, 200)
	assertTrustHTTPReplay(t, first, postJSON(t, s, secret, "/v1/verify", "checkpoint-replay", body, 200))
	if f.calls != 1 || !strings.Contains(first, `"subject_type":"audit_chain_checkpoint"`) {
		t.Fatal(first, f.calls)
	}
	for i, bad := range []string{`null`, `[]`, `{"subject_type":"audit_chain_checkpoint"}`, `{"subject_type":"audit_chain_checkpoint","subject_id":null}`, `{"subject_type":"audit_chain_checkpoint","subject_id":1}`, `{"subject_type":"audit_chain_checkpoint","subject_id":" "}`, `{"subject_type":"audit_chain_checkpoint","subject_id":"batch","extra":1}`, `{"subject_type":"audit_chain_checkpoint","subject_type":"merkle_batch","subject_id":"batch"}`, `{"subject_type":"audit_chain_checkpoint","subject_id":"batch"} {}`} {
		postRaw(t, s, secret, "/v1/verify", "bad-checkpoint-"+string(rune('a'+i)), []byte(bad), 400)
	}
	if f.calls != 1 {
		t.Fatal("malformed input reached verifier")
	}
	f.err = verificationapp.ErrVerificationFailed
	postJSON(t, s, secret, "/v1/verify", "checkpoint-failed", body, 422)
	f.err = errors.New("private SQL checkpoint payload")
	response := postJSON(t, s, secret, "/v1/verify", "checkpoint-backend", body, 500)
	if strings.Contains(response, "private SQL") || strings.Contains(response, `"data"`) {
		t.Fatal(response)
	}
}
