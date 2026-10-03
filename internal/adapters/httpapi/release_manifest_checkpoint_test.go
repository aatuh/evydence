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

type releaseManifestCheckpointHTTPFake struct{ bundleVerificationHTTPFake }

func (f *releaseManifestCheckpointHTTPFake) VerifyReleaseManifestCheckpoint(ctx context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	r, err := f.VerifyReleaseBundle(ctx, a, id)
	r.SubjectType = "audit_chain_release_manifest"
	return r, err
}
func TestReleaseManifestCheckpointHandlerUsesFocusedCommand(t *testing.T) {
	s, secret := testServer(t)
	f := &releaseManifestCheckpointHTTPFake{}
	s.releaseManifestCheckpoint = f
	body := map[string]any{"subject_type": "audit_chain_release_manifest", "subject_id": "bundle"}
	first := postJSON(t, s, secret, "/v1/verify", "manifest-checkpoint-replay", body, 200)
	if replay := postJSON(t, s, secret, "/v1/verify", "manifest-checkpoint-replay", body, 200); replay != first || f.calls != 1 || !strings.Contains(first, `"subject_type":"audit_chain_release_manifest"`) {
		t.Fatal(first, replay, f.calls)
	}
	for i, bad := range []string{`null`, `[]`, `{"subject_type":"audit_chain_release_manifest"}`, `{"subject_type":"audit_chain_release_manifest","subject_id":null}`, `{"subject_type":"audit_chain_release_manifest","subject_id":1}`, `{"subject_type":"audit_chain_release_manifest","subject_id":" "}`, `{"subject_type":"audit_chain_release_manifest","subject_id":"bundle","extra":1}`, `{"subject_type":"audit_chain_release_manifest","subject_type":"release_bundle","subject_id":"bundle"}`, `{"subject_type":"audit_chain_release_manifest","subject_id":"bundle"} {}`} {
		postRaw(t, s, secret, "/v1/verify", "bad-manifest-checkpoint-"+string(rune('a'+i)), []byte(bad), 400)
	}
	if f.calls != 1 {
		t.Fatal("malformed input reached verifier")
	}
	f.err = verificationapp.ErrVerificationFailed
	postJSON(t, s, secret, "/v1/verify", "manifest-checkpoint-failed", body, 422)
	f.err = errors.New("private SQL manifest checkpoint payload")
	if response := postJSON(t, s, secret, "/v1/verify", "manifest-checkpoint-backend", body, 500); strings.Contains(response, "private SQL") || strings.Contains(response, `"data"`) {
		t.Fatal(response)
	}
}
