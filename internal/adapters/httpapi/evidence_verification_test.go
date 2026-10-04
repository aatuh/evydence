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

type evidenceVerificationHTTPFake struct{ bundleVerificationHTTPFake }

func (f *evidenceVerificationHTTPFake) VerifyEvidence(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	result, err := f.VerifyReleaseBundle(ctx, actor, id)
	result.SubjectType = "evidence_item"
	result.Checks[0].Name = "canonical_hash"
	return result, err
}
func TestEvidenceVerificationHandlerUsesFocusedDurableCommands(t *testing.T) {
	server, secret := testServer(t)
	commands := &evidenceVerificationHTTPFake{}
	server.evidenceVerification = commands
	bindSubjectHTTPTestPort(t, server, secret, "evidence_item", commands.VerifyEvidence)
	input := map[string]any{"subject_type": "evidence_item", "subject_id": "not-in-ledger"}
	body := postJSON(t, server, secret, "/v1/verify", "focused-evidence", input, http.StatusOK)
	if !strings.Contains(body, `"id":"durable_receipt"`) || !strings.Contains(body, `"subject_type":"evidence_item"`) {
		t.Fatal(body)
	}
	assertTrustHTTPReplay(t, body, postJSON(t, server, secret, "/v1/verify", "focused-evidence", input, http.StatusOK))
	if commands.calls != 1 {
		t.Fatal("replay reran verification")
	}
	commands.err = verificationapp.ErrVerificationFailed
	postJSON(t, server, secret, "/v1/verify", "failed-evidence", input, http.StatusUnprocessableEntity)
	before := commands.calls
	for i, bad := range []string{`null`, `[]`, `{}`, `{"subject_type":"evidence_item"}`, `{"subject_type":"evidence_item","subject_id":null}`, `{"subject_type":"evidence_item","subject_id":" "}`, `{"subject_type":"evidence_item","subject_id":2}`, `{"subject_type":"evidence_item","subject_id":"a","subject_id":"b"}`, `{"subject_type":"evidence_item","subject_id":"a","extra":1}`, `{} {}`} {
		postRaw(t, server, secret, "/v1/verify", "bad-evidence-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.calls != before {
		t.Fatal("invalid request reached verification")
	}
	commands.err = errors.New("private evidence payload location and SQL")
	body = postJSON(t, server, secret, "/v1/verify", "backend-evidence", input, http.StatusInternalServerError)
	if strings.Contains(body, "private evidence") || strings.Contains(body, `"data"`) {
		t.Fatal("unsafe error", body)
	}
}
