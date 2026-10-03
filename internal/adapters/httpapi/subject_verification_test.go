package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type subjectVerificationHTTPFake struct {
	calls            int
	err              error
	kind, id, tenant string
}

func (f *subjectVerificationHTTPFake) VerifySubject(_ context.Context, a identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	f.calls++
	f.kind, f.id, f.tenant = kind, id, a.TenantID
	state, _ := verificationdomain.ParseVerificationState(verificationdomain.VerificationStatePassed)
	if errors.Is(f.err, verificationapp.ErrVerificationFailed) {
		state, _ = verificationdomain.ParseVerificationState(verificationdomain.VerificationStateFailed)
	}
	return verificationdomain.VerificationResult{ID: "focused_subject_receipt", TenantID: a.TenantID, SubjectType: kind, SubjectID: id, Result: state, SchemaVersion: verificationdomain.VerificationResultSchemaVersion}, f.err
}

func TestSubjectVerificationHandlerUsesComposedPortWithoutLedgerFallback(t *testing.T) {
	local, secret := testServer(t)
	postJSON(t, local, secret, "/v1/verify", "legacy-unsupported-subject", map[string]any{"subject_type": "unknown", "subject_id": "id"}, http.StatusBadRequest)
	f := &subjectVerificationHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{SubjectVerification: f})
	if err != nil {
		t.Fatal(err)
	}
	// A legacy verifier cannot be reached, even for unknown types or failures.
	s.verification = nil
	for i, kind := range []string{"audit_chain", "evidence_item", "release_bundle", "build_attestation", "artifact_signature", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest"} {
		id := "subject"
		if kind == "audit_chain" {
			id = ""
		}
		input := map[string]any{"subject_type": kind, "subject_id": id}
		key := fmt.Sprintf("composed-subject-%d", i)
		body := postJSON(t, s, secret, "/v1/verify", key, input, http.StatusOK)
		if !strings.Contains(body, `"id":"focused_subject_receipt"`) || f.kind != kind || f.id != id || f.tenant == "" || f.calls != i+1 {
			t.Fatal(body, f)
		}
		if replay := postJSON(t, s, secret, "/v1/verify", key, input, http.StatusOK); replay != body || f.calls != i+1 {
			t.Fatal("replay dispatched again", f)
		}
	}
	before := f.calls
	for i, bad := range []string{`null`, `[]`, `{}`, `{"subject_type":null,"subject_id":"id"}`, `{"subject_type":" ","subject_id":"id"}`, `{"subject_type":"backup_manifest"}`, `{"subject_type":"backup_manifest","subject_id":null}`, `{"subject_type":"backup_manifest","subject_id":1}`, `{"subject_type":"backup_manifest","subject_id":" "}`, `{"subject_type":"audit_chain","subject_id":"id"}`, `{"subject_type":"audit_chain","subject_id":null}`, `{"subject_type":"audit_chain","extra":1}`, `{"subject_type":"audit_chain","subject_type":"backup_manifest"}`, `{"subject_type":"audit_chain"} {}`} {
		postRaw(t, s, secret, "/v1/verify", fmt.Sprintf("invalid-composed-%d", i), []byte(bad), http.StatusBadRequest)
	}
	if f.calls != before {
		t.Fatal("malformed input reached dispatcher", f)
	}
	postJSON(t, s, secret, "/v1/verify", "composed-audit-omitted-id", map[string]any{"subject_type": "audit_chain"}, http.StatusOK)
	for i, tc := range []struct {
		err    error
		kind   string
		status int
	}{
		{verificationapp.ErrValidation, "unknown", http.StatusBadRequest},
		{verificationapp.ErrNotFound, "backup_manifest", http.StatusNotFound},
		{verificationapp.ErrForbidden, "backup_manifest", http.StatusForbidden},
		{verificationapp.ErrConflict, "backup_manifest", http.StatusConflict},
		{verificationapp.ErrVerificationFailed, "backup_manifest", http.StatusUnprocessableEntity},
		{errors.New("private SQL signing material"), "backup_manifest", http.StatusInternalServerError},
	} {
		f.err = tc.err
		before = f.calls
		body := postJSON(t, s, secret, "/v1/verify", fmt.Sprintf("failed-composed-%d", i), map[string]any{"subject_type": tc.kind, "subject_id": "id"}, tc.status)
		if f.calls != before+1 || strings.Contains(body, "private SQL") || strings.Contains(body, "focused_subject_receipt") {
			t.Fatal(body, f)
		}
	}
}
