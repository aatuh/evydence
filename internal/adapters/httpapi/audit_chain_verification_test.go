package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type auditVerificationHTTPFake struct{ bundleVerificationHTTPFake }

func (f *auditVerificationHTTPFake) VerifyAuditChain(ctx context.Context, a identitydomain.Actor) (verificationdomain.VerificationResult, error) {
	r, e := f.VerifyReleaseBundle(ctx, a, "")
	r.SubjectType = "audit_chain"
	return r, e
}
func TestAuditChainVerificationHandlersUseFocusedCommands(t *testing.T) {
	s, secret := testServer(t)
	f := &auditVerificationHTTPFake{}
	s.auditChainVerification = f
	bindSubjectHTTPTestPort(t, s, secret, "audit_chain", func(ctx context.Context, a identitydomain.Actor, _ string) (verificationdomain.VerificationResult, error) {
		return f.VerifyAuditChain(ctx, a)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/audit-chain/verify", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"id":"durable_receipt"`) || !strings.Contains(response.Body.String(), `"subject_type":"audit_chain"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	body := map[string]any{"subject_type": "audit_chain"}
	first := postJSON(t, s, secret, "/v1/verify", "focused-audit", body, 200)
	assertTrustHTTPReplay(t, first, postJSON(t, s, secret, "/v1/verify", "focused-audit", body, 200))
	if f.calls != 2 {
		t.Fatal("replay reran verification")
	}
	before := f.calls
	for i, bad := range []string{`null`, `[]`, `{"subject_type":"audit_chain","subject_id":"other"}`, `{"subject_type":"audit_chain","subject_id":null}`, `{"subject_type":"audit_chain","subject_id":1}`, `{"subject_type":"audit_chain","subject_type":"merkle_batch"}`, `{"subject_type":"audit_chain","extra":1}`, `{"subject_type":"audit_chain"} {}`} {
		postRaw(t, s, secret, "/v1/verify", "bad-audit-"+string(rune('a'+i)), []byte(bad), 400)
	}
	if f.calls != before {
		t.Fatal("invalid request reached verifier")
	}
	f.err = verificationapp.ErrVerificationFailed
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"result":"failed"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	postJSON(t, s, secret, "/v1/verify", "failed-audit", body, 422)
	f.err = errors.New("private SQL audit payload")
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 500 || strings.Contains(response.Body.String(), "private SQL") || strings.Contains(response.Body.String(), `"data"`) {
		t.Fatal(response.Body.String())
	}
}
