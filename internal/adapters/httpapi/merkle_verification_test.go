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

type merkleVerificationHTTPFake struct{ bundleVerificationHTTPFake }

func (f *merkleVerificationHTTPFake) VerifyMerkleBatch(ctx context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	r, e := f.VerifyReleaseBundle(ctx, a, id)
	r.SubjectType = "merkle_batch"
	return r, e
}
func TestMerkleVerificationHandlersUseFocusedCommands(t *testing.T) {
	s, secret := testServer(t)
	f := &merkleVerificationHTTPFake{}
	s.merkleVerification = f
	request := httptest.NewRequest(http.MethodGet, "/v1/merkle-batches/not-in-ledger/verify", nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"subject_type":"merkle_batch"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	body := map[string]any{"subject_type": "merkle_batch", "subject_id": "not-in-ledger"}
	first := postJSON(t, s, secret, "/v1/verify", "merkle-focused", body, 200)
	if replay := postJSON(t, s, secret, "/v1/verify", "merkle-focused", body, 200); replay != first || f.calls != 2 {
		t.Fatal("replayed verification")
	}
	before := f.calls
	for i, bad := range []string{`null`, `[]`, `{"subject_type":"merkle_batch","subject_id":null}`, `{"subject_type":"merkle_batch","subject_id":" "}`, `{"subject_type":"merkle_batch","subject_id":1}`, `{"subject_type":"merkle_batch","subject_id":"a","subject_id":"b"}`, `{"subject_type":"merkle_batch","subject_id":"a","extra":1}`, `{"subject_type":"merkle_batch","subject_id":"a"} {}`} {
		postRaw(t, s, secret, "/v1/verify", "bad-merkle-"+string(rune('a'+i)), []byte(bad), 400)
	}
	if f.calls != before {
		t.Fatal("invalid request reached command")
	}
	f.err = verificationapp.ErrVerificationFailed
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"result":"failed"`) {
		t.Fatal("dedicated failure contract", response.Code, response.Body.String())
	}
	postJSON(t, s, secret, "/v1/verify", "merkle-failed", body, 422)
	f.err = errors.New("private SQL and signing material")
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != 500 || strings.Contains(response.Body.String(), "private SQL") || strings.Contains(response.Body.String(), `"data"`) {
		t.Fatal("unsafe error", response.Body.String())
	}
}
