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

type bundleVerificationHTTPFake struct {
	calls int
	err   error
}

func (f *bundleVerificationHTTPFake) VerifyReleaseBundle(_ context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	f.calls++
	state, _ := verificationdomain.ParseVerificationState("passed")
	if errors.Is(f.err, verificationapp.ErrVerificationFailed) {
		state, _ = verificationdomain.ParseVerificationState("failed")
	}
	return verificationdomain.VerificationResult{ID: "durable_receipt", TenantID: actor.TenantID, SubjectType: "release_bundle", SubjectID: id, Result: state, Checks: []verificationdomain.VerifyCheck{{Name: "bundle_signature", Result: state.String()}}, SchemaVersion: verificationdomain.VerificationResultSchemaVersion}, f.err
}
func TestReleaseBundleVerificationHandlersUseFocusedDurableCommands(t *testing.T) {
	server, secret := testServer(t)
	commands := &bundleVerificationHTTPFake{}
	server.releaseBundleVerification = commands
	request := httptest.NewRequest(http.MethodGet, "/v1/release-bundles/bundle/verify", nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"result":"passed"`) || !strings.Contains(response.Body.String(), `"id":"durable_receipt"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	input := map[string]any{"subject_type": "release_bundle", "subject_id": "bundle"}
	body := postJSON(t, server, secret, "/v1/verify", "durable-verify", input, http.StatusOK)
	if replay := postJSON(t, server, secret, "/v1/verify", "durable-verify", input, http.StatusOK); replay != body || commands.calls != 2 {
		t.Fatal("verification replay reran command")
	}
	commands.err = verificationapp.ErrVerificationFailed
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"result":"failed"`) {
		t.Fatal("GET failed-verification contract", response.Code, response.Body.String())
	}
	postJSON(t, server, secret, "/v1/verify", "durable-failed", input, http.StatusUnprocessableEntity)
	commands.err = nil
	before := commands.calls
	for i, bad := range []string{`null`, `{}`, `[]`, `{"subject_type":"release_bundle"}`, `{"subject_type":"release_bundle","subject_id":null}`, `{"subject_type":"release_bundle","subject_id":" "}`, `{"subject_type":"release_bundle","subject_id":2}`, `{"subject_type":"release_bundle","subject_id":"a","subject_id":"b"}`, `{"subject_type":"release_bundle","subject_id":"a","extra":1}`, `{} {}`} {
		postRaw(t, server, secret, "/v1/verify", "bad-verify-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.calls != before {
		t.Fatal("malformed input reached focused command")
	}
	commands.err = errors.New("private verification SQL")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "private verification SQL") || strings.Contains(response.Body.String(), `"data"`) {
		t.Fatal("unsafe verification error", response.Body.String())
	}
}
