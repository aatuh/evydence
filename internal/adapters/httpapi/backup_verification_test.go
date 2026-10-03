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

type backupVerificationHTTPFake struct{ bundleVerificationHTTPFake }

func (f *backupVerificationHTTPFake) VerifyBackupManifest(ctx context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	r, err := f.VerifyReleaseBundle(ctx, a, id)
	r.SubjectType = "backup_manifest"
	return r, err
}
func TestBackupVerificationHandlersUseFocusedCommands(t *testing.T) {
	s, secret := testServer(t)
	f := &backupVerificationHTTPFake{}
	s.backupVerification = f
	req := httptest.NewRequest(http.MethodGet, "/v1/backup-manifests/backup/verify", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"id":"durable_receipt"`) || !strings.Contains(response.Body.String(), `"subject_type":"backup_manifest"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	body := map[string]any{"subject_type": "backup_manifest", "subject_id": "backup"}
	first := postJSON(t, s, secret, "/v1/verify", "backup-replay", body, 200)
	if replay := postJSON(t, s, secret, "/v1/verify", "backup-replay", body, 200); replay != first || f.calls != 2 {
		t.Fatal("replay repeated backup assessment")
	}
	for i, bad := range []string{`null`, `[]`, `{"subject_type":"backup_manifest"}`, `{"subject_type":"backup_manifest","subject_id":null}`, `{"subject_type":"backup_manifest","subject_id":1}`, `{"subject_type":"backup_manifest","subject_id":" "}`, `{"subject_type":"backup_manifest","subject_id":"backup","extra":1}`, `{"subject_type":"backup_manifest","subject_type":"release_bundle","subject_id":"backup"}`, `{"subject_type":"backup_manifest","subject_id":"backup"} {}`} {
		postRaw(t, s, secret, "/v1/verify", "bad-backup-"+string(rune('a'+i)), []byte(bad), 400)
	}
	if f.calls != 2 {
		t.Fatal("malformed input reached backup verifier")
	}
	f.err = verificationapp.ErrVerificationFailed
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"result":"failed"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	postJSON(t, s, secret, "/v1/verify", "backup-failed", body, 422)
	f.err = errors.New("private SQL backup payload")
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, req)
	if response.Code != 500 || strings.Contains(response.Body.String(), "private SQL") || strings.Contains(response.Body.String(), `"data"`) {
		t.Fatal(response.Code, response.Body.String())
	}
}
