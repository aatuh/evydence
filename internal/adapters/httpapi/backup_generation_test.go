package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type backupGenerationHTTPFake struct {
	calls, guards int
	err, guardErr error
}

func (f *backupGenerationHTTPFake) AuthorizeBackupGeneration(context.Context, identitydomain.Actor) error {
	f.guards++
	return f.guardErr
}

func TestBackupGenerationOpenAPIDeclaresMetadataCommitmentNotRestoreProof(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	paths := asStringAnyMap(t, doc["paths"])
	operation := operationMap(t, paths, "/v1/backup-manifests", "post")
	description, _ := operation["description"].(string)
	for _, required := range []string{"backup-manifest.v2.0.0", verificationapp.BackupStateCommitmentProfile, "not a restore receipt", "before reservation", "64 KiB", "32768", "8 MiB", "original", "requires PostgreSQL"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing scope/version/nonclaim", description)
		}
	}
	if strings.Contains(description, "after an operator backup completes") {
		t.Fatal("unverified operator completion claim", description)
	}
}

func TestBackupGenerationHTTPRequiresNativeReplayAndNoLedgerDependencies(t *testing.T) {
	base, secret := testServer(t)
	f := &backupGenerationHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{BackupGenerationCommands: f}); err == nil {
		t.Fatal("focused backup accepted Ledger replay")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{BackupGenerationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.idempotency = nil, nil
	one := postRaw(t, s, secret, "/v1/backup-manifests", "native", []byte(`{}`), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/backup-manifests", "native", []byte(`{}`), 201))
	postRaw(t, s, secret, "/v1/backup-manifests", "native", []byte(`{} `), 409)
	if f.calls != 1 || f.guards != 3 {
		t.Fatal("replay regenerated backup or skipped guard", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrNotFound, 404}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private-backup SQL password=secret"), 500}} {
		f.guardErr = tc.err
		before := f.calls
		out := postRaw(t, s, secret, "/v1/backup-manifests", fmt.Sprintf("guard-%d", i), []byte(`{}`), tc.status)
		if f.calls != before || strings.Contains(out, "private-backup") || strings.Contains(out, `"data"`) {
			t.Fatal("backup guard failed open or leaked", out)
		}
	}
}

func TestBackupGenerationHTTPStrictEmptyInputBeforeGuardForFixtureAndNativeCommands(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &backupGenerationHTTPFake{}
		if native {
			s.backupGenerationCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, body := range []string{"", `null`, `[]`, `true`, `{"unknown":true}`, `{"Unknown":true}`, `{"unknown":1,"unknown":2}`, `{} {}`, `{"invalid":"` + string([]byte{255}) + `"}`, strings.Repeat(" ", 65537)} {
			postRaw(t, s, secret, "/v1/backup-manifests", fmt.Sprintf("invalid-%d", i), []byte(body), 400)
		}
		if f.calls+f.guards != 0 {
			t.Fatal("invalid body reached backup reader", f)
		}
	}
}

func TestBackupGenerationHTTPCookieAndFixtureReplayAuthority(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, secret := testServer(t)
		f := &backupGenerationHTTPFake{}
		if native {
			s.backupGenerationCommands = f
			s.durableCommandExecutor = newTrustHTTPReplayExecutor(t, s, secret)
		}
		for i, tc := range []struct {
			origin string
			bearer bool
			status int
		}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
			r := httptest.NewRequest("POST", "https://api.example/v1/backup-manifests", strings.NewReader(`{}`))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Idempotency-Key", fmt.Sprintf("cookie-%d", i))
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			before := f.calls + f.guards
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" || tc.status == 403 && f.calls+f.guards != before {
				t.Fatal("unsafe cookie backup mutation", native, w.Code, w.Body.String())
			}
		}
	}
	base, secret := testServer(t)
	a, err := base.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"admin"}}}
	auth := &configuredAuthenticator{actor: a}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	one := postRaw(t, s, secret, "/v1/backup-manifests", "local", []byte(`{}`), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/backup-manifests", "local", []byte(`{}`), 201))
	auth.actor.ResourceGrants = nil
	postRaw(t, s, secret, "/v1/backup-manifests", "local", []byte(`{}`), 403)
}

func (f *backupGenerationHTTPFake) GenerateBackupManifest(_ context.Context, a identitydomain.Actor) (verificationdomain.BackupManifest, error) {
	f.calls++
	return verificationdomain.BackupManifest{ID: "durable_backup", TenantID: a.TenantID, StateHash: "sha256:state", ResourceCounts: map[string]int{"evidence": 1}, SchemaVersion: verificationdomain.BackupManifestTenantSchemaVersion}, f.err
}
func TestBackupGenerationHTTPUsesFocusedCommandAndSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &backupGenerationHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(local.ledger, ServerOptions{BackupGenerationCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	body := postJSON(t, s, secret, "/v1/backup-manifests", "backup-replay", map[string]any{}, 201)
	if !strings.Contains(body, `"id":"durable_backup"`) || !strings.Contains(body, `"schema_version":"backup-manifest.v2.0.0"`) || f.calls != 1 {
		t.Fatal(body, f)
	}
	assertTrustHTTPReplay(t, body, postJSON(t, s, secret, "/v1/backup-manifests", "backup-replay", map[string]any{}, 201))
	if f.calls != 1 {
		t.Fatal("replay regenerated backup", f)
	}
	for i, bad := range []string{`null`, `[]`, `{"unknown":1}`, `{} {}`, `{"unknown":1,"unknown":2}`} {
		postRaw(t, s, secret, "/v1/backup-manifests", fmt.Sprintf("bad-backup-%d", i), []byte(bad), 400)
	}
	if f.calls != 1 {
		t.Fatal("invalid empty-object input reached snapshot reader", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrForbidden, 403}, {verificationapp.ErrNotFound, 404}, {verificationapp.ErrConflict, 409}, {errors.New("private SQL row secret"), 500}} {
		f.err = tc.err
		before := f.calls
		body := postJSON(t, s, secret, "/v1/backup-manifests", fmt.Sprintf("failed-backup-%d", i), map[string]any{}, tc.status)
		if f.calls != before+1 || strings.Contains(body, "private SQL") || strings.Contains(body, "durable_backup") {
			t.Fatal(body, f)
		}
	}
}
