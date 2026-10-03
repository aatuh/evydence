package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type backupGenerationHTTPFake struct {
	calls int
	err   error
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
	for _, required := range []string{"backup-manifest.v2.0.0", verificationapp.BackupStateCommitmentProfile, "not a restore receipt"} {
		if !strings.Contains(description, required) {
			t.Fatal("missing scope/version/nonclaim", description)
		}
	}
	if strings.Contains(description, "after an operator backup completes") {
		t.Fatal("unverified operator completion claim", description)
	}
}

func (f *backupGenerationHTTPFake) GenerateBackupManifest(_ context.Context, a identitydomain.Actor) (verificationdomain.BackupManifest, error) {
	f.calls++
	return verificationdomain.BackupManifest{ID: "durable_backup", TenantID: a.TenantID, StateHash: "sha256:state", ResourceCounts: map[string]int{"evidence": 1}, SchemaVersion: verificationdomain.BackupManifestTenantSchemaVersion}, f.err
}
func TestBackupGenerationHTTPUsesFocusedCommandAndSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &backupGenerationHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{BackupGenerationCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	s.verification = nil
	body := postJSON(t, s, secret, "/v1/backup-manifests", "backup-replay", map[string]any{}, 201)
	if !strings.Contains(body, `"id":"durable_backup"`) || !strings.Contains(body, `"schema_version":"backup-manifest.v2.0.0"`) || f.calls != 1 {
		t.Fatal(body, f)
	}
	if replay := postJSON(t, s, secret, "/v1/backup-manifests", "backup-replay", map[string]any{}, 201); replay != body || f.calls != 1 {
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
