package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReleaseBundleSanitizesRetentionFactsBeforeHashAndSigning(t *testing.T) {
	state := newPackageTestState()
	state.releaseBundleSnapshot = ReleaseBundleSnapshot{SnapshotVersion: ReleaseBundleSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", ReleaseVersion: "1", ReleaseState: "draft", ObjectLockProofs: []map[string]any{{"id": "policy", "object_prefix_configured": true, "sample_object_key_configured": true, "object_key": "tenants/ten_1/private-object", "private_key": "private-material", "name": "reviewer@example.test", "verification_checks": []map[string]any{{"name": "check", "detail": "password=secret-canary"}}}}}
	c := newPackageTestService(t, state)
	v, err := c.CreateReleaseBundle(t.Context(), packageTestActor(), "rel_1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-object", "private-material", "reviewer@example.test", "secret-canary", `"object_key"`, `"private_key"`} {
		if strings.Contains(string(b), secret) {
			t.Fatal("sensitive retention fact reached signed manifest", secret)
		}
	}
	proofs := v.Manifest["object_lock_proofs"].([]map[string]any)
	if len(proofs) != 1 || proofs[0]["sample_object_key_configured"] != true || proofs[0]["object_prefix_configured"] != true || v.ManifestHash != state.lastSigningRequest.PayloadHash {
		t.Fatal("public fact or signing binding changed")
	}
	if state.releaseBundleSnapshot.ObjectLockProofs[0]["name"] != "reviewer@example.test" {
		t.Fatal("sanitization changed committed source snapshot")
	}
}
