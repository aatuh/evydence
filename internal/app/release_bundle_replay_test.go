package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func signedReplayBundle(t *testing.T) domain.ReleaseBundle {
	t.Helper()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := map[string]any{"manifest_version": packagedomain.ReleaseBundleSchemaVersion, "bundle_id": "bundle", "tenant_id": "tenant", "release": map[string]any{"id": "release", "version": "1", "state": "draft"}, "chain_checkpoint": map[string]any{"sequence": json.Number("9007199254740993"), "head_hash": "hash"}, "generated_at": at.Format(time.RFC3339Nano), "evidence_ids": []string{}, "object_lock_proofs": []map[string]any{{"id": "policy", "object_prefix_configured": true, "sample_object_key_configured": true, "name": "Retention"}}}
	h, err := canonicalAnyHash(m)
	if err != nil {
		t.Fatal(err)
	}
	return domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "release", State: "generated", Manifest: m, ManifestHash: h, SignatureRefs: []string{"signature"}, CreatedAt: at}
}
func replayJSONTree(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestSignedReleaseBundleReplayRetainsPublicRetentionFlagAndExactHash(t *testing.T) {
	v := signedReplayBundle(t)
	out, err := safeIdempotencyReplayResponse(v)
	if err != nil {
		t.Fatal(err)
	}
	tree := replayJSONTree(t, out)
	manifest := tree["manifest"].(map[string]any)
	proof := manifest["object_lock_proofs"].([]any)[0].(map[string]any)
	h, err := canonicalAnyHash(manifest)
	if err != nil || h != v.ManifestHash || proof["sample_object_key_configured"] != true || manifest["chain_checkpoint"].(map[string]any)["sequence"] != json.Number("9007199254740993") {
		t.Fatal("signed replay changed public commitment", err)
	}
	// Unknown storage/credential fields are not part of the public DTO.
	root := replayJSONTree(t, v)
	root["private_key"] = "private-canary"
	out, err = safeIdempotencyReplayResponse(root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "private-canary") || strings.Contains(string(b), `"private_key"`) {
		t.Fatal("versioned replay restored private field")
	}
}
func TestSignedReleaseBundleReplayDoesNotRestoreFlagForInvalidOrSensitiveManifest(t *testing.T) {
	for _, kind := range []string{"hash", "version", "string-flag", "object-path", "credential"} {
		v := signedReplayBundle(t)
		root := replayJSONTree(t, v)
		m := root["manifest"].(map[string]any)
		p := m["object_lock_proofs"].([]any)[0].(map[string]any)
		switch kind {
		case "hash":
			root["manifest_hash"] = "invalid"
		case "version":
			m["manifest_version"] = "unknown"
		case "string-flag":
			p["sample_object_key_configured"] = "secret-canary"
		case "object-path":
			p["object_key"] = "object://private-canary"
		case "credential":
			p["name"] = "password=secret-canary"
		}
		if kind != "hash" {
			h, err := canonicalAnyHash(m)
			if err != nil {
				t.Fatal(err)
			}
			root["manifest_hash"] = h
		}
		out, err := safeIdempotencyReplayResponse(root)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(out)
		if strings.Contains(string(b), "sample_object_key_configured") || strings.Contains(string(b), "secret-canary") || strings.Contains(string(b), "private-canary") {
			t.Fatal("untrusted replay exception", kind, string(b))
		}
	}
}
