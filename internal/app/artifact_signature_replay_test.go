package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestArtifactSignatureReplayPreservesOnlyCanonicalPublicPayloadReference(t *testing.T) {
	hash := hashBytes([]byte(`{"signed":"opaque"}`))
	_, final, err := CanonicalObjectPayloadKeys("tenant", hash)
	if err != nil {
		t.Fatal(err)
	}
	base := domain.ArtifactSignature{ID: "signature", TenantID: "tenant", ArtifactID: "artifact", SubjectDigest: "sha256:" + strings.Repeat("a", 64), Algorithm: "cosign", Signature: "opaque-signed-value", KeyID: "public-key", PayloadHash: hash, PayloadRef: "object://" + final, VerificationStatus: "recorded", SchemaVersion: domain.ArtifactSignatureSchemaVersion, CreatedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}
	safe, err := safeIdempotencyReplayResponse(base)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(safe)
	var replay domain.ArtifactSignature
	if err := json.Unmarshal(encoded, &replay); err != nil || replay != base {
		t.Fatal("canonical public signature DTO changed in replay", replay, err)
	}
	for _, mutate := range []func(*domain.ArtifactSignature){
		func(v *domain.ArtifactSignature) { v.ID = "" },
		func(v *domain.ArtifactSignature) { v.PayloadRef = "object://other/private-path" },
		func(v *domain.ArtifactSignature) { v.PayloadRef = "file:///private/location" },
		func(v *domain.ArtifactSignature) { v.PayloadHash = "invalid" },
		func(v *domain.ArtifactSignature) { v.TenantID = "other" },
		func(v *domain.ArtifactSignature) { v.SchemaVersion = "unknown" },
		func(v *domain.ArtifactSignature) { v.CreatedAt = time.Time{} },
	} {
		v := base
		mutate(&v)
		safe, err := safeIdempotencyReplayResponse(v)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(safe)
		if strings.Contains(string(encoded), `"payload_ref"`) {
			t.Fatal("unsafe/unbound storage reference escaped redaction", string(encoded))
		}
	}
	raw, _ := json.Marshal(base)
	var mixed map[string]any
	if err := json.Unmarshal(raw, &mixed); err != nil {
		t.Fatal(err)
	}
	mixed["raw_payload"] = "private-signature-secret"
	mixed["secret"] = "private-signature-secret"
	safe, err = safeIdempotencyReplayResponse(mixed)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(safe)
	if strings.Contains(string(encoded), "private-signature-secret") || strings.Contains(string(encoded), "raw_payload") {
		t.Fatal("public signature projection preserved private fields", string(encoded))
	}
	if strings.Contains(string(encoded), `"secret"`) {
		t.Fatal("secret field retained")
	}
}
