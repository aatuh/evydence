package app

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Only the explicit versioned recorded-signature DTO may retain its canonical
// tenant/digest-derived payload reference. Arbitrary storage paths and unknown
// response fields keep generic redaction; payload bytes are never in this DTO.
func publicArtifactSignatureReplay(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	for field := range root {
		switch field {
		case "id", "tenant_id", "artifact_id", "subject_digest", "algorithm", "key_id", "signature", "payload_ref", "payload_hash", "verification_status", "schema_version", "created_at":
		default:
			return nil, false
		}
	}
	raw, err := json.Marshal(root)
	if err != nil || len(raw) > 1<<20 {
		return nil, false
	}
	var v domain.ArtifactSignature
	if json.Unmarshal(raw, &v) != nil || v.SchemaVersion != domain.ArtifactSignatureSchemaVersion || v.VerificationStatus != "recorded" || v.CreatedAt.IsZero() {
		return nil, false
	}
	for _, id := range []string{v.ID, v.TenantID, v.ArtifactID} {
		if id == "" || !validPublicMembershipText(id, 1024) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	if _, err := verificationapp.NormalizeArtifactSignatureInput(verificationapp.CreateArtifactSignatureInput{ArtifactID: v.ArtifactID, Algorithm: v.Algorithm, KeyID: v.KeyID, Signature: v.Signature}); err != nil {
		return nil, false
	}
	if !validPublicMembershipText(v.SubjectDigest, 1024) || strings.TrimSpace(v.SubjectDigest) != v.SubjectDigest || ValidateCanonicalObjectDigest(v.PayloadHash) != nil {
		return nil, false
	}
	_, final, err := CanonicalObjectPayloadKeys(v.TenantID, v.PayloadHash)
	if err != nil || v.PayloadRef != "object://"+final {
		return nil, false
	}
	raw, err = json.Marshal(v)
	if err != nil {
		return nil, false
	}
	var projected map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&projected) != nil {
		return nil, false
	}
	safe, _ := redaction.RemoveSensitive(projected)
	result := safe.(map[string]any)
	result["payload_ref"] = v.PayloadRef
	return result, true
}
