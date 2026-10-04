package app

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Only the versioned public retention DTO may retain a tenant-owned sample
// key. Arbitrary responses and private payload references keep the denylist.
func publicObjectRetentionReplay(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(root)
	if err != nil || len(encoded) > verificationapp.MaxRetentionPolicyBytes {
		return nil, false
	}
	var p domain.ObjectRetentionPolicy
	if json.Unmarshal(encoded, &p) != nil || p.SchemaVersion != domain.ObjectRetentionPolicyVersion || p.CreatedAt.IsZero() {
		return nil, false
	}
	for _, id := range []string{p.ID, p.TenantID} {
		if id == "" || !validPublicMembershipText(id, 1024) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	switch p.Status {
	case "configured", "verified", "not_verified", "stale":
	default:
		return nil, false
	}
	in, err := verificationapp.NormalizeObjectRetentionPolicyInput(p.TenantID, verificationapp.CreateObjectRetentionPolicyInput{Name: p.Name, ObjectPrefix: p.ObjectPrefix, ObjectKey: p.ObjectKey, Mode: p.Mode, RetentionDays: p.RetentionDays, MaxVerificationAgeHours: p.MaxVerificationAgeHours, RequireLegalHold: p.RequireLegalHold})
	if err != nil || in.ObjectKey != p.ObjectKey || in.ObjectPrefix != p.ObjectPrefix || p.ObjectKey == "" || redaction.RedactString(p.ObjectKey) != p.ObjectKey {
		return nil, false
	}
	// Re-encode the explicit public DTO, excluding all unknown storage fields.
	encoded, err = json.Marshal(p)
	if err != nil {
		return nil, false
	}
	var projected map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&projected) != nil {
		return nil, false
	}
	safe, _ := redaction.RemoveSensitive(projected)
	result := safe.(map[string]any)
	result["object_key"] = p.ObjectKey
	return result, true
}
