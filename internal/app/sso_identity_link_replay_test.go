package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

func TestSSOIdentityLinkReplayPreservesOnlyVersionedAdminMetadata(t *testing.T) {
	for _, subject := range []string{"subject-1", "identity@example.test", "subject\nidentifier"} {
		link := domain.UserIdentityLink{ID: "link", TenantID: "tenant", UserID: "user", ProviderID: "provider", Subject: subject, Email: "person@example.test", Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
		encoded, _ := json.Marshal(link)
		var input map[string]any
		if err := json.Unmarshal(encoded, &input); err != nil {
			t.Fatal(err)
		}
		input["unknown"], input["secret"], input["hash"] = map[string]any{"email": "foreign@example.test"}, "private-secret", "private-hash"
		safe, err := safeIdempotencyReplayResponse(input)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ = json.Marshal(safe)
		var restored domain.UserIdentityLink
		if err := json.Unmarshal(encoded, &restored); err != nil || !reflect.DeepEqual(restored, link) {
			t.Fatal("admin link replay lost published metadata", err)
		}
		if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "foreign@example.test") || strings.Contains(string(encoded), "unknown") {
			t.Fatal("extra link replay data retained")
		}
		again, err := safeIdempotencyReplayResponse(safe)
		if err != nil || !reflect.DeepEqual(safe, again) {
			t.Fatal("link replay is not stable", err)
		}
		generic, _ := redaction.RemoveSensitive(input)
		if generic.(map[string]any)["email"] != nil || strings.Contains(redaction.RedactString(subject), "@") {
			t.Fatal("generic redaction weakened")
		}
		if input["email"] != link.Email || input["secret"] != "private-secret" {
			t.Fatal("caller response mutated")
		}
	}
}

func TestSSOIdentityLinkReplayCannotBroadenPrivacyException(t *testing.T) {
	base := map[string]any{"id": "link", "tenant_id": "tenant", "user_id": "user", "provider_id": "provider", "subject": "subject", "email": "person@example.test", "verified": true, "schema_version": "user-identity-link.v1.0.0", "created_at": "2026-09-01T00:00:00Z"}
	for _, change := range []map[string]any{{"schema_version": "unknown"}, {"verified": false}, {"id": ""}, {"user_id": ""}, {"provider_id": "bad\x00"}, {"subject": ""}, {"subject": strings.Repeat("x", 2305)}, {"email": "Person <person@example.test>"}, {"created_at": "0001-01-01T00:00:00Z"}, {"tenant_id": " secret=private "}} {
		input := make(map[string]any)
		for k, v := range base {
			input[k] = v
		}
		for k, v := range change {
			input[k] = v
		}
		safe, err := safeIdempotencyReplayResponse(input)
		if err != nil || safe.(map[string]any)["email"] != nil {
			t.Fatal("invalid link DTO bypassed PII redaction", change, err)
		}
	}
	base["subject"] = "secret=private-credential"
	safe, err := safeIdempotencyReplayResponse(base)
	if err != nil || strings.Contains(safe.(map[string]any)["subject"].(string), "private-credential") {
		t.Fatal("subject bypassed credential redaction", err)
	}
}
