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

func TestHumanUserReplayPreservesOnlyAuthorizedPublicDTO(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, status := range []string{"active", "deactivated"} {
		user := domain.HumanUser{ID: "user", TenantID: "tenant", OrganizationID: "org", Email: "person@example.test", DisplayName: "Person", Status: status, SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now}
		if status == "deactivated" {
			user.DeactivatedAt = &now
		}
		encoded, _ := json.Marshal(user)
		var root map[string]any
		if err := json.Unmarshal(encoded, &root); err != nil {
			t.Fatal(err)
		}
		root["hash"], root["secret"], root["unknown"] = "private-hash", "private-secret", map[string]any{"email": "foreign@example.test"}
		safe, err := safeIdempotencyReplayResponse(root)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ = json.Marshal(safe)
		var restored domain.HumanUser
		if err := json.Unmarshal(encoded, &restored); err != nil || !reflect.DeepEqual(restored, user) {
			t.Fatal("public user replay lost required fields", err)
		}
		if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "foreign@example.test") {
			t.Fatal("extra replay fields retained")
		}
		if root["email"] != user.Email || root["hash"] != "private-hash" {
			t.Fatal("replay projection mutated caller")
		}
		again, err := safeIdempotencyReplayResponse(safe)
		if err != nil || !reflect.DeepEqual(safe, again) {
			t.Fatal("replay projection is not stable", err)
		}
		generic, _ := redaction.RemoveSensitive(root)
		if generic.(map[string]any)["email"] != nil {
			t.Fatal("generic log/package email redaction weakened")
		}
	}
}

func TestHumanUserReplayFailsClosedOutsidePublishedDTO(t *testing.T) {
	for _, change := range []map[string]any{{"schema_version": "unknown"}, {"id": ""}, {"tenant_id": "other\x00"}, {"status": "unknown"}, {"created_at": "0001-01-01T00:00:00Z"}, {"email": "Person <person@example.test>"}, {"status": "deactivated"}} {
		root := map[string]any{"id": "user", "tenant_id": "tenant", "email": "person@example.test", "display_name": "Person", "status": "active", "schema_version": domain.HumanUserSchemaVersion, "created_at": "2026-09-01T00:00:00Z"}
		for key, value := range change {
			root[key] = value
		}
		safe, err := safeIdempotencyReplayResponse(root)
		if err != nil {
			t.Fatal(err)
		}
		if safe.(map[string]any)["email"] != nil {
			t.Fatal("non-public DTO bypassed PII redaction")
		}
	}
}
