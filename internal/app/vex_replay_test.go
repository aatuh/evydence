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

func publicVEXReplayFixture() domain.VEXDocument {
	return domain.VEXDocument{ID: "vex_public", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "openvex", Author: "security@example.test", Version: "1", StatementCount: 2, StatusSummary: map[string]int{"fixed": 1, "not_affected": 1}, SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)}
}

func TestVEXReplayPreservesPublicAuthorEmailAndRemainsStable(t *testing.T) {
	for _, format := range []string{"openvex", "cyclonedx"} {
		t.Run(format, func(t *testing.T) {
			input := publicVEXReplayFixture()
			input.Format = format
			safe, err := safeIdempotencyReplayResponse(input)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(safe)
			if err != nil {
				t.Fatal(err)
			}
			var replay domain.VEXDocument
			if err := json.Unmarshal(encoded, &replay); err != nil || !reflect.DeepEqual(input, replay) {
				t.Fatal("published VEX metadata changed on replay", err, replay)
			}
			again, err := safeIdempotencyReplayResponse(safe)
			if err != nil || !reflect.DeepEqual(safe, again) {
				t.Fatal("stored VEX replay is not stable", err)
			}
		})
	}
}

func TestVEXReplayAuthorExceptionRejectsMalformedAndPrivateMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing identity", func(v map[string]any) { v["evidence_id"] = "" }},
		{"foreign schema", func(v map[string]any) { v["schema_version"] = "unknown" }},
		{"invalid timestamp", func(v map[string]any) { v["created_at"] = "invalid" }},
		{"unknown format", func(v map[string]any) { v["format"] = "unknown" }},
		{"negative count", func(v map[string]any) { v["statement_count"] = -1 }},
		{"incoherent summary", func(v map[string]any) { v["status_summary"] = map[string]int{"fixed": 3} }},
		{"unknown status", func(v map[string]any) { v["status_summary"] = map[string]int{"private": 1} }},
		{"unknown field", func(v map[string]any) { v["extra"] = "untrusted" }},
		{"raw payload", func(v map[string]any) { v["raw_payload"] = "private-replay-sentinel" }},
		{"credentials in author", func(v map[string]any) { v["author"] = "security@example.test password=private-replay-sentinel" }},
		{"URL credentials", func(v map[string]any) { v["author"] = "https://user:private-replay-sentinel@example.test" }},
		{"header in author", func(v map[string]any) {
			v["author"] = "security@example.test\nAuthorization: Bearer private-replay-sentinel"
		}},
		{"quoted credentials", func(v map[string]any) { v["author"] = `"password=private-replay-sentinel"@example.test` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(publicVEXReplayFixture())
			if err != nil {
				t.Fatal(err)
			}
			var input map[string]any
			if err := json.Unmarshal(encoded, &input); err != nil {
				t.Fatal(err)
			}
			tc.mutate(input)
			safe, err := safeIdempotencyReplayResponse(input)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err = json.Marshal(safe)
			if err != nil || strings.Contains(string(encoded), "security@example.test") || strings.Contains(string(encoded), "private-replay-sentinel") || strings.Contains(string(encoded), "raw_payload") {
				t.Fatal("untrusted VEX-like metadata bypassed redaction", err, string(encoded))
			}
		})
	}
}

func TestVEXPublicAuthorReplayDoesNotRelaxOtherFieldsOrGenericRedaction(t *testing.T) {
	input := publicVEXReplayFixture()
	input.Version = "password=private-replay-sentinel"
	safe, err := safeIdempotencyReplayResponse(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(safe)
	if err != nil || !strings.Contains(string(encoded), "security@example.test") || strings.Contains(string(encoded), "private-replay-sentinel") {
		t.Fatal("author exception bypassed unrelated secret redaction", err)
	}
	generic, _ := redaction.RemoveSensitive(map[string]any{"author": input.Author})
	encoded, err = json.Marshal(generic)
	if err != nil || strings.Contains(string(encoded), "security@example.test") {
		t.Fatal("generic PII redaction changed", err)
	}
}
