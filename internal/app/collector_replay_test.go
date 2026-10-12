package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestCollectorReplayPreservesOnlyPublicBoundCredentialMetadata(t *testing.T) {
	key := domain.APIKey{ID: "key_public", TenantID: "tenant", Name: "collector:Builder", Prefix: "evy_public01", Scopes: []string{"build:write", "evidence:write"}, CreatedAt: fixedNow(), Hash: "private-hash-canary"}
	collector := domain.Collector{ID: "col_public", TenantID: "tenant", Name: "Builder", Type: "generic_ci", Version: "1", APIKeyID: key.ID, Status: "active", AllowedScopes: append([]string(nil), key.Scopes...), SchemaVersion: domain.CollectorSchemaVersion, CreatedAt: key.CreatedAt}
	response := map[string]any{"collector": collector, "api_key": key, "secret": "evy_one_time_secret_canary"}
	safe, err := safeIdempotencyReplayResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-hash-canary", "evy_one_time_secret_canary", `"secret"`, `"hash"`} {
		if strings.Contains(string(raw), private) {
			t.Fatal("replay exposed private credential material")
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["api_key"]; !ok {
		t.Fatal("public API-key metadata was removed")
	}
	if out["collector"].(map[string]any)["api_key_id"] != key.ID {
		t.Fatal("public collector binding was removed")
	}
	if response["secret"] != "evy_one_time_secret_canary" || response["api_key"].(domain.APIKey).Hash != "private-hash-canary" {
		t.Fatal("replay projection mutated the first response")
	}
	if again, err := safeIdempotencyReplayResponse(out); err != nil || !reflect.DeepEqual(again, out) {
		t.Fatal("persisted replay changed after another sanitation pass", err)
	}
	keyObject := out["api_key"].(map[string]any)
	keyObject["hash"] = "private-hash-canary"
	keyObject["secret"] = "evy_one_time_secret_canary"
	keyObject["extra"] = map[string]any{"nested": "evy_one_time_secret_canary"}
	projected, err := safeIdempotencyReplayResponse(out)
	if err != nil {
		t.Fatal(err)
	}
	public := projected.(map[string]any)["api_key"].(map[string]any)
	for _, field := range []string{"hash", "secret", "extra"} {
		if _, ok := public[field]; ok {
			t.Fatal("non-public API-key field retained", field)
		}
	}
	if public["id"] != key.ID || out["api_key"].(map[string]any)["hash"] != "private-hash-canary" {
		t.Fatal("narrow projection lost its public ID or mutated the input")
	}
	for _, mutation := range []string{"foreign-key", "foreign-tenant", "secret-value", "full-secret-prefix"} {
		var bad map[string]any
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &bad); err != nil {
			t.Fatal(err)
		}
		switch mutation {
		case "foreign-key":
			bad["collector"].(map[string]any)["api_key_id"] = "key_other"
		case "foreign-tenant":
			bad["api_key"].(map[string]any)["tenant_id"] = "other"
		case "secret-value":
			bad["api_key"] = "evy_one_time_secret_canary"
		case "full-secret-prefix":
			bad["api_key"].(map[string]any)["prefix"] = "evy_one_time_secret_canary"
		}
		v, err := safeIdempotencyReplayResponse(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := v.(map[string]any)["api_key"]; ok {
			t.Fatal("invalid credential envelope escaped redaction", mutation)
		}
	}
}
