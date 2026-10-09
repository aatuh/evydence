package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestAPIKeyReplayPreservesOnlyPublishedCredentialMetadata(t *testing.T) {
	key := domain.APIKey{ID: "key_public", TenantID: "tenant", Name: "Automation", Prefix: "evy_public01", Scopes: []string{"", "custom:scope", "evidence:read", "evidence:read"}, CreatedAt: fixedNow(), Hash: "private-hash-canary"}
	input := map[string]any{"api_key": key, "secret": "evy_one_time_secret_canary"}
	safe, err := safeIdempotencyReplayResponse(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private-hash-canary", "evy_one_time_secret_canary", `"hash"`, `"secret"`} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("API-key replay retained private data")
		}
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	public, ok := out["api_key"].(map[string]any)
	if !ok || public["id"] != key.ID || public["name"] != key.Name || public["prefix"] != key.Prefix {
		t.Fatal("required public API-key metadata removed")
	}
	if again, err := safeIdempotencyReplayResponse(out); err != nil || !reflect.DeepEqual(again, out) {
		t.Fatal("stored replay not stable", err)
	}
	if input["secret"] != "evy_one_time_secret_canary" || input["api_key"].(domain.APIKey).Hash != "private-hash-canary" {
		t.Fatal("first credential response mutated")
	}
	public["hash"], public["secret"], public["extra"] = "private-hash-canary", "evy_one_time_secret_canary", "private-field"
	safe, err = safeIdempotencyReplayResponse(out)
	if err != nil {
		t.Fatal(err)
	}
	projected := safe.(map[string]any)["api_key"].(map[string]any)
	for _, field := range []string{"hash", "secret", "extra"} {
		if _, ok := projected[field]; ok {
			t.Fatal("unpublished credential field retained", field)
		}
	}
	for _, mutation := range []string{"full-secret-prefix", "bad-id", "bad-tenant", "missing-name", "missing-time", "oversized-scopes", "unrelated-envelope"} {
		var bad map[string]any
		if err := json.Unmarshal(encoded, &bad); err != nil {
			t.Fatal(err)
		}
		obj := bad["api_key"].(map[string]any)
		switch mutation {
		case "full-secret-prefix":
			obj["prefix"] = "evy_one_time_secret_canary"
		case "bad-id":
			obj["id"] = ""
		case "bad-tenant":
			obj["tenant_id"] = "other\x00"
		case "missing-name":
			delete(obj, "name")
		case "missing-time":
			delete(obj, "created_at")
		case "oversized-scopes":
			obj["scopes"] = make([]string, 1025)
		case "unrelated-envelope":
			bad["unrelated"] = true
		}
		v, err := safeIdempotencyReplayResponse(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := v.(map[string]any)["api_key"]; ok {
			t.Fatal("invalid or unrelated credential envelope bypassed redaction", mutation)
		}
	}
}
