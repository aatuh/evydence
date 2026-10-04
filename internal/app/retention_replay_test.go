package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func retentionReplayFixture() domain.ObjectRetentionPolicy {
	return domain.ObjectRetentionPolicy{ID: "policy", TenantID: "tenant", Name: "Lock", ObjectPrefix: "tenants/tenant/", ObjectKey: "tenants/tenant/raw/sample", Mode: "governance", RetentionDays: 30, MaxVerificationAgeHours: 24, Status: "configured", SchemaVersion: domain.ObjectRetentionPolicyVersion, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 123, time.UTC)}
}

func TestRetentionReplayPreservesOnlyVersionedPublicSampleKey(t *testing.T) {
	policy := retentionReplayFixture()
	raw, _ := json.Marshal(policy)
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	for _, input := range []any{policy, stored} {
		safe, err := safeIdempotencyReplayResponse(input)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(safe)
		if err != nil || !strings.Contains(string(body), `"object_key":"tenants/tenant/raw/sample"`) {
			t.Fatal("public sample key lost on replay", string(body), err)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil || !reflect.DeepEqual(got, stored) {
			t.Fatal("safe public policy changed", string(body), err)
		}
		again, err := safeIdempotencyReplayResponse(safe)
		if err != nil || !reflect.DeepEqual(again, safe) {
			t.Fatal("public-policy sanitization is not stable", err)
		}
	}
	stored["secret"] = "private-retention-canary"
	stored["unrelated_metadata"] = "must-not-become-public-policy"
	stored["verification_checks"] = []any{map[string]any{"name": "provider", "result": "passed", "access_token": "private-retention-canary", "detail": "password=private-retention-canary"}}
	safe, err := safeIdempotencyReplayResponse(stored)
	body, marshalErr := json.Marshal(safe)
	if err != nil || marshalErr != nil || strings.Contains(string(body), "private-retention-canary") || strings.Contains(string(body), "must-not-become-public-policy") || !strings.Contains(string(body), `"object_key":"tenants/tenant/raw/sample"`) {
		t.Fatal("public-policy projection retained private fields or lost sample", string(body), err, marshalErr)
	}
}

func TestRetentionReplayDoesNotExemptArbitraryOrUnsafeObjectKeys(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) {
			for key := range v {
				if key != "object_key" {
					delete(v, key)
				}
			}
		},
		func(v map[string]any) { v["schema_version"] = "not-a-retention-policy" },
		func(v map[string]any) { v["status"] = "unknown" },
		func(v map[string]any) { delete(v, "created_at") },
		func(v map[string]any) { delete(v, "tenant_id") },
		func(v map[string]any) { v["object_key"] = "tenants/foreign/raw/sample" },
		func(v map[string]any) { v["object_prefix"] = "tenants/tenant/another/" },
		func(v map[string]any) { v["object_key"] = "tenants/tenant/password=private-retention-canary" },
		func(v map[string]any) { v["object_key"] = "tenants/tenant/" + strings.Repeat("x", 4096) },
		func(v map[string]any) { v["object_key"] = "tenants/tenant/bad\x00" },
	} {
		raw, _ := json.Marshal(retentionReplayFixture())
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		mutate(v)
		safe, err := safeIdempotencyReplayResponse(v)
		body, marshalErr := json.Marshal(safe)
		if err != nil || marshalErr != nil || strings.Contains(string(body), `"object_key"`) || strings.Contains(string(body), "private-retention-canary") {
			t.Fatal("unsafe sample escaped generic redaction", string(body), err, marshalErr)
		}
	}
}
