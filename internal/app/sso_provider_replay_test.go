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

func TestSSOProviderReplayPreservesOnlyPublicGroupRoleMetadata(t *testing.T) {
	p := domain.SSOProvider{ID: "provider", TenantID: "tenant", Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", RoleMapping: map[string]string{"token-reviewers": "security_engineer", "unknown": "future-role"}, Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	encoded, _ := json.Marshal(p)
	var root map[string]any
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	root["client_secret"], root["unknown"] = "private-provider-canary", map[string]any{"password": "private-provider-canary"}
	safe, err := safeIdempotencyReplayResponse(root)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(safe)
	var restored domain.SSOProvider
	if err := json.Unmarshal(encoded, &restored); err != nil || !reflect.DeepEqual(restored, p) || strings.Contains(string(encoded), "private-provider-canary") {
		t.Fatal("provider replay changed public metadata or retained secrets", err)
	}
	again, err := safeIdempotencyReplayResponse(safe)
	if err != nil || !reflect.DeepEqual(safe, again) {
		t.Fatal("provider replay projection is unstable", err)
	}
	generic, _ := redaction.RemoveSensitive(root)
	if generic.(map[string]any)["role_mapping"].(map[string]any)["token-reviewers"] != nil {
		t.Fatal("generic privacy redaction weakened")
	}
	if root["client_secret"] != "private-provider-canary" {
		t.Fatal("provider replay mutated caller")
	}
	for _, change := range []map[string]any{{"schema_version": "unknown"}, {"id": ""}, {"tenant_id": "bad\x00"}, {"status": "disabled"}, {"created_at": "0001-01-01T00:00:00Z"}, {"trust_material_updated_at": "0001-01-01T00:00:00Z"}} {
		copy := make(map[string]any, len(root))
		for k, v := range root {
			copy[k] = v
		}
		for k, v := range change {
			copy[k] = v
		}
		safe, err := safeIdempotencyReplayResponse(copy)
		if err != nil {
			t.Fatal(err)
		}
		if safe.(map[string]any)["role_mapping"].(map[string]any)["token-reviewers"] != nil {
			t.Fatal("invalid provider shape bypassed redaction")
		}
	}
	root["role_mapping"].(map[string]any)["secret-group"] = "access_token=private-provider-canary"
	safe, err = safeIdempotencyReplayResponse(root)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(safe)
	if strings.Contains(string(encoded), "private-provider-canary") {
		t.Fatal("credential-shaped group metadata acquired exception")
	}
}

func TestSSOProviderReplayPreservesRotatedPublicTrustAndRoleMetadata(t *testing.T) {
	updated := time.Date(2026, 10, 3, 12, 0, 0, 123456000, time.UTC)
	p := domain.SSOProvider{ID: "provider", TenantID: "tenant", Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", RoleMapping: map[string]string{"token-reviewers": "security_engineer"}, JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "rotated", "crv": "Ed25519", "x": "public-only"}}}, TrustMaterialUpdatedAt: &updated, Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: updated.Add(-time.Hour)}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	root["client_secret"] = "private-provider-canary"
	safe, err := safeIdempotencyReplayResponse(root)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	var restored domain.SSOProvider
	if err := json.Unmarshal(encoded, &restored); err != nil || !reflect.DeepEqual(restored, p) || strings.Contains(string(encoded), "private-provider-canary") {
		t.Fatal("rotation replay changed public trust or role metadata", err)
	}
	if again, err := safeIdempotencyReplayResponse(safe); err != nil || !reflect.DeepEqual(safe, again) {
		t.Fatal("rotated provider replay projection is unstable", err)
	}
	if root["client_secret"] != "private-provider-canary" {
		t.Fatal("rotation replay mutated caller")
	}
}

func TestSSOProviderReplayPreservesNormalizedPublicSAMLPEM(t *testing.T) {
	_, certificate := samlTestCertificate(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for _, updated := range []*time.Time{nil, &now} {
		p := domain.SSOProvider{ID: "provider", TenantID: "tenant", Name: "Fixture", Type: "saml", Issuer: "https://saml.example.test/entity", ClientID: "client", RoleMapping: map[string]string{"token-reviewers": "security_engineer"}, SAMLSigningCertificates: []string{certificate}, TrustMaterialUpdatedAt: updated, Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now.Add(-time.Hour)}
		safe, err := safeIdempotencyReplayResponse(p)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(safe)
		if err != nil {
			t.Fatal(err)
		}
		var restored domain.SSOProvider
		if err := json.Unmarshal(encoded, &restored); err != nil || !reflect.DeepEqual(restored, p) {
			t.Fatal("SAML replay damaged normalized public PEM", err)
		}
		if again, err := safeIdempotencyReplayResponse(safe); err != nil || !reflect.DeepEqual(safe, again) {
			t.Fatal("public SAML replay projection is unstable", err)
		}
	}
}
