package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestTrustConfigurationOpenAPIConstrainsCreationNotHistoricalRecords(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties  map[string]map[string]any `json:"properties"`
				Description string                    `json:"description"`
				Required    []string                  `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CreateSigningProviderRequest", "CreateDSSETrustRootRequest"} {
		v := doc.Components.Schemas[name]
		if v.Properties["name"]["maxLength"] != float64(4096) || !strings.Contains(v.Description, "before reservation") || !strings.Contains(v.Description, "64 KiB") || !strings.Contains(v.Description, "Local memory") {
			t.Fatal("creation bounds/replay/nonclaims missing", name)
		}
	}
	p := doc.Components.Schemas["CreateSigningProviderRequest"]
	if p.Properties["key_ref"]["maxLength"] != float64(4096) || len(p.Properties["type"]["enum"].([]any)) != 6 {
		t.Fatal("provider bounds/types missing")
	}
	for _, name := range p.Required {
		if name == "encrypted" {
			t.Fatal("optional encrypted flag became required")
		}
	}
	r := doc.Components.Schemas["CreateDSSETrustRootRequest"]
	if r.Properties["key_id"]["maxLength"] != float64(1024) || r.Properties["public_key"]["maxLength"] != float64(128) {
		t.Fatal("public key bounds missing")
	}
	for _, field := range []string{"allowed_predicate_types", "expected_builder_ids", "required_claims"} {
		p := r.Properties[field]
		if p["maxItems"] != float64(verificationapp.MaxTrustPolicyEntries) || p["uniqueItems"] != true || p["items"].(map[string]any)["maxLength"] != float64(4096) {
			t.Fatal("policy bounds/uniqueness missing", field)
		}
	}
	for _, name := range []string{"SigningProvider", "DSSETrustRoot"} {
		if doc.Components.Schemas[name].Properties["name"]["maxLength"] != nil {
			t.Fatal("historical response newly restricted", name)
		}
	}
}
