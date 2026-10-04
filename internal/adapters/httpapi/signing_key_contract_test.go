package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSigningKeyOpenAPISeparatesRotationAndBoundsFreshTransitions(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties  map[string]map[string]any
				Description string
				Required    []string
			}
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SigningKeyRotationRequest", "SigningKeyTransitionRequest"} {
		s := doc.Components.Schemas[name]
		if s.Properties["reason"]["maxLength"] != float64(4096) || !strings.Contains(s.Description, "before reservation") || !strings.Contains(s.Description, "64 KiB") || !strings.Contains(s.Description, "Local memory") || len(s.Required) != 1 || s.Required[0] != "reason" {
			t.Fatal("key lifecycle contract missing", name)
		}
	}
	if len(doc.Components.Schemas["SigningKeyRotationRequest"].Properties) != 1 {
		t.Fatal("rotation accepts revocation-only fields")
	}
	if doc.Components.Schemas["SigningKey"].Properties["revocation_reason"]["maxLength"] != nil {
		t.Fatal("historical key response newly restricted")
	}
}
