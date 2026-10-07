package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRetentionOpenAPIConstrainsCreationNotHistoricalReceipts(t *testing.T) {
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
	v := doc.Components.Schemas["CreateObjectRetentionPolicyRequest"]
	for _, field := range []string{"name", "mode", "object_prefix", "object_key"} {
		if v.Properties[field]["maxLength"] != float64(4096) {
			t.Fatal("request raw text bound missing", field)
		}
	}
	if v.Properties["retention_days"]["maximum"] != float64(2147483647) || v.Properties["max_verification_age_hours"]["maximum"] != float64(8784) || len(v.Required) != 3 {
		t.Fatal("numeric bounds or optional defaults changed")
	}
	for _, text := range []string{"64 KiB", "before reservation", "requires PostgreSQL", "does not prove"} {
		if !strings.Contains(v.Description, text) {
			t.Fatal("creation/replay/nonclaim missing", text)
		}
	}
	if doc.Components.Schemas["ObjectRetentionPolicy"].Properties["name"]["maxLength"] != nil {
		t.Fatal("historical receipt newly restricted")
	}
}
