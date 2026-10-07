package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordedCheckpointOpenAPIDocumentsNativeReplayAndAssertionLimits(t *testing.T) {
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
	v := doc.Components.Schemas["CreateTransparencyCheckpointRequest"]
	if v.Properties["batch_id"]["maxLength"] != float64(1024) || v.Properties["batch_id"]["minLength"] != float64(1) || v.Properties["provider"]["minLength"] != float64(1) {
		t.Fatal("bounded nonblank coordinate contract missing")
	}
	for _, phrase := range []string{"before reservation", "64 KiB", "1 MiB", "requires PostgreSQL", "original", "recorded", "not proof"} {
		if !strings.Contains(v.Description, phrase) {
			t.Fatal("checkpoint contract missing", phrase)
		}
	}
	if len(v.Required) != 2 || v.Required[0] != "batch_id" || v.Required[1] != "provider" {
		t.Fatal("existing required fields changed", v.Required)
	}
	if v.Properties["external_url"]["format"] != nil {
		t.Fatal("recorded coordinate incorrectly advertised as validated/fetched URL")
	}
	if doc.Components.Schemas["TransparencyCheckpoint"].Properties["external_id"]["maxLength"] != nil {
		t.Fatal("historical response records newly restricted")
	}
}
