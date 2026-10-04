package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMerkleCreationOpenAPIDocumentsFreshInputAndHistoricalReplay(t *testing.T) {
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
	v := doc.Components.Schemas["CreateMerkleBatchRequest"]
	for _, f := range []string{"from_sequence", "to_sequence"} {
		if v.Properties[f]["minimum"] != float64(0) || v.Properties[f]["format"] != "int64" {
			t.Fatal("nonnegative sequence contract missing", f)
		}
	}
	for _, phrase := range []string{"before reservation", "64 KiB", "4096", "8 MiB", "Local memory", "original"} {
		if !strings.Contains(v.Description, phrase) {
			t.Fatal("Merkle creation contract missing", phrase)
		}
	}
	if len(v.Required) != 0 {
		t.Fatal("optional default bounds became required")
	}
	if doc.Components.Schemas["MerkleBatch"].Properties["leaf_hashes"]["maxItems"] != nil {
		t.Fatal("historical batch schema newly restricted")
	}
}
