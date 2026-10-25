package application_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

func FuzzNormalizedJSONHashStable(f *testing.F) {
	for _, seed := range []string{
		`null`, `true`, `[]`, `{}`, `{"b":2,"a":1}`,
		`{"n":9007199254740993}`, `{"n":1e1000}`,
		`{"items":[{"z":"<review>&","a":-0.0},null]}`,
		`{"id":"first","id":"second"}`, `{} {}`,
		`{"unicode":"\ud83d\ude00","escaped":"\u0061"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16<<10 {
			return
		}
		limits := jsonbounds.Limits{
			MaxDepth: 16, MaxObjectKeys: 64,
			MaxArrayItems: 128, MaxStringBytes: 1024,
		}
		// Admit one bounded, unambiguous value before generic decoding. The
		// hash profile itself retains its historical float64 normalization.
		if err := jsonbounds.Validate(raw, limits); err != nil {
			return
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("validated JSON could not be decoded: %v", err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("decoded JSON could not be serialized: %v", err)
		}
		first, err := application.NormalizedJSONHash(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("validated JSON could not be hashed: %v", err)
		}
		if len(first) != 71 || !strings.HasPrefix(first, "sha256:") {
			t.Fatal("normalized hash lost its SHA-256 profile")
		}
		for _, equivalent := range []any{value, json.RawMessage(encoded)} {
			actual, err := application.NormalizedJSONHash(equivalent)
			if err != nil || actual != first {
				t.Fatalf("parse/serialize changed normalized hash: %v", err)
			}
		}
		before, err := application.NormalizedJSONHash(map[string]any{
			"value": value, "tampered": false,
		})
		if err != nil {
			t.Fatal(err)
		}
		after, err := application.NormalizedJSONHash(map[string]any{
			"value": value, "tampered": true,
		})
		if err != nil || before == after {
			t.Fatalf("changed canonical field did not change its hash: %v", err)
		}
	})
}
