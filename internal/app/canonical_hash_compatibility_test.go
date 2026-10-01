package app

import (
	"encoding/json"
	"testing"
)

func TestCanonicalAnyHashPreservesLegacyNormalizedJSON(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   any
		encoded string
	}{
		{"sorted and escaped", map[string]any{"z": "<review>&", "a": 1}, `{"a":1,"z":"\u003creview\u003e\u0026"}`},
		{"large numeric compatibility", map[string]any{"n": json.Number("9007199254740993")}, `{"n":9007199254740992}`},
		{"nested arrays", map[string]any{"items": []any{map[string]any{"b": 2, "a": 1}, nil}}, `{"items":[{"a":1,"b":2},null]}`},
		{"nil map", map[string]any(nil), `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := canonicalAnyHash(tc.input)
			if err != nil || actual != hashBytes([]byte(tc.encoded)) {
				t.Fatalf("hash=%s err=%v", actual, err)
			}
		})
	}
}
