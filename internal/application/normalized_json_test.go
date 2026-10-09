package application

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"testing"
)

func TestNormalizedJSONHashPreservesLegacyProfile(t *testing.T) {
	for _, tc := range []struct {
		input   any
		encoded string
	}{
		{map[string]any{"z": "<review>&", "a": 1}, `{"a":1,"z":"\u003creview\u003e\u0026"}`},
		{map[string]any{"n": json.Number("9007199254740993")}, `{"n":9007199254740992}`},
		{map[string]any{"items": []any{map[string]any{"b": 2, "a": 1}, nil}}, `{"items":[{"a":1,"b":2},null]}`},
		{map[string]any(nil), `null`},
	} {
		actual, err := NormalizedJSONHash(tc.input)
		if err != nil || actual != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(tc.encoded))) {
			t.Fatalf("hash=%s err=%v", actual, err)
		}
	}
	for _, invalid := range []any{make(chan int), math.NaN(), json.RawMessage("invalid"), json.Number("1e1000")} {
		if hash, err := NormalizedJSONHash(invalid); err == nil || hash != "" {
			t.Fatalf("invalid value returned hash=%s err=%v", hash, err)
		}
	}
}
