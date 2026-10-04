package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIdempotencyReplayRedactionPreservesExactJSONNumbers(t *testing.T) {
	const numbers = `{"size":9007199254740993,"max":9223372036854775807,"min":-9223372036854775808,"decimal":0.12345678901234567890123456789,"nested":[9007199254740995]}`
	for _, redact := range []bool{false, true} {
		response := map[string]any{"manifest": json.RawMessage(numbers)}
		if redact {
			response["secret"] = "replay-private-number-canary"
		}
		safe, err := safeIdempotencyReplayResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(safe)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "replay-private-number-canary") || strings.Contains(string(body), `"secret"`) {
			t.Fatal("redaction weakened", string(body))
		}
		for _, number := range []string{"9007199254740993", "9223372036854775807", "-9223372036854775808", "0.12345678901234567890123456789", "9007199254740995"} {
			if !strings.Contains(string(body), number) {
				t.Fatal("exact JSON number changed during replay redaction", redact, number, string(body))
			}
		}
	}
}
