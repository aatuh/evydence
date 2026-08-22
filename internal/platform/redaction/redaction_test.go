package redaction

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeRecursivelyRedactsSensitiveFieldsAndValues(t *testing.T) {
	canaries := []string{
		"evy_api_key_canary_123",
		"bearer-token-canary-456",
		"session-cookie-canary-789",
		"PRIVATE-SIGNING-MATERIAL-CANARY",
		"postgres://operator:db-password-canary@db.example.test/evydence",
		"provider-credential-canary",
		"internal-note-canary",
		"object://tenants/ten_1/payloads/raw-payload-canary",
		"customer@example.test",
	}
	value := map[string]any{
		"api_key":              canaries[0],
		"authorization":        "Bearer " + canaries[1],
		"cookie":               "session=" + canaries[2],
		"private_key":          canaries[3],
		"database_url":         canaries[4],
		"provider_credentials": canaries[5],
		"internal_notes":       canaries[6],
		"payload_ref":          canaries[7],
		"reviewer_email":       canaries[8],
		"nested": []any{
			map[string]any{"access_token": canaries[1]},
			"token=" + canaries[1],
		},
	}

	safe := Sanitize(value)
	body, err := json.Marshal(safe)
	if err != nil {
		t.Fatalf("marshal sanitized value: %v", err)
	}
	for _, canary := range canaries {
		if strings.Contains(string(body), canary) {
			t.Fatalf("sanitized output leaked %q: %s", canary, body)
		}
	}
	if !strings.Contains(string(body), Redacted) {
		t.Fatalf("sanitized output did not mark redaction: %s", body)
	}
}

func TestRedactStringRetainsSafeContextWithoutCredentials(t *testing.T) {
	value := "request to https://operator-canary:password-canary@example.test/path failed with Authorization: Bearer token-canary; customer@example.test; object://tenants/ten_1/raw-payload-canary"
	safe := RedactString(value)
	if strings.Contains(safe, "operator-canary") || strings.Contains(safe, "password-canary") || strings.Contains(safe, "token-canary") || strings.Contains(safe, "customer@example.test") || strings.Contains(safe, "raw-payload-canary") {
		t.Fatalf("redacted string leaked credential: %q", safe)
	}
	if !strings.Contains(safe, "example.test") || !strings.Contains(safe, Redacted) {
		t.Fatalf("redacted string removed all useful context: %q", safe)
	}
}

func TestSanitizeRejectsRawBytePayloads(t *testing.T) {
	body, err := Marshal([]byte("raw-payload-canary"))
	if err != nil {
		t.Fatalf("marshal raw bytes: %v", err)
	}
	if strings.Contains(string(body), "raw-payload-canary") || !strings.Contains(string(body), Redacted) {
		t.Fatalf("raw bytes were not redacted: %s", body)
	}
}

func TestRedactStringProducesSingleLineDiagnostic(t *testing.T) {
	safe := RedactString("request failed\nfor Authorization: Bearer token-canary\r\n")
	if strings.ContainsAny(safe, "\r\n") {
		t.Fatalf("redacted diagnostic contains a log-injection line break: %q", safe)
	}
	if strings.Contains(safe, "token-canary") {
		t.Fatalf("redacted diagnostic leaked credential: %q", safe)
	}
}

func TestSanitizeHandlesTypedJSONValues(t *testing.T) {
	type diagnostic struct {
		APIKey   string `json:"api_key"`
		Database struct {
			URL string `json:"database_url"`
		} `json:"database"`
		Safe string `json:"safe"`
	}

	value := diagnostic{APIKey: "typed-api-key-canary", Safe: "retained"}
	value.Database.URL = "postgres://operator:typed-password-canary@db.example.test/evydence"
	body, err := Marshal(value)
	if err != nil {
		t.Fatalf("marshal typed diagnostic: %v", err)
	}
	for _, canary := range []string{"typed-api-key-canary", "typed-password-canary"} {
		if strings.Contains(string(body), canary) {
			t.Fatalf("typed diagnostic leaked %q: %s", canary, body)
		}
	}
	if !strings.Contains(string(body), `"safe":"retained"`) {
		t.Fatalf("typed diagnostic lost safe context: %s", body)
	}
}

func TestRedactStringHandlesPrefixedCredentialsAndBoundsWork(t *testing.T) {
	canaries := []string{
		"prefixed-api-key-canary",
		"provider-secret-canary",
		"database-user-canary",
		"database-password-canary",
		"customer-name-canary",
	}
	value := "EVYDENCE_API_KEY=" + canaries[0] +
		" AWS_SECRET_ACCESS_KEY=" + canaries[1] +
		" DATABASE_URL=postgres://" + canaries[2] + ":" + canaries[3] + "@internal-db.example.test/evydence" +
		" customer_name=" + canaries[4] +
		" " + strings.Repeat("x", (64<<10)*2)

	safe := RedactString(value)
	for _, canary := range canaries {
		if strings.Contains(safe, canary) {
			t.Fatalf("bounded diagnostic leaked %q: %q", canary, safe)
		}
	}
	if len(safe) > (64<<10)+64 {
		t.Fatalf("diagnostic length=%d, want bounded output", len(safe))
	}
	if !strings.Contains(safe, "[TRUNCATED]") {
		t.Fatalf("bounded diagnostic did not report truncation: %q", safe)
	}
}
