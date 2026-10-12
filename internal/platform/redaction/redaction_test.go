package redaction

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type malformedJSONDiagnostic struct{}

func (malformedJSONDiagnostic) MarshalJSON() ([]byte, error) {
	return []byte("{"), nil
}

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

func TestRemoveSensitiveDropsFieldsWithoutMutatingInput(t *testing.T) {
	value := map[string]any{
		"safe":    "retained",
		"api_key": "remove-api-key-canary",
		"nested": []any{
			map[string]any{
				"access_token": "remove-access-token-canary",
				"status":       "kept",
			},
		},
	}

	safe, changed := RemoveSensitive(value)
	if !changed {
		t.Fatal("RemoveSensitive reported that a sensitive input was unchanged")
	}
	body, err := json.Marshal(safe)
	if err != nil {
		t.Fatalf("marshal field-removed value: %v", err)
	}
	for _, forbidden := range []string{"api_key", "access_token", "remove-api-key-canary", "remove-access-token-canary"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("field-removed output retained %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(string(body), `"safe":"retained"`) || !strings.Contains(string(body), `"status":"kept"`) {
		t.Fatalf("field removal lost non-sensitive context: %s", body)
	}
	if value["api_key"] != "remove-api-key-canary" {
		t.Fatalf("RemoveSensitive mutated its input: %#v", value)
	}

	unchanged := map[string]any{"status": "retained"}
	got, changed := RemoveSensitive(unchanged)
	if changed || !reflect.DeepEqual(got, unchanged) {
		t.Fatalf("safe input changed: got=%#v changed=%v", got, changed)
	}
}

func TestFirstSensitivePathIsDeterministicAndDoesNotRevealValues(t *testing.T) {
	value := map[string]any{
		"z_secret": "path-secret-canary",
		"a": []any{
			map[string]any{"reviewer_email": "path-reviewer@example.test"},
		},
	}

	for iteration := 0; iteration < 10; iteration++ {
		path, ok := FirstSensitivePath(value)
		if !ok || path != "/a/0/reviewer_email" {
			t.Fatalf("FirstSensitivePath()=(%q, %v), want deterministic first path", path, ok)
		}
		if strings.Contains(path, "path-reviewer") || strings.Contains(path, "path-secret") {
			t.Fatalf("sensitive path leaked a value: %q", path)
		}
	}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "credential-like map value",
			value: map[string]string{"details": "Authorization: Bearer opaque-token-canary"},
			want:  "/details",
		},
		{
			name:  "credential-like string slice",
			value: []string{"safe", "customer_email=path@example.test"},
			want:  "/1",
		},
		{
			name: "typed JSON value",
			value: struct {
				APIKey string `json:"api_key"`
			}{APIKey: "typed-path-canary"},
			want: "/api_key",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, ok := FirstSensitivePath(test.value)
			if !ok || path != test.want {
				t.Fatalf("FirstSensitivePath()=(%q, %v), want (%q, true)", path, ok, test.want)
			}
		})
	}
	if path, ok := FirstSensitivePath(map[string]any{"safe": []any{"retained"}}); ok || path != "" {
		t.Fatalf("safe value reported a sensitive path: (%q, %v)", path, ok)
	}
}

func TestMarshalIndentAndErrorApplyTheSameBoundaryPolicy(t *testing.T) {
	body, err := MarshalIndent(
		map[string]any{"reviewer_email": "indent-reviewer@example.test", "safe": "retained"},
		"",
		"  ",
	)
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if strings.Contains(string(body), "indent-reviewer@example.test") || !strings.Contains(string(body), Redacted) {
		t.Fatalf("MarshalIndent did not sanitize its output: %s", body)
	}
	if !strings.Contains(string(body), "\n  ") || !strings.Contains(string(body), `"safe": "retained"`) {
		t.Fatalf("MarshalIndent did not retain deterministic readable context: %s", body)
	}

	if got := Error(nil); got != "" {
		t.Fatalf("Error(nil)=%q, want empty string", got)
	}
	got := Error(errors.New("database_url=postgres://operator:error-password@db.example.test/evydence\nfailed"))
	if strings.Contains(got, "error-password") || strings.ContainsAny(got, "\r\n") || !strings.Contains(got, Redacted) {
		t.Fatalf("Error leaked unsafe diagnostic content: %q", got)
	}
}

func TestSanitizeHandlesJSONShapeFailuresAndRawMessages(t *testing.T) {
	stringMap := map[string]string{
		"api_key": "string-map-key-canary",
		"details": "customer_email=string-map@example.test",
		"safe":    "retained",
	}
	sanitizedMap := Sanitize(stringMap)
	gotMap, ok := sanitizedMap.(map[string]string)
	if !ok {
		t.Fatalf("string map sanitize result=%#v, want string map", sanitizedMap)
	}
	if gotMap["api_key"] != Redacted || strings.Contains(gotMap["details"], "string-map@example.test") || gotMap["safe"] != "retained" {
		t.Fatalf("string map was not selectively sanitized: %#v", gotMap)
	}
	if stringMap["api_key"] != "string-map-key-canary" {
		t.Fatalf("string map input was mutated: %#v", stringMap)
	}
	removedMap, changed := RemoveSensitive(stringMap)
	gotRemovedMap, ok := removedMap.(map[string]string)
	if !changed || !ok || gotRemovedMap["api_key"] != "" || gotRemovedMap["safe"] != "retained" {
		t.Fatalf("string map field removal result=(%#v, %v)", removedMap, changed)
	}
	cleanMap := map[string]string{"safe": "retained"}
	if got, changed := RemoveSensitive(cleanMap); changed || !reflect.DeepEqual(got, cleanMap) {
		t.Fatalf("clean string map changed: got=%#v changed=%v", got, changed)
	}
	if IsSensitiveField(" __ ") {
		t.Fatal("empty normalized field name was classified as sensitive")
	}
	for _, safeValue := range []any{
		nil,
		42,
		[]byte{},
		[]any{"retained"},
		[]string{"retained"},
		struct {
			Status string `json:"status"`
		}{Status: "retained"},
	} {
		got := Sanitize(safeValue)
		if !reflect.DeepEqual(got, safeValue) {
			t.Fatalf("safe value changed: got=%#v want=%#v", got, safeValue)
		}
	}
	if got := Sanitize(malformedJSONDiagnostic{}); got != Redacted {
		t.Fatalf("malformed custom JSON sanitized to %#v, want %q", got, Redacted)
	}
	if path, ok := FirstSensitivePath("customer_email=root@example.test"); !ok || path != "" {
		t.Fatalf("sensitive root string path=(%q, %v), want root match", path, ok)
	}

	invalidRaw := json.RawMessage(`{"api_key":`)
	if got := Sanitize(invalidRaw); got != Redacted {
		t.Fatalf("invalid raw JSON sanitized to %#v, want %q", got, Redacted)
	}

	validRaw := json.RawMessage(`{"api_key":"raw-message-canary","safe":"retained"}`)
	got := Sanitize(validRaw)
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal sanitized raw JSON: %v", err)
	}
	if strings.Contains(string(body), "raw-message-canary") || !strings.Contains(string(body), Redacted) {
		t.Fatalf("raw JSON leaked sensitive content: %s", body)
	}

	cleanRaw := json.RawMessage(`{"safe":"retained"}`)
	clean, changed := RemoveSensitive(cleanRaw)
	if changed || !reflect.DeepEqual(clean, cleanRaw) {
		t.Fatalf("clean raw JSON changed: got=%#v changed=%v", clean, changed)
	}

	unserializable := struct {
		Channel chan int `json:"channel"`
	}{Channel: make(chan int)}
	if got := Sanitize(unserializable); got != Redacted {
		t.Fatalf("unserializable typed diagnostic sanitized to %#v, want %q", got, Redacted)
	}
	if path, ok := FirstSensitivePath(unserializable); !ok || path != "" {
		t.Fatalf("unserializable typed diagnostic path=(%q, %v), want root failure", path, ok)
	}

	stringsValue := []string{"safe", "customer_email=shape@example.test"}
	safe, changed := RemoveSensitive(stringsValue)
	if !changed {
		t.Fatal("credential-like string slice reported unchanged")
	}
	if gotStrings, ok := safe.([]string); !ok || gotStrings[0] != "safe" || strings.Contains(gotStrings[1], "shape@example.test") {
		t.Fatalf("string slice was not selectively sanitized: %#v", safe)
	}
	if stringsValue[1] != "customer_email=shape@example.test" {
		t.Fatalf("string slice input was mutated: %#v", stringsValue)
	}
}
