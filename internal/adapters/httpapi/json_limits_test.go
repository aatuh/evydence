package httpapi

import (
	"strconv"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsStructuralResourceBombs(t *testing.T) {
	objectFields := make([]string, 257)
	for index := range objectFields {
		objectFields[index] = `"key_` + strconv.Itoa(index) + `":1`
	}
	arrayItems := make([]string, 1025)
	for index := range arrayItems {
		arrayItems[index] = "1"
	}
	tests := map[string]string{
		"depth":    strings.Repeat(`{"nested":`, 33) + `"value"` + strings.Repeat(`}`, 33),
		"map keys": "{" + strings.Join(objectFields, ",") + "}",
		"array":    `{"items":[` + strings.Join(arrayItems, ",") + `]}`,
		"string":   `{"value":"` + strings.Repeat("x", (16<<10)+1) + `"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			var decoded any
			if err := decodeJSON([]byte(body), &decoded); err == nil {
				t.Fatalf("decodeJSON accepted %s resource bomb", name)
			}
		})
	}
}
