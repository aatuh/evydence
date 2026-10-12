package jsonbounds

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestValidateAcceptsOneBoundedJSONValue(t *testing.T) {
	if err := Validate([]byte(`{"items":[{"name":"release"}]}`), DefaultLimits()); err != nil {
		t.Fatalf("validate bounded JSON: %v", err)
	}
}

func TestValidateRejectsAmbiguousAndOverBudgetJSON(t *testing.T) {
	objectFields := make([]string, 257)
	for index := range objectFields {
		objectFields[index] = `"key_` + strconv.Itoa(index) + `":1`
	}
	arrayItems := make([]string, 1025)
	for index := range arrayItems {
		arrayItems[index] = "1"
	}
	tests := []struct {
		name          string
		body          string
		duplicateKeys bool
	}{
		{name: "duplicate object key", body: `{"id":"first","id":"second"}`, duplicateKeys: true},
		{name: "trailing value", body: `{} {}`},
		{name: "depth", body: strings.Repeat(`{"nested":`, 33) + `"value"` + strings.Repeat(`}`, 33)},
		{name: "object keys", body: "{" + strings.Join(objectFields, ",") + "}"},
		{name: "array items", body: `[` + strings.Join(arrayItems, ",") + `]`},
		{name: "string bytes", body: `"` + strings.Repeat("x", (16<<10)+1) + `"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate([]byte(tt.body), DefaultLimits())
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() error = %v, want ErrInvalid", err)
			}
			if got := errors.Is(err, ErrDuplicateObjectKey); got != tt.duplicateKeys {
				t.Fatalf("duplicate-key marker = %t, want %t (err=%v)", got, tt.duplicateKeys, err)
			}
		})
	}
}
