package jsonbounds

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidateUniqueKeysPreservesCallerBoundedJSON(t *testing.T) {
	fields := make([]string, 300)
	for index := range fields {
		fields[index] = fmt.Sprintf(`"key%d":0`, index)
	}
	for _, raw := range []string{
		`{"number":1e1000,"integer":9007199254740993}`,
		`[{"id":1},{"id":2}]`,
		`{"long":"` + strings.Repeat("x", 20<<10) + `"}`,
		"{" + strings.Join(fields, ",") + "}",
		strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40),
	} {
		if err := ValidateUniqueKeys([]byte(raw)); err != nil {
			t.Fatalf("unambiguous caller-bounded JSON rejected: %v", err)
		}
	}
}

func TestValidateUniqueKeysRejectsAmbiguousOrInvalidJSON(t *testing.T) {
	for _, raw := range []string{`{"id":1,"id":2}`, `{"nested":[{"id":1,"\u0069d":2}]}`} {
		err := ValidateUniqueKeys([]byte(raw))
		if !errors.Is(err, ErrInvalid) || !errors.Is(err, ErrDuplicateObjectKey) {
			t.Fatalf("duplicate-key diagnostic lost: %v", err)
		}
	}
	for _, raw := range []string{"", `{} null`, `{"missing":}`, `[[`, `1e`, `{"id":0,}`} {
		if !errors.Is(ValidateUniqueKeys([]byte(raw)), ErrInvalid) {
			t.Fatal("invalid JSON accepted")
		}
	}
}
