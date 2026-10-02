package httpapi

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/aatuh/evydence/internal/app"
)

// Use after decodeJSON for optional fields that are non-nullable in the
// published contract. encoding/json otherwise treats null as omission.
func validateNonNullableObjectFields(body []byte, names ...string) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return app.ErrValidation
	}
	for _, name := range names {
		if bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return app.NewValidationError(app.FieldViolation{Field: "/" + name, Code: "invalid_type"})
		}
	}
	return nil
}

func validateNonNullableArrayItems(body []byte, name string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return app.ErrValidation
	}
	if fields[name] == nil {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(fields[name], &items); err != nil {
		return app.ErrValidation
	}
	for i, item := range items {
		if bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
			return app.NewValidationError(app.FieldViolation{Field: "/" + name + "/" + strconv.Itoa(i), Code: "invalid_type"})
		}
	}
	return nil
}
