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

// encoding/json matches tagged fields case-insensitively. For strict request
// objects, reject aliases as well as null so a second spelling cannot override
// a canonical field or bypass its non-nullability check.
func validateExactNonNullableObjectFields(body []byte, names ...string) error {
	if err := validateNonNullableObjectFields(body, names...); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return app.ErrValidation
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	for name := range fields {
		if !allowed[name] {
			return app.ErrValidation
		}
	}
	return nil
}
