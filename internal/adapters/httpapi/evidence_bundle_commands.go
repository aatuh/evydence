package httpapi

import (
	"bytes"
	"encoding/json"

	"github.com/aatuh/evydence/internal/app"
)

// Export fields are optional but non-nullable in the published contract.
// encoding/json otherwise silently treats null strings and slices as omitted.
func validateEvidenceBundleExportJSON(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return app.ErrValidation
	}
	for _, name := range []string{"release_id", "evidence_ids"} {
		if bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return app.NewValidationError(app.FieldViolation{Field: "/" + name, Code: "invalid_type"})
		}
	}
	return nil
}
