package app

import (
	"bytes"
	"encoding/json"

	"github.com/aatuh/evydence/internal/domain"
)

// Detach recorded evidence/build identity and append-only lifecycle details
// without numeric rounding. JSON and time validation remain unchanged.
func cloneMemoryCanonicalRecord[T domain.EvidenceItem | domain.EvidenceLifecycleEvent | domain.BuildRun](value T) (T, error) {
	var detached T
	raw, err := json.Marshal(value)
	if err != nil {
		return detached, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&detached); err != nil {
		var zero T
		return zero, err
	}
	return detached, nil
}
