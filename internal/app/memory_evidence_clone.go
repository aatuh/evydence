package app

import (
	"bytes"
	"encoding/json"

	"github.com/aatuh/evydence/internal/domain"
)

// Detach the persisted DTO without rounding immutable canonical metadata or
// append-only lifecycle details. JSON and time validation remain unchanged.
func cloneMemoryEvidenceRecord[T domain.EvidenceItem | domain.EvidenceLifecycleEvent](value T) (T, error) {
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
