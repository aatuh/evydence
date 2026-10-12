package app

import (
	"bytes"
	"encoding/json"

	"github.com/aatuh/evydence/internal/domain"
)

// Canonical audit metadata must not pass through float64 during a test-backend
// append, commit, snapshot or reopen. Decode the persisted record DTO to retain
// its JSON/time validation while detaching metadata with exact numbers.
func cloneMemoryAuditEntry(e domain.AuditChainEntry) (domain.AuditChainEntry, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return domain.AuditChainEntry{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var detached domain.AuditChainEntry
	if err := decoder.Decode(&detached); err != nil {
		return domain.AuditChainEntry{}, err
	}
	return detached, nil
}
