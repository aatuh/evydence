package app

import "github.com/aatuh/evydence/internal/domain"

// Signatures contain scalar public fields only; map membership is detached.
func cloneSignatureMap(values map[string]domain.Signature) map[string]domain.Signature {
	result := make(map[string]domain.Signature, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
