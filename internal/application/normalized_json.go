package application

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// NormalizedJSONHash preserves the existing normalized-JSON hash profile:
// marshal, decode to generic JSON values, marshal again, then hash with SHA-256.
// It uses encoding/json's sorted map keys, escaping, and float64 numeric
// normalization. It is not RFC 8785/JCS or a new canonicalization version.
// Changing numeric handling would invalidate historical manifest hashes.
func NormalizedJSONHash(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return "", err
	}
	body, err = json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(body)), nil
}
