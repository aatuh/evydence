package app

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// Only the published API-key creation envelope may preserve a fixed public
// key DTO. Generic log/package redaction remains unchanged. The JSON model
// cannot serialize Hash; unknown fields and the one-time secret are dropped.
func publicAPIKeyCreationReplayMetadata(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok || len(root) > 2 {
		return nil, false
	}
	for field := range root {
		if field != "api_key" && field != "secret" {
			return nil, false
		}
	}
	object, ok := root["api_key"].(map[string]any)
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, false
	}
	var key domain.APIKey
	if json.Unmarshal(encoded, &key) != nil {
		return nil, false
	}
	for _, id := range []string{key.ID, key.TenantID} {
		if id == "" || len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	if key.Name == "" || len(key.Name) > 65536 || !utf8.ValidString(key.Name) || strings.ContainsRune(key.Name, 0) || strings.TrimSpace(key.Name) != key.Name || key.CreatedAt.IsZero() || len(key.Scopes) == 0 || len(key.Scopes) > 1024 || key.RevokedAt != nil || key.LastUsedAt != nil || len(key.Prefix) != 12 || !strings.HasPrefix(key.Prefix, "evy_") {
		return nil, false
	}
	for _, scope := range key.Scopes {
		if len(scope) > 128 || !utf8.ValidString(scope) || strings.ContainsRune(scope, 0) {
			return nil, false
		}
	}
	if raw, err := base64.RawURLEncoding.DecodeString(key.Prefix[4:]); err != nil || len(raw) != 6 {
		return nil, false
	}
	key.Hash = ""
	encoded, err = json.Marshal(key)
	if err != nil {
		return nil, false
	}
	var projected map[string]any
	if json.Unmarshal(encoded, &projected) != nil {
		return nil, false
	}
	safe, _ := redaction.RemoveSensitive(projected)
	return safe.(map[string]any), true
}
