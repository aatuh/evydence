package app

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// Only the published collector-creation envelope can preserve credential
// metadata. Decode into fixed public DTOs, validate the tenant/key binding,
// and project again: arbitrary objects, extra fields, hashes and secrets
// never gain an exception to generic logging/package/replay redaction.
func publicCollectorReplayMetadata(value any) (map[string]any, string, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, "", false
	}
	keyObject, ok := root["api_key"].(map[string]any)
	if !ok {
		return nil, "", false
	}
	collectorObject, ok := root["collector"].(map[string]any)
	if !ok {
		return nil, "", false
	}
	keyBytes, err := json.Marshal(keyObject)
	if err != nil {
		return nil, "", false
	}
	collectorBytes, err := json.Marshal(collectorObject)
	if err != nil {
		return nil, "", false
	}
	var key domain.APIKey
	var collector domain.Collector
	if json.Unmarshal(keyBytes, &key) != nil || json.Unmarshal(collectorBytes, &collector) != nil {
		return nil, "", false
	}
	for _, id := range []string{key.ID, key.TenantID, collector.ID, collector.TenantID, collector.APIKeyID} {
		if id == "" || len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, "", false
		}
	}
	if key.ID != collector.APIKeyID || key.TenantID != collector.TenantID || key.Name != "collector:"+collector.Name || !validCollectorType(collector.Type) || collector.Status != "active" || collector.Version == "" || collector.SchemaVersion != domain.CollectorSchemaVersion || !validCollectorScopes(key.Scopes) || !reflect.DeepEqual(key.Scopes, collector.AllowedScopes) || key.CreatedAt.IsZero() || !key.CreatedAt.Equal(collector.CreatedAt) || len(key.Prefix) != 12 || !strings.HasPrefix(key.Prefix, "evy_") {
		return nil, "", false
	}
	if prefix, err := base64.RawURLEncoding.DecodeString(key.Prefix[4:]); err != nil || len(prefix) != 6 {
		return nil, "", false
	}
	// Hash has no JSON representation. Extra input fields were intentionally
	// discarded by decoding into the exact public APIKey model.
	key.Hash = ""
	encoded, err := json.Marshal(key)
	if err != nil {
		return nil, "", false
	}
	var projected map[string]any
	if json.Unmarshal(encoded, &projected) != nil {
		return nil, "", false
	}
	safe, _ := redaction.RemoveSensitive(projected)
	return safe.(map[string]any), key.ID, true
}
