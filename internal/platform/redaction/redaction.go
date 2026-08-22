// Package redaction provides the single denylist used at process-output
// boundaries. It deliberately operates on JSON-shaped values, so callers can
// safely use it for logs, errors, package metadata, reports, and replay data
// without teaching each transport its own secret vocabulary.
package redaction

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	Redacted           = "[REDACTED]"
	Truncated          = "[TRUNCATED]"
	MaxDiagnosticBytes = 64 << 10
)

var (
	databaseURLPattern     = regexp.MustCompile(`(?i)\bpostgres(?:ql)?://[^\s,;]+`)
	credentialURLPattern   = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)([^\s/@]+(?::[^\s@/]*)?)(@)`)
	sensitiveValuePattern  = regexp.MustCompile(`(?i)(\b[a-z0-9_.-]*(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session(?:[_-]?id|[_-]?token)?|bearer|token|secret|password|credential|cookie|private[_-]?key|database[_-]?(?:url|dsn)|connection[_-]?string|reviewer[_-]?(?:email|name)|customer[_-]?(?:email|name)|email|address|ip[_-]?address)[a-z0-9_.-]*\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+`)
	emailPattern           = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	objectReferencePattern = regexp.MustCompile(`(?i)\b(?:s3|gs|az|object)://[^\s,;]+`)
	// Standalone bearer values are redacted only when they look like opaque
	// credentials. This avoids treating explanatory prose such as "bearer
	// tokens are excluded" as a secret while Authorization headers remain
	// redacted by sensitiveValuePattern regardless of token length.
	bearerPattern     = regexp.MustCompile(`(?i)(\bbearer\s+)[a-z0-9._~+/-]{16,}`)
	privateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)
)

// IsSensitiveField identifies fields that must never be serialized outside a
// narrowly scoped one-time secret return. The classification covers secret
// material, credentials, internal evidence references, and direct PII fields.
func IsSensitiveField(key string) bool {
	normalized := normalizeKey(key)
	if normalized == "" {
		return false
	}
	for _, fragment := range []string{"secret", "password", "credential", "private_key", "privatekey", "signing_key", "signing_material", "key_material", "bearer", "token", "cookie", "authorization", "api_key", "apikey", "database_url", "database_dsn", "connection_string", "dsn", "payload_ref", "payload_reference", "raw_payload", "object_key", "object_store", "internal_note", "internal_notes", "internal_url"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	switch normalized {
	case "email", "reviewer_email", "customer_email", "customer_name", "reviewer_name", "address", "ip_address":
		return true
	default:
		return false
	}
}

// Sanitize replaces sensitive JSON fields and credential-like strings while
// preserving the surrounding shape for safe diagnostics and metrics.
func Sanitize(value any) any {
	safe, _ := sanitize(value, false)
	return safe
}

// RemoveSensitive removes sensitive JSON fields. It is suited to persisted
// replay responses and customer-delivery packages, where even a redacted field
// name should not be retained.
func RemoveSensitive(value any) (any, bool) {
	return sanitize(value, true)
}

// FirstSensitivePath returns a JSON-pointer-like field path without returning
// the underlying value. It is safe for internal validation diagnostics.
func FirstSensitivePath(value any) (string, bool) {
	return firstSensitivePath(value, "")
}

// Marshal serializes a sanitized JSON-shaped value.
func Marshal(value any) ([]byte, error) {
	return json.Marshal(Sanitize(value))
}

// MarshalIndent serializes a sanitized JSON-shaped value in a deterministic
// human-readable form appropriate for scoped artifacts.
func MarshalIndent(value any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(Sanitize(value), prefix, indent)
}

// Error returns a safe diagnostic string. It is intentionally a string rather
// than an error wrapper so callers cannot accidentally unwrap and log the raw
// provider, database, or filesystem error later.
func Error(err error) string {
	if err == nil {
		return ""
	}
	return RedactString(err.Error())
}

// RedactString removes credentials embedded in a free-form error or log
// message while retaining non-secret destination and operation context.
func RedactString(value string) string {
	truncated := len(value) > MaxDiagnosticBytes
	if truncated {
		value = value[:MaxDiagnosticBytes]
	}
	value = privateKeyPattern.ReplaceAllString(value, Redacted)
	value = databaseURLPattern.ReplaceAllString(value, Redacted)
	value = credentialURLPattern.ReplaceAllString(value, "${1}"+Redacted+"${3}")
	value = sensitiveValuePattern.ReplaceAllString(value, "${1}"+Redacted)
	value = objectReferencePattern.ReplaceAllString(value, Redacted)
	value = emailPattern.ReplaceAllString(value, Redacted)
	value = bearerPattern.ReplaceAllString(value, "${1}"+Redacted)
	value = strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
	if truncated {
		value += " " + Truncated
	}
	return value
}

func sanitize(value any, remove bool) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		changed := false
		for key, nested := range typed {
			if IsSensitiveField(key) {
				changed = true
				if !remove {
					result[key] = Redacted
				}
				continue
			}
			safe, nestedChanged := sanitize(nested, remove)
			changed = changed || nestedChanged
			result[key] = safe
		}
		if !changed {
			return value, false
		}
		return result, true
	case map[string]string:
		result := make(map[string]string, len(typed))
		changed := false
		for key, nested := range typed {
			if IsSensitiveField(key) {
				changed = true
				if !remove {
					result[key] = Redacted
				}
				continue
			}
			safe := RedactString(nested)
			changed = changed || safe != nested
			result[key] = safe
		}
		if !changed {
			return value, false
		}
		return result, true
	case []any:
		var result []any
		changed := false
		for index, nested := range typed {
			safe, nestedChanged := sanitize(nested, remove)
			if nestedChanged && result == nil {
				result = append([]any(nil), typed...)
			}
			if result != nil {
				result[index] = safe
			}
			changed = changed || nestedChanged
		}
		if !changed {
			return value, false
		}
		return result, true
	case []string:
		var result []string
		for index, nested := range typed {
			safe := RedactString(nested)
			if safe != nested && result == nil {
				result = append([]string(nil), typed...)
			}
			if result != nil {
				result[index] = safe
			}
		}
		if result == nil {
			return value, false
		}
		return result, true
	case []byte:
		if len(typed) == 0 {
			return value, false
		}
		return Redacted, true
	case string:
		safe := RedactString(typed)
		return safe, safe != typed
	case json.RawMessage:
		var decoded any
		if err := json.Unmarshal(typed, &decoded); err != nil {
			return Redacted, true
		}
		safe, changed := sanitize(decoded, remove)
		if !changed {
			return value, false
		}
		encoded, err := json.Marshal(safe)
		if err != nil {
			return Redacted, true
		}
		return json.RawMessage(encoded), true
	default:
		decoded, ok := decodeJSONShapedValue(value)
		if !ok {
			return value, false
		}
		safe, changed := sanitize(decoded, remove)
		if !changed {
			return value, false
		}
		return safe, true
	}
}

func decodeJSONShapedValue(value any) (any, bool) {
	if value == nil {
		return nil, false
	}
	kind := reflect.TypeOf(value).Kind()
	switch kind {
	case reflect.Array, reflect.Map, reflect.Pointer, reflect.Slice, reflect.Struct:
	default:
		return nil, false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return Redacted, true
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return Redacted, true
	}
	return decoded, true
}

func normalizeKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(key)
	return strings.Trim(key, "_")
}

func firstSensitivePath(value any, path string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			next := path + "/" + key
			if IsSensitiveField(key) {
				return next, true
			}
			if nested, ok := firstSensitivePath(typed[key], next); ok {
				return nested, true
			}
		}
	case map[string]string:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			next := path + "/" + key
			if IsSensitiveField(key) || RedactString(typed[key]) != typed[key] {
				return next, true
			}
		}
	case []any:
		for index, nested := range typed {
			if nestedPath, ok := firstSensitivePath(nested, path+"/"+strconv.Itoa(index)); ok {
				return nestedPath, true
			}
		}
	case []string:
		for index, nested := range typed {
			if RedactString(nested) != nested {
				return path + "/" + strconv.Itoa(index), true
			}
		}
	case string:
		if RedactString(typed) != typed {
			return path, true
		}
	default:
		if decoded, ok := decodeJSONShapedValue(value); ok {
			return firstSensitivePath(decoded, path)
		}
	}
	return "", false
}
