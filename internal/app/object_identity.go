package app

import (
	"mime"
	"strings"
	"unicode"
)

// ObjectKeySchemaVersion identifies the canonical tenant/object key layout.
// Changing these rules requires an explicit compatibility and migration review.
const ObjectKeySchemaVersion = "evydence-object-key.v1"

type ObjectPayloadKeyKind string

const (
	ObjectPayloadKeyStaging ObjectPayloadKeyKind = "staging"
	ObjectPayloadKeyFinal   ObjectPayloadKeyKind = "payloads"
)

// ValidateObjectTenantID rejects identifiers that can change path structure or
// produce ambiguous object namespaces. Tenant identifiers remain otherwise
// opaque to the object layer so this validation does not invent a new product
// identifier format.
func ValidateObjectTenantID(tenantID string) error {
	if tenantID == "" || tenantID != strings.TrimSpace(tenantID) || tenantID == "." || tenantID == ".." || len(tenantID) > 255 {
		return ErrValidation
	}
	for _, r := range tenantID {
		if r == '/' || r == '\\' || unicode.IsControl(r) {
			return ErrValidation
		}
	}
	return nil
}

// ValidateCanonicalObjectDigest accepts only the lowercase canonical SHA-256
// representation used in object keys and metadata.
func ValidateCanonicalObjectDigest(digest string) error {
	if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
		return ErrValidation
	}
	for _, r := range digest[len("sha256:"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ErrValidation
		}
	}
	return nil
}

// TenantObjectPrefix returns the canonical namespace prefix for one tenant.
func TenantObjectPrefix(tenantID string) (string, error) {
	if err := ValidateObjectTenantID(tenantID); err != nil {
		return "", err
	}
	return "tenants/" + tenantID + "/", nil
}

// TenantIDFromObjectKey validates the path-like object key before returning its
// tenant component. Keys are slash-separated logical identifiers, not host
// filesystem paths: backslashes, empty/dot components, controls, and surrounding
// whitespace are rejected rather than normalized.
func TenantIDFromObjectKey(key string) (string, error) {
	if key == "" || key != strings.TrimSpace(key) || strings.ContainsRune(key, '\\') {
		return "", ErrValidation
	}
	for _, r := range key {
		if unicode.IsControl(r) {
			return "", ErrValidation
		}
	}
	parts := strings.Split(key, "/")
	if len(parts) < 3 || parts[0] != "tenants" {
		return "", ErrValidation
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || part != strings.TrimSpace(part) {
			return "", ErrValidation
		}
	}
	if err := ValidateObjectTenantID(parts[1]); err != nil {
		return "", err
	}
	return parts[1], nil
}

func ValidateTenantObjectKey(tenantID, key string) error {
	if err := ValidateObjectTenantID(tenantID); err != nil {
		return err
	}
	keyTenantID, err := TenantIDFromObjectKey(key)
	if err != nil || keyTenantID != tenantID {
		return ErrValidation
	}
	return nil
}

func CanonicalObjectPayloadKey(tenantID, digest string, kind ObjectPayloadKeyKind) (string, error) {
	prefix, err := TenantObjectPrefix(tenantID)
	if err != nil {
		return "", err
	}
	if err := ValidateCanonicalObjectDigest(digest); err != nil {
		return "", err
	}
	if kind != ObjectPayloadKeyStaging && kind != ObjectPayloadKeyFinal {
		return "", ErrValidation
	}
	return prefix + string(kind) + "/sha256/" + strings.TrimPrefix(digest, "sha256:"), nil
}

func CanonicalObjectPayloadKeys(tenantID, digest string) (string, string, error) {
	stagingKey, err := CanonicalObjectPayloadKey(tenantID, digest, ObjectPayloadKeyStaging)
	if err != nil {
		return "", "", err
	}
	finalKey, err := CanonicalObjectPayloadKey(tenantID, digest, ObjectPayloadKeyFinal)
	if err != nil {
		return "", "", err
	}
	return stagingKey, finalKey, nil
}

func ParseObjectPayloadKey(key string) (tenantID, digest string, kind ObjectPayloadKeyKind, err error) {
	tenantID, err = TenantIDFromObjectKey(key)
	if err != nil {
		return "", "", "", err
	}
	parts := strings.Split(key, "/")
	if len(parts) != 5 || parts[3] != "sha256" {
		return "", "", "", ErrValidation
	}
	kind = ObjectPayloadKeyKind(parts[2])
	if kind != ObjectPayloadKeyStaging && kind != ObjectPayloadKeyFinal {
		return "", "", "", ErrValidation
	}
	digest = "sha256:" + parts[4]
	if err := ValidateCanonicalObjectDigest(digest); err != nil {
		return "", "", "", err
	}
	canonical, err := CanonicalObjectPayloadKey(tenantID, digest, kind)
	if err != nil || canonical != key {
		return "", "", "", ErrValidation
	}
	return tenantID, digest, kind, nil
}

func canonicalObjectMediaType(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "application/octet-stream", nil
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return "", ErrValidation
	}
	return mime.FormatMediaType(strings.ToLower(mediaType), params), nil
}

func ValidateObjectMediaType(value string) error {
	_, err := canonicalObjectMediaType(value)
	return err
}

func ObjectMediaTypesMatch(expected, actual string) bool {
	expectedCanonical, err := canonicalObjectMediaType(expected)
	if err != nil {
		return false
	}
	actualCanonical, err := canonicalObjectMediaType(actual)
	return err == nil && actualCanonical == expectedCanonical
}

func VerifyObjectDigestBytes(digest string, body []byte) error {
	if err := ValidateCanonicalObjectDigest(digest); err != nil || hashBytes(body) != digest {
		return ErrValidation
	}
	return nil
}

// VerifyObjectPayloadRead is the shared trust boundary for managed payload
// reads used by parsing, verification, reconciliation, and export paths.
func VerifyObjectPayloadRead(payload ObjectPayload, object Object, expectedKey string) error {
	if err := validateObjectPayload(payload); err != nil {
		return err
	}
	if expectedKey != payload.StagingKey && expectedKey != payload.FinalKey {
		return ErrValidation
	}
	if object.Key != expectedKey || object.TenantID != payload.TenantID || object.Digest != payload.Digest || int64(len(object.Bytes)) != payload.Size {
		return ErrValidation
	}
	if err := ValidateTenantObjectKey(payload.TenantID, object.Key); err != nil {
		return err
	}
	if err := VerifyObjectDigestBytes(object.Digest, object.Bytes); err != nil {
		return err
	}
	if !ObjectMediaTypesMatch(payload.MediaType, object.MediaType) {
		return ErrValidation
	}
	return nil
}
