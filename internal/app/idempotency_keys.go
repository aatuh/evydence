package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func idempotencyActorID(actor domain.Actor) string {
	switch {
	case strings.TrimSpace(actor.KeyID) != "":
		return "api_key:" + strings.TrimSpace(actor.KeyID)
	case strings.TrimSpace(actor.UserID) != "":
		return "user:" + strings.TrimSpace(actor.UserID)
	case strings.TrimSpace(actor.CollectorID) != "":
		return "collector:" + strings.TrimSpace(actor.CollectorID)
	default:
		return "anonymous"
	}
}

func NewIdempotencyRecordKey(tenantID, actorID, method, path, key string) string {
	parts := []string{tenantID, actorID, method, path, key}
	encoded := make([]string, 0, len(parts))
	for _, part := range parts {
		encoded = append(encoded, base64.RawURLEncoding.EncodeToString([]byte(part)))
	}
	return "v2:" + strings.Join(encoded, ".")
}

func ParseIdempotencyRecordKey(value string) (IdempotencyRecordKey, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "v2:") {
		parts := strings.Split(strings.TrimPrefix(value, "v2:"), ".")
		if len(parts) != 5 {
			return IdempotencyRecordKey{}, false
		}
		decoded := make([]string, 0, len(parts))
		for _, part := range parts {
			raw, err := base64.RawURLEncoding.DecodeString(part)
			if err != nil {
				return IdempotencyRecordKey{}, false
			}
			decoded = append(decoded, string(raw))
		}
		return idempotencyRecordKeyFromParts(decoded)
	}
	return idempotencyRecordKeyFromParts(strings.Split(value, "\x00"))
}

func idempotencyRecordKeyFromParts(parts []string) (IdempotencyRecordKey, bool) {
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[4] == "" {
		return IdempotencyRecordKey{}, false
	}
	return IdempotencyRecordKey{
		TenantID:       parts[0],
		ActorID:        parts[1],
		Method:         parts[2],
		Path:           parts[3],
		IdempotencyKey: parts[4],
	}, true
}

func secretHashEqual(stored, candidate string) bool {
	if len(stored) != sha256.Size*2 || len(candidate) != sha256.Size*2 {
		return false
	}
	return hmac.Equal([]byte(stored), []byte(candidate))
}
