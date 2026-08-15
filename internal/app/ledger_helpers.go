package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func require(actor domain.Actor, scope string) error {
	if actor.TenantID == "" || (actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "") {
		return ErrUnauthorized
	}
	if requiresExplicitScope(scope) {
		if actorHasExactScope(actor, scope) {
			return nil
		}
		return ErrForbidden
	}
	if actor.HasScope(scope) || actor.HasScope(ScopeAdmin) {
		return nil
	}
	return ErrForbidden
}

func requireGrantableScopes(actor domain.Actor, scopes []string) error {
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if requiresExplicitScope(scope) && !actorHasExactScope(actor, scope) {
			return ErrForbidden
		}
	}
	return nil
}

func requiresExplicitScope(scope string) bool {
	return scope == ScopeInstanceAdmin
}

func actorHasExactScope(actor domain.Actor, scope string) bool {
	for _, got := range actor.Scopes {
		if got == scope {
			return true
		}
	}
	return false
}

func canonicalHash(item domain.EvidenceItem) (string, error) {
	item.CanonicalHash = ""
	item.ChainEntryID = ""
	item.SignatureRefs = nil
	return canonicalAnyHash(item)
}

func canonicalAnyHash(v any) (string, error) {
	body, err := json.Marshal(v)
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
	return hashBytes(body), nil
}

func hashBytes(body []byte) string {
	// codeql[go/weak-sensitive-data-hashing] SHA-256 is required here for
	// content-addressed evidence digests, not password or bearer-token storage.
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(strings.TrimPrefix(value, "sha256:")) == 64
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func secretPrefix(secret string) string {
	if len(secret) <= 12 {
		return secret
	}
	return secret[:12]
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	sort.Strings(out)
	return out
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func nonEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func subjectForArtifact(artifactID string) []domain.SubjectRef {
	if strings.TrimSpace(artifactID) == "" {
		return nil
	}
	return []domain.SubjectRef{{Type: "artifact", ID: artifactID}}
}

func IsValidation(err error) bool {
	return errors.Is(err, ErrValidation)
}

func ProblemCode(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "UNAUTHORIZED"
	case errors.Is(err, ErrForbidden):
		return "FORBIDDEN"
	case errors.Is(err, ErrNotFound):
		return "NOT_FOUND"
	case CurrentVersionConflict(err):
		return "VERSION_CONFLICT"
	case errors.Is(err, ErrConflict):
		return "CONFLICT"
	case errors.Is(err, ErrImmutable):
		return "EVIDENCE_IMMUTABLE"
	case errors.Is(err, ErrIdempotencyConflict):
		return "IDEMPOTENCY_KEY_REUSED"
	case errors.Is(err, ErrIdempotencyInProgress):
		return "IDEMPOTENCY_IN_PROGRESS"
	case errors.Is(err, ErrIdempotencyFailed):
		return "IDEMPOTENCY_REQUEST_FAILED"
	case errors.Is(err, ErrFullVerificationUnavailable):
		return "COSIGN_FULL_VERIFICATION_UNAVAILABLE"
	case errors.Is(err, ErrVerificationFailed):
		return "VERIFICATION_FAILED"
	case errors.Is(err, ErrRetryableSigning):
		return "SIGNING_PROVIDER_UNAVAILABLE"
	case errors.Is(err, ErrRateLimited):
		return "RATE_LIMITED"
	case errors.Is(err, ErrValidation):
		return "VALIDATION_FAILED"
	default:
		return "INTERNAL_ERROR"
	}
}

func CurrentVersionConflict(err error) bool {
	_, ok := CurrentRevision(err)
	return ok
}

func StatusCode(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return 401
	case errors.Is(err, ErrForbidden):
		return 403
	case errors.Is(err, ErrNotFound):
		return 404
	case errors.Is(err, ErrConflict), errors.Is(err, ErrImmutable), errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrIdempotencyInProgress), errors.Is(err, ErrIdempotencyFailed):
		return 409
	case errors.Is(err, ErrValidation):
		return 400
	case errors.Is(err, ErrFullVerificationUnavailable), errors.Is(err, ErrVerificationFailed):
		return 422
	case errors.Is(err, ErrRateLimited):
		return 429
	case errors.Is(err, ErrRetryableSigning):
		return 503
	default:
		return 500
	}
}

func SafeErrorDetail(err error) string {
	switch StatusCode(err) {
	case 500:
		return "internal server error"
	default:
		return fmt.Sprintf("%s", err)
	}
}
