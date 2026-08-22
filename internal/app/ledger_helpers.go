package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func signingKeyProvider(key domain.SigningKey) string {
	if key.Provider == "" {
		return domain.SigningKeyDefaultProvider
	}
	return key.Provider
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

func ProblemCode(err error) ErrorCode {
	return DescribeProblem(err).Code
}

func CurrentVersionConflict(err error) bool {
	_, ok := CurrentRevision(err)
	return ok
}

func StatusCode(err error) int {
	return DescribeProblem(err).Status
}

func SafeErrorDetail(err error) string {
	return DescribeProblem(err).Detail
}
