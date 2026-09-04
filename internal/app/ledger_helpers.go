package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
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
	if item.Canonicalization == evidencedomain.EvidenceCanonicalizationProfileVersion {
		// Scope columns and relationship fields are current query projections.
		// Their append-only audited changes must not rewrite the immutable hash
		// that signatures, citations, and historical receipts can reference.
		// The creation-time origin remains bound through SubjectRefs.
		item.ProductID = ""
		item.ProjectID = ""
		item.ReleaseID = ""
		item.BuildID = ""
		item.DeploymentID = ""
		item.RelatedEvidenceRefs = nil
		item.Supersedes = ""
		item.SupersededBy = ""
	}
	return canonicalAnyHash(item)
}

func withEvidenceCanonicalOriginRefs(item domain.EvidenceItem) domain.EvidenceItem {
	for _, ref := range []domain.SubjectRef{
		{Type: "product", ID: item.ProductID},
		{Type: "project", ID: item.ProjectID},
		{Type: "release", ID: item.ReleaseID},
		{Type: "build", ID: item.BuildID},
		{Type: "deployment", ID: item.DeploymentID},
	} {
		if ref.ID == "" || hasEvidenceSubjectRef(item.SubjectRefs, ref.Type, ref.ID) {
			continue
		}
		item.SubjectRefs = append(item.SubjectRefs, ref)
	}
	return item
}

func hasEvidenceSubjectRef(refs []domain.SubjectRef, subjectType, subjectID string) bool {
	for _, ref := range refs {
		if ref.Type == subjectType && ref.ID == subjectID {
			return true
		}
	}
	return false
}

type legacyCanonicalRelationshipOrigin struct {
	ProductID           string               `json:"product_id,omitempty"`
	ProjectID           string               `json:"project_id,omitempty"`
	ReleaseID           string               `json:"release_id,omitempty"`
	BuildID             string               `json:"build_id,omitempty"`
	DeploymentID        string               `json:"deployment_id,omitempty"`
	RelatedEvidenceRefs []domain.EvidenceRef `json:"related_evidence_refs,omitempty"`
	Supersedes          string               `json:"supersedes,omitempty"`
	SupersededBy        string               `json:"superseded_by,omitempty"`
}

func evidenceForCanonicalVerification(item domain.EvidenceItem, events map[string]domain.EvidenceLifecycleEvent) (domain.EvidenceItem, error) {
	if item.Canonicalization != evidencedomain.LegacyEvidenceCanonicalizationProfileVersion {
		return item, nil
	}
	var recorded *legacyCanonicalRelationshipOrigin
	for _, event := range events {
		if event.TenantID != item.TenantID || event.EvidenceID != item.ID {
			continue
		}
		if event.SchemaVersion != evidencedomain.EvidenceRelationshipLifecycleSchemaVersion {
			continue
		}
		raw, ok := event.Details[evidencedomain.LegacyCanonicalOriginDetailKey]
		if !ok {
			continue
		}
		body, err := json.Marshal(raw)
		if err != nil {
			return domain.EvidenceItem{}, err
		}
		var origin legacyCanonicalRelationshipOrigin
		if err := json.Unmarshal(body, &origin); err != nil {
			return domain.EvidenceItem{}, err
		}
		if recorded != nil && !reflect.DeepEqual(*recorded, origin) {
			return domain.EvidenceItem{}, errors.New("conflicting legacy evidence canonical origins")
		}
		recorded = &origin
	}
	if recorded == nil {
		return item, nil
	}
	item.ProductID = recorded.ProductID
	item.ProjectID = recorded.ProjectID
	item.ReleaseID = recorded.ReleaseID
	item.BuildID = recorded.BuildID
	item.DeploymentID = recorded.DeploymentID
	item.RelatedEvidenceRefs = append([]domain.EvidenceRef(nil), recorded.RelatedEvidenceRefs...)
	item.Supersedes = recorded.Supersedes
	item.SupersededBy = recorded.SupersededBy
	return item, nil
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
