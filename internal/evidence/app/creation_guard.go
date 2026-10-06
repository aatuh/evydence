package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

const MaxGenericEvidenceTextBytes = 64 << 10
const MaxGenericEvidenceListItems = 1024

// EvidenceCreationGuardTransaction exposes current ownership and grants only.
// Fresh creation separately verifies declared artifact digests and payloads.
type EvidenceCreationGuardTransaction interface {
	application.Authorizer
	ValidateScope(context.Context, string, EvidenceScope) error
	ValidateArtifactIdentity(context.Context, string, string) error
}

func validGenericEvidenceText(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// NormalizeGenericEvidenceCreation validates raw budgets before trimming or
// copying. It is not used by parser-owned document preparation.
func NormalizeGenericEvidenceCreation(in CreateEvidenceInput) (CreateEvidenceInput, error) {
	for _, v := range []string{in.ProductID, in.ProjectID, in.ReleaseID, in.BuildID, in.DeploymentID, in.CollectorID} {
		if !validGenericEvidenceText(v, 1024) {
			return CreateEvidenceInput{}, ErrValidation
		}
	}
	for _, v := range []string{in.Type, in.Subtype, in.Title, in.SourceSystem, in.PayloadRef, in.PayloadMediaType} {
		if !validGenericEvidenceText(v, MaxGenericEvidenceTextBytes) {
			return CreateEvidenceInput{}, ErrValidation
		}
	}
	if !validGenericEvidenceText(in.PayloadHash, 128) || !validDigest(strings.TrimSpace(in.PayloadHash)) || in.PayloadSize < 0 || strings.TrimSpace(in.Type) == "" || strings.TrimSpace(in.Title) == "" || isDeploymentEvent(in.Type, in.Subtype) || strings.TrimSpace(in.Type) == parserNormalizationType {
		return CreateEvidenceInput{}, ErrValidation
	}
	if len(in.SubjectRefs) > MaxGenericEvidenceListItems || len(in.Tags) > MaxGenericEvidenceListItems || len(in.Limitations) > MaxGenericEvidenceListItems {
		return CreateEvidenceInput{}, ErrValidation
	}
	for _, ref := range in.SubjectRefs {
		if !validGenericEvidenceText(ref.Type, 1024) || !validGenericEvidenceText(ref.ID, 1024) || !validGenericEvidenceText(ref.Digest, MaxGenericEvidenceTextBytes) {
			return CreateEvidenceInput{}, ErrValidation
		}
	}
	for _, values := range [][]string{in.Tags, in.Limitations} {
		for _, v := range values {
			if !validGenericEvidenceText(v, MaxGenericEvidenceTextBytes) {
				return CreateEvidenceInput{}, ErrValidation
			}
		}
	}
	for _, v := range []map[string]any{in.SourceIdentity, in.Metadata} {
		if err := validateGenericEvidenceJSON(v); err != nil {
			return CreateEvidenceInput{}, err
		}
	}
	if !in.ObservedAt.IsZero() {
		utc := in.ObservedAt.UTC()
		if utc.Year() < 1 || utc.Year() > 9999 {
			return CreateEvidenceInput{}, ErrValidation
		}
	}
	in.ProductID = strings.TrimSpace(in.ProductID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.BuildID = strings.TrimSpace(in.BuildID)
	in.DeploymentID = strings.TrimSpace(in.DeploymentID)
	var err error
	in.SubjectRefs, err = normalizeSubjectRefs(in.SubjectRefs)
	if err != nil {
		return CreateEvidenceInput{}, err
	}
	return in, nil
}

func validateGenericEvidenceJSON(v map[string]any) error {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxGenericEvidenceTextBytes {
		return ErrValidation
	}
	limits := jsonbounds.DefaultLimits()
	limits.MaxStringBytes = MaxGenericEvidenceTextBytes
	if jsonbounds.Validate(raw, limits) != nil {
		return ErrValidation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	for {
		t, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return ErrValidation
		}
		if s, ok := t.(string); ok && !validGenericEvidenceText(s, MaxGenericEvidenceTextBytes) {
			return ErrValidation
		}
	}
}

func (c *EvidenceCreationCommands) AuthorizeEvidenceCreation(ctx context.Context, a identitydomain.Actor, in CreateEvidenceInput) error {
	if c == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if !validGenericEvidenceText(a.TenantID, 1024) || a.TenantID == "" || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	if err := c.preparer.authorize(ctx, a, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return err
	}
	var err error
	in, err = NormalizeGenericEvidenceCreation(in)
	if err != nil {
		return err
	}
	scope := EvidenceScope{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, DeploymentID: in.DeploymentID}
	return c.transactions.ExecuteEvidenceCreation(ctx, func(ctx context.Context, tx EvidenceCreationTransaction) error {
		guard, ok := tx.(EvidenceCreationGuardTransaction)
		if !ok {
			return ErrValidation
		}
		if err := guard.ValidateScope(ctx, a.TenantID, scope); err != nil {
			return err
		}
		if err := guard.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: resourceReferences(scope)}); err != nil {
			return err
		}
		for _, ref := range in.SubjectRefs {
			if ref.ID == "" {
				continue
			}
			if ref.Type == "artifact" {
				if err := guard.ValidateArtifactIdentity(ctx, a.TenantID, ref.ID); err != nil {
					return err
				}
				if err := guard.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: ref.ID}}); err != nil {
					return err
				}
				continue
			}
			s, refs, err := subjectReferenceScope(ref)
			if err != nil {
				continue
			}
			if err := guard.ValidateScope(ctx, a.TenantID, s); err != nil {
				return err
			}
			if err := guard.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: refs}); err != nil {
				return err
			}
		}
		return nil
	})
}
