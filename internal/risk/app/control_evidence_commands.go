package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const ScopeControlsWrite = "controls:write"

type ControlEvidenceSubjectKey struct {
	SubjectType, SubjectID, ProductID, ReleaseID string
}

// Coordinates contain only current, tenant-owned subject/parent identities.
// A reader must check all parent relationships in the active transaction,
// including source-evidence relationships for parsed subjects. Supplied scopes
// are filters, never proof of ownership. Scoped artifacts require a matching
// evidence/build association. Authorization resolves matching current artifact
// associations independently, so an arbitrary projected association never
// decides a multi-associated artifact's visibility.
type ControlEvidenceSubjectCoordinates struct {
	TenantID, SubjectType, SubjectID, ProductID, ProjectID, ReleaseID string
}

type ControlEvidenceLinkKey struct {
	ControlID, EvidenceType, SubjectType, SubjectID, ProductID, ReleaseID string
}

// Reads must fence concurrent projection changes before parent locks, check
// control AND framework ownership, and use the complete duplicate natural key.
// Duplicate projections are bounded to the command's text budgets; readers
// reject overflow rather than transfer or truncate arbitrary stored notes.
type ControlEvidenceReader interface {
	ControlEvidenceControlExists(context.Context, string, string) (bool, error)
	ReadControlEvidenceSubject(context.Context, string, ControlEvidenceSubjectKey) (ControlEvidenceSubjectCoordinates, error)
	ReadControlEvidenceLink(context.Context, string, ControlEvidenceLinkKey) (riskdomain.ControlEvidence, bool, error)
}
type ControlEvidenceTransaction interface {
	ControlEvidenceReader
	// Artifact requests carry ArtifactID plus optional product/release filters.
	// Authorization must derive grants from a CURRENT association matching all
	// those filters; the supplied IDs themselves never confer authority.
	application.Authorizer
	application.AuditAppender
	InsertControlEvidence(context.Context, riskdomain.ControlEvidence) error
}
type ControlEvidenceTransactionRunner interface {
	ExecuteControlEvidence(context.Context, func(context.Context, ControlEvidenceTransaction) error) error
}
type ControlEvidenceCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ControlEvidenceTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ControlEvidenceCommands struct{ config ControlEvidenceCommandConfig }

func NewControlEvidenceCommands(config ControlEvidenceCommandConfig) (*ControlEvidenceCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ControlEvidenceCommands{config: config}, nil
}

type LinkControlEvidenceInput struct {
	EvidenceType, SubjectType, SubjectID, ProductID, ReleaseID, Confidence, Notes string
}

func (s *ControlEvidenceCommands) LinkControlEvidence(ctx context.Context, actor identitydomain.Actor, controlID string, in LinkControlEvidenceInput) (riskdomain.ControlEvidence, error) {
	if s == nil {
		return riskdomain.ControlEvidence{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return riskdomain.ControlEvidence{}, err
	}
	credential := application.AuthorizationRequest{Scope: ScopeControlsWrite, ScopeOnly: true}
	if err := s.config.Authorizer.Authorize(ctx, actor, credential); err != nil {
		return riskdomain.ControlEvidence{}, err
	}
	controlID = strings.TrimSpace(controlID)
	in.EvidenceType, in.SubjectType, in.SubjectID = strings.TrimSpace(in.EvidenceType), strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	in.ProductID, in.ReleaseID, in.Confidence, in.Notes = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.Confidence), strings.TrimSpace(in.Notes)
	key := ControlEvidenceLinkKey{ControlID: controlID, EvidenceType: in.EvidenceType, SubjectType: in.SubjectType, SubjectID: in.SubjectID, ProductID: in.ProductID, ReleaseID: in.ReleaseID}
	if !ValidControlEvidenceLinkKey(actor.TenantID, key) || !riskdomain.SupportedControlEvidenceType(in.EvidenceType) || !riskdomain.ValidControlConfidence(in.Confidence) || !validControlText(in.Notes, 65536, false) {
		return riskdomain.ControlEvidence{}, ErrValidation
	}
	// Retain the existing not-found policy for unsupported subject kinds.
	if !riskdomain.SupportedControlEvidenceSubject(in.SubjectType) {
		return riskdomain.ControlEvidence{}, ErrNotFound
	}
	var result riskdomain.ControlEvidence
	err := s.config.Transactions.ExecuteControlEvidence(ctx, func(ctx context.Context, tx ControlEvidenceTransaction) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, actor, credential); err != nil {
			return err
		}
		if exists, err := tx.ControlEvidenceControlExists(ctx, actor.TenantID, key.ControlID); err != nil {
			return err
		} else if !exists {
			return ErrNotFound
		}
		subject, err := tx.ReadControlEvidenceSubject(ctx, actor.TenantID, ControlEvidenceSubjectKey{SubjectType: key.SubjectType, SubjectID: key.SubjectID, ProductID: key.ProductID, ReleaseID: key.ReleaseID})
		if err != nil {
			return err
		}
		if subject.TenantID != actor.TenantID || subject.SubjectType != key.SubjectType || subject.SubjectID != key.SubjectID {
			return ErrNotFound
		}
		for _, text := range []string{subject.ProductID, subject.ProjectID, subject.ReleaseID} {
			if !validControlText(text, 1024, false) {
				return ErrValidation
			}
		}
		if subject.ProductID == "" && (subject.ProjectID != "" || subject.ReleaseID != "") {
			return ErrNotFound
		}
		if key.ProductID != "" && key.ProductID != subject.ProductID || key.ReleaseID != "" && key.ReleaseID != subject.ReleaseID {
			return ErrNotFound
		}
		refs := application.ResourceReferences{ProductID: subject.ProductID, ProjectID: subject.ProjectID, ReleaseID: subject.ReleaseID}
		if key.SubjectType == "artifact" {
			// Do not choose an arbitrary first artifact association and deny
			// access to another valid one. The artifact policy queries current
			// matching grants before selecting a bounded association.
			refs = application.ResourceReferences{ArtifactID: key.SubjectID, ProductID: key.ProductID, ReleaseID: key.ReleaseID}
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeControlsWrite, Resources: refs}); err != nil {
			return err
		}
		existing, found, err := tx.ReadControlEvidenceLink(ctx, actor.TenantID, key)
		if err != nil {
			return err
		}
		if found {
			if !validExistingControlEvidence(existing, actor.TenantID, key) {
				return ErrValidation
			}
			result = existing
			return nil
		}
		result = riskdomain.ControlEvidence{ID: s.config.IDs.NewID("ce"), TenantID: actor.TenantID, ControlID: key.ControlID, EvidenceType: key.EvidenceType, SubjectType: key.SubjectType, SubjectID: key.SubjectID, ProductID: key.ProductID, ReleaseID: key.ReleaseID, Confidence: in.Confidence, Notes: in.Notes, SchemaVersion: riskdomain.ControlEvidenceSchemaVersion, CreatedAt: s.config.Clock.Now().UTC()}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "control_evidence.linked", SubjectType: "control_evidence", SubjectID: result.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: result.CreatedAt}
		if !validControlText(result.ID, 1024, true) || !validControlText(audit.ID, 1024, true) || result.CreatedAt.IsZero() {
			return ErrValidation
		}
		if err := tx.InsertControlEvidence(ctx, result); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return riskdomain.ControlEvidence{}, err
	}
	return result, nil
}

// ValidControlEvidenceLinkKey bounds the indexed tuple before database work.
// Persistence adapters reuse it for direct port callers.
func ValidControlEvidenceLinkKey(tenant string, key ControlEvidenceLinkKey) bool {
	bytes := 0
	for _, field := range []struct {
		text     string
		required bool
	}{{tenant, true}, {key.ControlID, true}, {key.EvidenceType, true}, {key.SubjectType, true}, {key.SubjectID, true}, {key.ProductID, false}, {key.ReleaseID, false}} {
		if !validControlText(field.text, 1024, field.required) || len(field.text) > 2048-bytes {
			return false
		}
		bytes += len(field.text)
	}
	return true
}

func validExistingControlEvidence(v riskdomain.ControlEvidence, tenant string, key ControlEvidenceLinkKey) bool {
	return v.TenantID == tenant && (ControlEvidenceLinkKey{ControlID: v.ControlID, EvidenceType: v.EvidenceType, SubjectType: v.SubjectType, SubjectID: v.SubjectID, ProductID: v.ProductID, ReleaseID: v.ReleaseID}) == key && validControlText(v.ID, 1024, true) && riskdomain.ValidControlConfidence(v.Confidence) && validControlText(v.Notes, 65536, false) && v.SchemaVersion == riskdomain.ControlEvidenceSchemaVersion && !v.CreatedAt.IsZero()
}
