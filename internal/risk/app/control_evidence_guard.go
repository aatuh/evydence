package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// The guard joins the caller's replay transaction and resolves current
// control/framework/subject coordinates and grants only. It never reads
// duplicate-link metadata, clocks or IDs and cannot append records or audits.
func (s *ControlEvidenceCommands) AuthorizeControlEvidenceLink(ctx context.Context, a identitydomain.Actor, id string, in LinkControlEvidenceInput) error {
	_, _, key, err := s.prepareControlEvidenceLink(ctx, a, id, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteControlEvidence(ctx, func(ctx context.Context, tx ControlEvidenceTransaction) error {
		return authorizeControlEvidenceLinkScope(ctx, a, key, tx)
	})
}

func authorizeControlEvidenceLinkScope(ctx context.Context, actor identitydomain.Actor, key ControlEvidenceLinkKey, tx ControlEvidenceTransaction) error {
	credential := application.AuthorizationRequest{Scope: ScopeControlsWrite, ScopeOnly: true}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := tx.Authorize(ctx, actor, credential); err != nil {
		return err
	}
	if err := tx.LockControlEvidenceTenant(ctx, actor.TenantID); err != nil {
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

	return nil
}
