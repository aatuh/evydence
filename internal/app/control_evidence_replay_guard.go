package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

// Local compatibility only: no projection refresh, duplicate-link lookup,
// clock or audit write occurs here. Native HTTP binds the focused Risk guard.
func (l *Ledger) AuthorizeControlEvidenceLink(ctx context.Context, a domain.Actor, id string, in LinkControlEvidenceInput) error {
	id, in, err := prepareLocalControlEvidenceLink(ctx, a, id, in)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeControlEvidenceLinkLocked(a, id, in)
}

// Fresh compatibility commands must refresh worker-owned projections before
// ownership lookup; replay guards deliberately consult only local state.
func prepareLocalControlEvidenceLink(ctx context.Context, a domain.Actor, id string, in LinkControlEvidenceInput) (string, LinkControlEvidenceInput, error) {
	if ctx == nil {
		return "", LinkControlEvidenceInput{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "", LinkControlEvidenceInput{}, err
	}
	if err := require(a, ScopeControlsWrite); err != nil {
		return "", LinkControlEvidenceInput{}, err
	}
	id, normalized, err := riskapp.NormalizeControlEvidenceLinkInput(id, riskapp.LinkControlEvidenceInput{EvidenceType: in.EvidenceType, SubjectType: in.SubjectType, SubjectID: in.SubjectID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Confidence: in.Confidence, Notes: in.Notes})
	if err != nil {
		return "", LinkControlEvidenceInput{}, fromRiskContextError(err)
	}
	key := riskapp.ControlEvidenceLinkKey{ControlID: id, EvidenceType: normalized.EvidenceType, SubjectType: normalized.SubjectType, SubjectID: normalized.SubjectID, ProductID: normalized.ProductID, ReleaseID: normalized.ReleaseID}
	if !riskapp.ValidControlEvidenceLinkKey(a.TenantID, key) {
		return "", LinkControlEvidenceInput{}, ErrValidation
	}
	return id, LinkControlEvidenceInput{EvidenceType: normalized.EvidenceType, SubjectType: normalized.SubjectType, SubjectID: normalized.SubjectID, ProductID: normalized.ProductID, ReleaseID: normalized.ReleaseID, Confidence: normalized.Confidence, Notes: normalized.Notes}, nil
}

func (l *Ledger) authorizeControlEvidenceLinkLocked(a domain.Actor, id string, in LinkControlEvidenceInput) error {
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	c, ok := l.controls[id]
	if !ok || c.TenantID != a.TenantID {
		return ErrNotFound
	}
	f, ok := l.frameworks[c.FrameworkID]
	if !ok || f.TenantID != a.TenantID {
		return ErrNotFound
	}
	if err := l.ensureScopeLocked(a.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return err
	}
	if in.ProductID != "" && in.ReleaseID != "" && l.releases[in.ReleaseID].ProductID != in.ProductID {
		return ErrNotFound
	}
	if !l.controlSubjectExistsLocked(a.TenantID, in.SubjectType, in.SubjectID, in.ProductID, in.ReleaseID) {
		return ErrNotFound
	}
	refs := l.refsForControlEvidenceSubjectLocked(in.SubjectType, in.SubjectID, in.ProductID, in.ReleaseID)
	return l.authorizeResourceLocked(a, ScopeControlsWrite, refs)
}
