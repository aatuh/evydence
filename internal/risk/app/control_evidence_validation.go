package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func NormalizeControlEvidencePathID(raw string) (string, error) {
	if !validControlText(raw, 1024, true) {
		return "", ErrValidation
	}
	id := strings.TrimSpace(raw)
	if id == "" {
		return "", ErrValidation
	}
	return id, nil
}

// Raw fields are bounded before trimming; the normalized indexed tuple is
// separately bounded with the caller tenant before transactional work.
func NormalizeControlEvidenceLinkInput(rawID string, in LinkControlEvidenceInput) (string, LinkControlEvidenceInput, error) {
	id, err := NormalizeControlEvidencePathID(rawID)
	if err != nil {
		return "", LinkControlEvidenceInput{}, err
	}
	for _, v := range []string{in.EvidenceType, in.SubjectType, in.SubjectID, in.ProductID, in.ReleaseID} {
		if !validControlText(v, 1024, false) {
			return "", LinkControlEvidenceInput{}, ErrValidation
		}
	}
	if !validControlText(in.Confidence, 64, true) || !validControlText(in.Notes, 65536, false) {
		return "", LinkControlEvidenceInput{}, ErrValidation
	}
	in.EvidenceType, in.SubjectType, in.SubjectID = strings.TrimSpace(in.EvidenceType), strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	in.ProductID, in.ReleaseID, in.Confidence, in.Notes = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.Confidence), strings.TrimSpace(in.Notes)
	if in.SubjectID == "" || in.SubjectType == "" || !riskdomain.SupportedControlEvidenceType(in.EvidenceType) || !riskdomain.ValidControlConfidence(in.Confidence) {
		return "", LinkControlEvidenceInput{}, ErrValidation
	}
	if !riskdomain.SupportedControlEvidenceSubject(in.SubjectType) {
		return "", LinkControlEvidenceInput{}, ErrNotFound
	}
	return id, in, nil
}

func (s *ControlEvidenceCommands) prepareControlEvidenceLink(ctx context.Context, a identitydomain.Actor, id string, in LinkControlEvidenceInput) (string, LinkControlEvidenceInput, ControlEvidenceLinkKey, error) {
	var empty ControlEvidenceLinkKey
	if s == nil {
		return "", LinkControlEvidenceInput{}, empty, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return "", LinkControlEvidenceInput{}, empty, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeControlsWrite, ScopeOnly: true}); err != nil {
		return "", LinkControlEvidenceInput{}, empty, err
	}
	id, in, err := NormalizeControlEvidenceLinkInput(id, in)
	if err != nil {
		return "", LinkControlEvidenceInput{}, empty, err
	}
	key := ControlEvidenceLinkKey{ControlID: id, EvidenceType: in.EvidenceType, SubjectType: in.SubjectType, SubjectID: in.SubjectID, ProductID: in.ProductID, ReleaseID: in.ReleaseID}
	if !validControlTenant(a.TenantID) || !ValidControlEvidenceLinkKey(a.TenantID, key) {
		return "", LinkControlEvidenceInput{}, empty, ErrValidation
	}
	return id, in, key, nil
}
