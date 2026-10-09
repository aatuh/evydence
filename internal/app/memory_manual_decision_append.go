package app

import (
	"context"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Snapshot.Decisions is the projected DTO view. This models a checked append
// plus derived superseded_by changes, not SQL relationship rows or row locks.
func (r memoryDecisionRepository) AppendVulnerabilityDecision(ctx context.Context, v riskdomain.VulnerabilityDecision, expected []riskapp.ActiveDecisionHead) error {
	if !validMemoryDecisionAppend(v, expected) {
		return ErrValidation
	}
	cloned := domain.VulnerabilityDecisionFromContextModel(v)
	want := slices.Clone(expected)
	slices.SortFunc(want, func(a, b riskapp.ActiveDecisionHead) int { return strings.Compare(a.ID, b.ID) })
	return memoryGovernanceRead(ctx, r.uow, v.TenantID, v.ID, func(s *MemoryUnitOfWorkSnapshot) error {
		if _, exists := s.Decisions[v.ID]; exists {
			return ErrConflict
		}
		var finding riskapp.FindingReference
		if err := readMemoryDecisionFinding(ctx, s, v.TenantID, v.FindingID, &finding); err != nil {
			return err
		}
		if finding.ScanID != v.ScanID || finding.ReleaseID != v.ReleaseID || finding.Vulnerability != v.Vulnerability || finding.Component != v.Component || v.SBOMID != "" && (v.SBOMID != finding.SBOMID || v.SBOMComponentPURL != finding.SBOMComponentPURL || v.SBOMComponentName != finding.SBOMComponentName) {
			return ErrNotFound
		}
		ids := slices.Clone(v.EvidenceIDs)
		if v.EvidenceID != "" {
			ids = append(ids, v.EvidenceID)
		}
		for _, id := range ids {
			owner, err := memoryGovernanceEvidence(s, v.TenantID, id, s.Evidence[id].Type)
			if err != nil {
				return err
			}
			if owner.ProductID != "" && owner.ProductID != finding.ProductID || owner.ReleaseID != "" && owner.ReleaseID != v.ReleaseID {
				return ErrNotFound
			}
		}
		if v.VEXDocumentID != "" {
			d, ok := s.VEXDocuments[v.VEXDocumentID]
			if !ok || d.ID != v.VEXDocumentID || d.TenantID != v.TenantID {
				return ErrNotFound
			}
			owner, err := memoryDecisionParsedOwner(s, v.TenantID, d.EvidenceID, "vex", d.ReleaseID, d.ArtifactID)
			if err != nil {
				return err
			}
			if owner.ReleaseID != v.ReleaseID || owner.ProductID != "" && owner.ProductID != finding.ProductID {
				return ErrNotFound
			}
		}
		for _, ref := range v.SupportingRefs {
			if !memoryDecisionSupportingOwned(s, v.TenantID, finding.ProductID, v.ReleaseID, ref.Type, ref.ID) {
				return ErrNotFound
			}
		}
		var current []riskapp.ActiveDecisionHead
		if err := readMemoryActiveDecisionHeads(ctx, s, v.TenantID, v.FindingID, 129, &current); err != nil {
			return err
		}
		if len(current) != len(want) || len(current) > 128 {
			return ErrConflict
		}
		for i, h := range current {
			if h != want[i] {
				return ErrConflict
			}
		}
		if len(want) == 0 && v.Supersedes != "" || len(want) > 0 && v.Supersedes != want[0].ID {
			return ErrConflict
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// No failure-prone operation follows the first projected mutation.
		// Preserve all historical core fields; only derive the successor link.
		for _, h := range want {
			prior := s.Decisions[h.ID]
			prior.SupersededBy = v.ID
			s.Decisions[h.ID] = prior
		}
		s.Decisions[v.ID] = cloned
		return nil
	})
}

func validMemoryDecisionAppend(v riskdomain.VulnerabilityDecision, expected []riskapp.ActiveDecisionHead) bool {
	if v.Status.IsZero() || v.CreatedAt.IsZero() || v.SupersededBy != "" || len(expected) > 128 || len(v.EvidenceIDs) > 256 || len(v.SupportingRefs) > 20 {
		return false
	}
	for _, value := range []string{v.FindingID, v.ScanID, v.ReleaseID, v.Vulnerability} {
		if strings.TrimSpace(value) == "" || !memoryGovernanceText(value, 1024) {
			return false
		}
	}
	for _, value := range []string{v.Component, v.SBOMID, v.SBOMComponentPURL, v.EvidenceID, v.VEXDocumentID, v.Supersedes, v.ApprovedBy} {
		if !memoryGovernanceText(value, 1024) {
			return false
		}
	}
	for _, value := range []string{v.SBOMComponentName, v.Justification, v.ImpactStatement, v.ActionStatement} {
		if !memoryGovernanceText(value, 65536) {
			return false
		}
	}
	if strings.TrimSpace(v.Justification) == "" || !memoryGovernanceText(v.InternalNotes, 8192) || !memoryGovernanceText(v.Source, 128) || v.Source == "" || !memoryGovernanceText(v.SchemaVersion, 128) || v.SchemaVersion == "" {
		return false
	}
	for _, id := range v.EvidenceIDs {
		if id == "" || !memoryGovernanceText(id, 1024) {
			return false
		}
	}
	for _, ref := range v.SupportingRefs {
		if !riskdomain.SupportedDecisionSupportingReference(ref.Type) || ref.ID == "" || !memoryGovernanceText(ref.ID, 1024) || !memoryGovernanceText(ref.Digest, 128) || strings.TrimSpace(ref.Digest) != "" {
			return false
		}
	}
	seen := map[string]bool{}
	for _, h := range expected {
		if h.ID == "" || !memoryGovernanceText(h.ID, 1024) || h.ID == v.ID || seen[h.ID] || h.TenantID != v.TenantID || h.FindingID != v.FindingID || h.ScanID != v.ScanID || h.ReleaseID != v.ReleaseID || h.Status.IsZero() {
			return false
		}
		seen[h.ID] = true
	}
	return true
}
