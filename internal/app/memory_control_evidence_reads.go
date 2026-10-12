package app

import (
	"context"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/application"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

var _ riskapp.ControlEvidenceReader = memoryControlRepository{}
var _ riskapp.ControlEvidenceArtifactGrantReader = memoryControlRepository{}

func (r memoryControlRepository) LockControlEvidenceTenant(ctx context.Context, tenant string) error {
	return r.LockControlCreationTenant(ctx, tenant)
}
func memoryControlParentExists(s *MemoryUnitOfWorkSnapshot, tenant, id string) bool {
	c, ok := s.SecurityControls[id]
	if !ok || c.ID != id || c.TenantID != tenant || c.FrameworkID == "" {
		return false
	}
	f, ok := s.ControlFrameworks[c.FrameworkID]
	return ok && f.ID == c.FrameworkID && f.TenantID == tenant
}
func (r memoryControlRepository) ControlEvidenceControlExists(ctx context.Context, tenant, id string) (bool, error) {
	var found bool
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error { found = memoryControlParentExists(s, tenant, id); return nil })
	if err != nil {
		return false, err
	}
	return found, nil
}
func (r memoryControlRepository) ReadControlEvidenceSubject(ctx context.Context, tenant string, key riskapp.ControlEvidenceSubjectKey) (riskapp.ControlEvidenceSubjectCoordinates, error) {
	var out riskapp.ControlEvidenceSubjectCoordinates
	err := memoryGovernanceRead(ctx, r.uow, tenant, key.SubjectID, func(s *MemoryUnitOfWorkSnapshot) error {
		for _, v := range []string{key.SubjectType, key.ProductID, key.ReleaseID} {
			if !memoryGovernanceText(v, 1024) {
				return ErrValidation
			}
		}
		count := 0
		err := memoryControlSubjectCandidates(ctx, s, tenant, key.SubjectType, key.SubjectID, true, func(refs application.ResourceReferences, _ time.Time) bool {
			if key.ProductID != "" && refs.ProductID != key.ProductID || key.ReleaseID != "" && refs.ReleaseID != key.ReleaseID {
				return false
			}
			count++
			out = riskapp.ControlEvidenceSubjectCoordinates{TenantID: tenant, SubjectType: key.SubjectType, SubjectID: key.SubjectID, ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}
			return key.SubjectType == "artifact" || count > 1
		})
		if err != nil {
			return err
		}
		if count == 0 {
			return ErrNotFound
		}
		if count > 1 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return riskapp.ControlEvidenceSubjectCoordinates{}, err
	}
	return out, nil
}
func (r memoryControlRepository) ReadControlEvidenceLink(ctx context.Context, tenant string, key riskapp.ControlEvidenceLinkKey) (riskdomain.ControlEvidence, bool, error) {
	var out riskdomain.ControlEvidence
	var found bool
	err := memoryGovernanceRead(ctx, r.uow, tenant, key.ControlID, func(s *MemoryUnitOfWorkSnapshot) error {
		if !riskapp.ValidControlEvidenceLinkKey(tenant, key) {
			return ErrValidation
		}
		if !memoryControlParentExists(s, tenant, key.ControlID) {
			return nil
		}
		for id, v := range s.ControlEvidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.TenantID != tenant || (riskapp.ControlEvidenceLinkKey{ControlID: v.ControlID, EvidenceType: v.EvidenceType, SubjectType: v.SubjectType, SubjectID: v.SubjectID, ProductID: v.ProductID, ReleaseID: v.ReleaseID}) != key {
				continue
			}
			if found {
				return ErrConflict
			}
			if v.ID != id || id == "" || !memoryGovernanceText(v.ID, 1024) || !memoryGovernanceText(v.Confidence, 64) || !memoryGovernanceText(v.Notes, 65536) || !memoryGovernanceText(v.SchemaVersion, 64) {
				return ErrValidation
			}
			out = riskdomain.ControlEvidence(v)
			out.CreatedAt = out.CreatedAt.UTC()
			found = true
		}
		return nil
	})
	if err != nil {
		return riskdomain.ControlEvidence{}, false, err
	}
	return out, found, nil
}
func (r memoryControlRepository) ControlEvidenceArtifactVisible(ctx context.Context, req riskapp.ControlEvidenceArtifactGrantRequest) (bool, error) {
	var visible bool
	err := memoryGovernanceRead(ctx, r.uow, req.TenantID, req.ArtifactID, func(s *MemoryUnitOfWorkSnapshot) error {
		if !riskapp.ValidControlEvidenceArtifactGrantRequest(req) {
			return ErrValidation
		}
		return memoryControlSubjectCandidates(ctx, s, req.TenantID, "artifact", req.ArtifactID, true, func(refs application.ResourceReferences, _ time.Time) bool {
			if req.ProductID != "" && refs.ProductID != req.ProductID || req.ReleaseID != "" && refs.ReleaseID != req.ReleaseID {
				return false
			}
			visible = refs.ProductID != "" && slices.Contains(req.AllowedProductIDs, refs.ProductID) || refs.ProjectID != "" && slices.Contains(req.AllowedProjectIDs, refs.ProjectID) || refs.ReleaseID != "" && slices.Contains(req.AllowedReleaseIDs, refs.ReleaseID)
			return visible
		})
	})
	if err != nil {
		return false, err
	}
	return visible, nil
}
