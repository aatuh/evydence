package app

import (
	"context"
	"slices"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ControlEvidenceReader = memoryControlRepository{}

// This current typed page models native ownership/grant/keyset joins. It is
// not SQL work/transfer, locking or durability proof. Like native link pages,
// public metadata has no per-page byte ceiling; duplicate-command reads do.
func (r memoryControlRepository) PageControlEvidence(ctx context.Context, req riskquery.ControlEvidencePageRequest) (appquery.Result[riskquery.ControlEvidencePoint], error) {
	var out appquery.Result[riskquery.ControlEvidencePoint]
	if req.TenantWide && (len(req.AllowedProductIDs)+len(req.AllowedProjectIDs)+len(req.AllowedReleaseIDs) != 0) || !req.TenantWide && len(req.AllowedProductIDs)+len(req.AllowedProjectIDs)+len(req.AllowedReleaseIDs) == 0 {
		return out, riskquery.ErrValidation
	}
	window, err := newMemoryDeploymentPageWindow(req.Page, req.After)
	if err != nil {
		return out, err
	}
	err = memoryGovernanceRead(ctx, r.uow, req.TenantID, req.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		selectPoint := func(v domain.ControlEvidence) (riskquery.ControlEvidencePoint, bool, error) {
			var point riskquery.ControlEvidencePoint
			var found bool
			if v.TenantID != req.TenantID || req.Filter.ControlID != "" && v.ControlID != req.Filter.ControlID || req.Filter.ProductID != "" && v.ProductID != req.Filter.ProductID || req.Filter.ReleaseID != "" && v.ReleaseID != req.Filter.ReleaseID || !memoryControlParentExists(s, req.TenantID, v.ControlID) {
				return point, false, nil
			}
			if _, owned := memoryCoverageCoordinates(s, req.TenantID, application.ResourceReferences{ProductID: v.ProductID, ReleaseID: v.ReleaseID}); !owned {
				return point, false, nil
			}
			err := memoryControlSubjectCandidates(ctx, s, req.TenantID, v.SubjectType, v.SubjectID, false, func(refs application.ResourceReferences, observed time.Time) bool {
				if v.ProductID != "" && v.ProductID != refs.ProductID || v.ReleaseID != "" && v.ReleaseID != refs.ReleaseID {
					return false
				}
				visible := refs.ProductID != "" && slices.Contains(req.AllowedProductIDs, refs.ProductID) || refs.ProjectID != "" && slices.Contains(req.AllowedProjectIDs, refs.ProjectID) || refs.ReleaseID != "" && slices.Contains(req.AllowedReleaseIDs, refs.ReleaseID)
				if !req.TenantWide && !visible {
					return false
				}
				if observed.IsZero() {
					observed = v.CreatedAt
				}
				point = riskquery.ControlEvidencePoint{Link: riskdomain.ControlEvidence(v), ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, ObservedAt: observed.UTC()}
				point.Link.CreatedAt = point.Link.CreatedAt.UTC()
				found = true
				return true
			})
			return point, found, err
		}
		for id, v := range s.ControlEvidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, found, err := selectPoint(v)
			if err != nil {
				return err
			}
			if found {
				window.offer(id, v.CreatedAt)
			}
		}
		items := make([]riskquery.ControlEvidencePoint, 0, len(window.keys))
		for _, key := range window.keys {
			v := s.ControlEvidence[key.id]
			if v.ID == "" || v.ID != key.id || !memoryGovernanceText(v.ID, 1024) || v.EvidenceType == "" || v.SubjectType == "" || v.SubjectID == "" || v.Confidence == "" || v.SchemaVersion == "" || v.CreatedAt.IsZero() {
				return riskquery.ErrInvalidProjection
			}
			point, found, err := selectPoint(v)
			if err != nil {
				return err
			}
			if !found {
				return riskquery.ErrInvalidProjection
			}
			items = append(items, point)
		}
		out = appquery.Result[riskquery.ControlEvidencePoint]{Items: items, Next: window.next()}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[riskquery.ControlEvidencePoint]{}, err
	}
	return out, nil
}
