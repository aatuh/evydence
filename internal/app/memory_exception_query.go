package app

import (
	"context"
	"errors"
	"slices"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ExceptionReader = memoryDecisionRepository{}

func (r memoryDecisionRepository) PageExceptions(ctx context.Context, request riskquery.ExceptionPageRequest) (riskquery.ExceptionPage, error) {
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return riskquery.ExceptionPage{}, riskquery.ErrValidation
	}
	if request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedReleaseIDs) != 0) {
		return riskquery.ExceptionPage{}, riskquery.ErrValidation
	}
	var out riskquery.ExceptionPage
	err := memoryGovernanceRead(ctx, r.uow, request.TenantID, request.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		if request.ReleaseID != "" {
			refs, err := memoryOperationsCoordinates(s, request.TenantID, application.ResourceReferences{ReleaseID: request.ReleaseID})
			if err != nil {
				return err
			}
			out.FilterRelease = riskquery.ReleaseScope{ID: request.ReleaseID, ProductID: refs.ProductID}
		}
		points := []riskquery.ExceptionPoint{}
		for id, x := range s.Exceptions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if x.ID != id || x.TenantID != request.TenantID || request.ReleaseID != "" && x.ReleaseID != request.ReleaseID {
				continue
			}
			refs, err := memoryOperationsCoordinates(s, request.TenantID, application.ResourceReferences{ReleaseID: x.ReleaseID})
			if err != nil || refs.ProductID == "" {
				continue
			}
			if !request.TenantWide && !slices.Contains(request.AllowedProductIDs, refs.ProductID) && !slices.Contains(request.AllowedReleaseIDs, x.ReleaseID) {
				continue
			}
			points = append(points, riskquery.ExceptionPoint{ProductID: refs.ProductID, Exception: riskdomain.Exception{ID: id, CreatedAt: x.CreatedAt}})
		}
		page, err := appquery.Page(points, request.Page, request.After, func(p riskquery.ExceptionPoint, sort appquery.Sort) appquery.SortKey {
			return appquery.RecordSortKey(p.Exception.ID, p.Exception.CreatedAt, sort)
		})
		if err != nil {
			return err
		}
		for i, p := range page.Items {
			x := s.Exceptions[p.Exception.ID]
			for _, text := range []string{x.ID, x.ReleaseID, x.FindingID, x.ControlID, x.Owner, x.ApprovedBy} {
				if !memoryGovernanceText(text, 1024) {
					return riskquery.ErrInvalidProjection
				}
			}
			if !memoryGovernanceText(x.Reason, 65536) || x.CreatedAt.IsZero() || x.ExpiresAt.IsZero() {
				return riskquery.ErrInvalidProjection
			}
			x.ApprovedAt = cloneTimePtr(x.ApprovedAt)
			page.Items[i].Exception = riskdomain.Exception(x)
		}
		out.Page = page
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		err = riskquery.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = riskquery.ErrValidation
	}
	if err != nil {
		return riskquery.ExceptionPage{}, err
	}
	return out, nil
}
