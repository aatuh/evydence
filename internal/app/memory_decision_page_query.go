package app

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.VulnerabilityDecisionReader = memoryDecisionRepository{}

type memoryDecisionCandidate struct {
	id, product string
	created     time.Time
}

// The typed fixture retains at most PageSize+1 candidate coordinates and
// hydrates only that window. It does not model SQL transfer/work or durability.
func (r memoryDecisionRepository) PageVulnerabilityDecisions(ctx context.Context, req riskquery.DecisionPageRequest) (riskquery.DecisionPage, error) {
	var out riskquery.DecisionPage
	if !validMemoryDecisionPage(req) {
		return out, riskquery.ErrValidation
	}
	var cursor *memoryDecisionCandidate
	if req.After != nil {
		cursor = &memoryDecisionCandidate{id: req.After.ID}
		if req.Page.Sort == appquery.SortCreatedAt {
			cursor.created, _ = time.Parse(time.RFC3339Nano, req.After.Value)
		}
	}
	before := func(a, b memoryDecisionCandidate) bool {
		order := 0
		if req.Page.Sort == appquery.SortCreatedAt {
			order = a.created.Compare(b.created)
		}
		if order == 0 {
			order = strings.Compare(a.id, b.id)
		}
		if req.Page.Direction == appquery.Descending {
			return order > 0
		}
		return order < 0
	}
	err := memoryGovernanceRead(ctx, r.uow, req.TenantID, req.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		if req.Filter.ProductID != "" {
			refs, err := memoryOperationsCoordinates(s, req.TenantID, application.ResourceReferences{ProductID: req.Filter.ProductID})
			if err != nil {
				return err
			}
			out.FilterProductID = refs.ProductID
		}
		if req.Filter.ReleaseID != "" {
			refs, err := memoryOperationsCoordinates(s, req.TenantID, application.ResourceReferences{ReleaseID: req.Filter.ReleaseID})
			if err != nil {
				return err
			}
			out.FilterRelease = riskquery.ReleaseScope{ID: req.Filter.ReleaseID, ProductID: refs.ProductID}
		}
		if req.Filter.ProductID != "" && !req.TenantWide && !slices.Contains(req.AllowedProductIDs, out.FilterProductID) {
			return application.ErrForbidden
		}
		if req.Filter.ReleaseID != "" {
			if req.Filter.ProductID != "" && out.FilterRelease.ProductID != req.Filter.ProductID {
				return ErrNotFound
			}
			if !req.TenantWide && !slices.Contains(req.AllowedProductIDs, out.FilterRelease.ProductID) && !slices.Contains(req.AllowedReleaseIDs, out.FilterRelease.ID) {
				return application.ErrForbidden
			}
		}
		candidates := make([]memoryDecisionCandidate, 0, req.Page.PageSize+1)
		for id, d := range s.Decisions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.TenantID != req.TenantID || !memoryDecisionMatches(d, req.Filter) {
				continue
			}
			refs, err := memoryOperationsCoordinates(s, req.TenantID, application.ResourceReferences{ReleaseID: d.ReleaseID})
			if err != nil || refs.ProductID == "" || req.Filter.ProductID != "" && refs.ProductID != req.Filter.ProductID {
				continue
			}
			if !req.TenantWide && !slices.Contains(req.AllowedProductIDs, refs.ProductID) && !slices.Contains(req.AllowedReleaseIDs, d.ReleaseID) {
				continue
			}
			candidate := memoryDecisionCandidate{id: id, product: refs.ProductID, created: d.CreatedAt}
			if cursor != nil && !before(*cursor, candidate) {
				continue
			}
			position := sort.Search(len(candidates), func(i int) bool { return before(candidate, candidates[i]) })
			if position >= req.Page.PageSize+1 {
				continue
			}
			if len(candidates) < req.Page.PageSize+1 {
				candidates = append(candidates, memoryDecisionCandidate{})
			}
			copy(candidates[position+1:], candidates[position:])
			candidates[position] = candidate
		}
		out.Page.Items = make([]riskquery.DecisionPoint, 0, min(len(candidates), req.Page.PageSize))
		remaining := riskquery.MaxDecisionPageTextBytes
		for i, c := range candidates {
			d := s.Decisions[c.id]
			if d.ID != c.id || !memoryMembershipQueryText(d.ID, 1024) || d.CreatedAt.IsZero() {
				return riskquery.ErrInvalidProjection
			}
			d.InternalNotes = ""
			if !memoryDecisionProjectionBudget(d, c.product, &remaining) {
				return riskquery.ErrInvalidProjection
			}
			model, err := domain.VulnerabilityDecisionToContextModel(d)
			if err != nil {
				return riskquery.ErrInvalidProjection
			}
			if i == req.Page.PageSize {
				last := out.Page.Items[len(out.Page.Items)-1].Decision
				key := appquery.RecordSortKey(last.ID, last.CreatedAt, req.Page.Sort)
				out.Page.Next = &key
				break
			}
			out.Page.Items = append(out.Page.Items, riskquery.DecisionPoint{Decision: model, ProductID: c.product})
		}
		return ctx.Err()
	})
	if errors.Is(err, ErrNotFound) {
		err = riskquery.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = riskquery.ErrValidation
	}
	if err != nil {
		return riskquery.DecisionPage{}, err
	}
	return out, nil
}

func memoryDecisionMatches(d domain.VulnerabilityDecision, f riskquery.DecisionFilter) bool {
	return (f.ReleaseID == "" || d.ReleaseID == f.ReleaseID) &&
		(f.Vulnerability == "" || d.Vulnerability == f.Vulnerability) &&
		(f.Component == "" || d.Component == f.Component) &&
		(f.Status == "" || d.Status == f.Status) &&
		(f.Active == nil || *f.Active == (d.SupersededBy == ""))
}

func validMemoryDecisionPage(req riskquery.DecisionPageRequest) bool {
	if appquery.Validate(req.Page, req.After) != nil || req.TenantWide && len(req.AllowedProductIDs)+len(req.AllowedReleaseIDs) != 0 {
		return false
	}
	if req.After == nil {
		return true
	}
	if req.Page.Sort == appquery.SortID {
		return req.After.Value == req.After.ID
	}
	created, err := time.Parse(time.RFC3339Nano, req.After.Value)
	return err == nil && created.UTC().Format(time.RFC3339Nano) == req.After.Value
}
