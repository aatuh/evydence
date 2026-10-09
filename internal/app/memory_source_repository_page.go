package app

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

var _ integrationquery.SourceRepositoryReader = memorySourceRepository{}

// Select at most page-size+1 coordinates before projecting current public
// source metadata after current parent/grant filtering. This typed adapter does not prove PostgreSQL JSON shapes,
// work/transfer or per-field byte budgets, native locks or durability.
func (r memorySourceRepository) PageSourceRepositories(ctx context.Context, req integrationquery.SourceRepositoryPageRequest) (appquery.Result[integrationquery.SourceRepositoryPoint], error) {
	var out appquery.Result[integrationquery.SourceRepositoryPoint]
	if req.TenantWide && (len(req.AllowedProductIDs) != 0 || len(req.AllowedProjectIDs) != 0) || !req.TenantWide && len(req.AllowedProductIDs) == 0 && len(req.AllowedProjectIDs) == 0 {
		return out, ErrValidation
	}
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return out, err
	}
	type candidate struct {
		id string
		at time.Time
	}
	var cursor *candidate
	if req.After != nil {
		c := candidate{id: req.After.ID}
		if req.Page.Sort == appquery.SortCreatedAt {
			at, err := time.Parse(time.RFC3339Nano, req.After.Value)
			if err != nil || at.UTC().Format(time.RFC3339Nano) != req.After.Value {
				return out, appquery.ErrInvalidCursor
			}
			c.at = at
		} else if req.After.Value != req.After.ID {
			return out, appquery.ErrInvalidCursor
		}
		cursor = &c
	}
	before := func(a, b candidate) bool {
		comparison := 0
		if req.Page.Sort == appquery.SortCreatedAt {
			comparison = a.at.Compare(b.at)
		}
		if comparison == 0 {
			comparison = strings.Compare(a.id, b.id)
		}
		if req.Page.Direction == appquery.Descending {
			return comparison > 0
		}
		return comparison < 0
	}
	err := memoryGovernanceRead(ctx, r.uow, req.TenantID, req.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		points := make([]candidate, 0, req.Page.PageSize+1)
		for id, v := range s.SourceRepositories {
			if err := ctx.Err(); err != nil {
				return err
			}
			c := candidate{id: id, at: v.CreatedAt}
			if v.TenantID != req.TenantID || req.ProjectID != "" && v.ProjectID != req.ProjectID {
				continue
			}
			product := ""
			if v.ProjectID != "" {
				p, err := memorySourceProject(s, req.TenantID, v.ProjectID)
				if err != nil {
					continue
				}
				product = p.ProductID
			}
			productAllowed := product != "" && slices.Contains(req.AllowedProductIDs, product)
			projectAllowed := v.ProjectID != "" && slices.Contains(req.AllowedProjectIDs, v.ProjectID)
			if !req.TenantWide && !productAllowed && !projectAllowed {
				continue
			}
			if cursor != nil && !before(*cursor, c) {
				continue
			}
			position := sort.Search(len(points), func(i int) bool { return before(c, points[i]) })
			if position >= req.Page.PageSize+1 {
				continue
			}
			if len(points) < req.Page.PageSize+1 {
				points = append(points, candidate{})
			}
			copy(points[position+1:], points[position:])
			points[position] = c
		}
		items := make([]integrationquery.SourceRepositoryPoint, 0, len(points))
		for _, c := range points {
			if err := ctx.Err(); err != nil {
				return err
			}
			v := s.SourceRepositories[c.id]
			if v.ID != c.id || v.ID == "" || !memoryGovernanceText(v.ID, 1024) || v.CreatedAt.IsZero() {
				return integrationquery.ErrInvalidProjection
			}
			identity, err := memorySourceIdentity(s, req.TenantID, c.id)
			if err != nil {
				return integrationquery.ErrInvalidProjection
			}
			model := integrationquery.SourceRepositoryPoint{Repository: integrationdomain.SourceRepository(v), ProductID: identity.ProductID}
			items = append(items, model)
		}
		out = appquery.Result[integrationquery.SourceRepositoryPoint]{Items: items}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
			last := out.Items[len(out.Items)-1]
			next := appquery.RecordSortKey(last.Repository.ID, last.Repository.CreatedAt, req.Page.Sort)
			out.Next = &next
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[integrationquery.SourceRepositoryPoint]{}, err
	}
	return out, nil
}
