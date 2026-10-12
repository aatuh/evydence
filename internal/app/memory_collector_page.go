package app

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

var _ integrationquery.CollectorReader = memoryBuildRepository{}

const maxMemoryCollectorScopesBytes = 1 << 20

// Select at most page-size+1 coordinates before projecting current public
// collector metadata. This typed adapter is not SQL work/transfer or durability
// evidence; credential records are never consulted by the page reader.
func (r memoryBuildRepository) PageCollectors(ctx context.Context, req integrationquery.CollectorPageRequest) (appquery.Result[integrationdomain.Collector], error) {
	var out appquery.Result[integrationdomain.Collector]
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
		for id, v := range s.Collectors {
			if err := ctx.Err(); err != nil {
				return err
			}
			c := candidate{id: id, at: v.CreatedAt}
			if v.TenantID != req.TenantID || cursor != nil && !before(*cursor, c) {
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
		items := make([]integrationdomain.Collector, 0, len(points))
		for _, c := range points {
			if err := ctx.Err(); err != nil {
				return err
			}
			v := s.Collectors[c.id]
			if v.ID != c.id || v.ID == "" || !memoryGovernanceText(v.ID, 1024) || v.CreatedAt.IsZero() || len(v.AllowedScopes) > maxMemoryCollectorScopesBytes/3 {
				return integrationquery.ErrInvalidProjection
			}
			// Bound source strings before encoding; JSON escaping is checked too.
			size := 0
			for _, scope := range v.AllowedScopes {
				size += len(scope)
				if size > maxMemoryCollectorScopesBytes {
					return integrationquery.ErrInvalidProjection
				}
			}
			raw, err := json.Marshal(v.AllowedScopes)
			if err != nil || len(raw) > maxMemoryCollectorScopesBytes {
				return integrationquery.ErrInvalidProjection
			}
			model, err := domain.CollectorToContextModel(v)
			if err != nil {
				return integrationquery.ErrInvalidProjection
			}
			items = append(items, model)
		}
		out = appquery.Result[integrationdomain.Collector]{Items: items}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
			last := out.Items[len(out.Items)-1]
			next := appquery.RecordSortKey(last.ID, last.CreatedAt, req.Page.Sort)
			out.Next = &next
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	return out, nil
}
