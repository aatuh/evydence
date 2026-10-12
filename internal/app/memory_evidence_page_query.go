package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.EvidencePageReader = memoryEvidenceRepository{}

type memoryEvidenceCandidate struct {
	id      string
	created time.Time
}

// This typed test model preserves native candidate/recheck semantics and
// bounded selection, not SQL transfer/work limits, JSON shapes or locks.
func (r memoryEvidenceRepository) PageEvidence(ctx context.Context, in evidencequery.EvidencePageRequest, guard evidencequery.EvidenceReadGuard) (appquery.Result[evidencequery.EvidencePoint], error) {
	var empty appquery.Result[evidencequery.EvidencePoint]
	if ctx == nil || r.uow == nil || guard == nil || !validMemoryEvidencePageRequest(in) {
		return empty, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var cursor *memoryEvidenceCandidate
	if in.After != nil {
		key := memoryEvidenceCandidate{id: in.After.ID}
		if in.Page.Sort == appquery.SortCreatedAt {
			key.created, _ = time.Parse(time.RFC3339Nano, in.After.Value)
		}
		cursor = &key
	}
	before := func(a, b memoryEvidenceCandidate) bool {
		comparison := 0
		if in.Page.Sort == appquery.SortCreatedAt {
			comparison = a.created.Compare(b.created)
		}
		if comparison == 0 {
			if a.id < b.id {
				comparison = -1
			} else if a.id > b.id {
				comparison = 1
			}
		}
		if in.Page.Direction == appquery.Descending {
			return comparison > 0
		}
		return comparison < 0
	}
	var out appquery.Result[evidencequery.EvidencePoint]
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		points := make([]evidencequery.EvidencePoint, 0, in.Page.PageSize)
		encodedBytes := 0
		for {
			candidates := make([]memoryEvidenceCandidate, 0, in.Page.PageSize+1)
			for id, e := range s.Evidence {
				if err := ctx.Err(); err != nil {
					return err
				}
				key := memoryEvidenceCandidate{id: id, created: e.CreatedAt}
				if e.TenantID != in.TenantID || cursor != nil && !before(*cursor, key) || !memoryEvidencePageMatches(e, in.Filter) || !memoryEvidenceCandidateVisible(s, e, in) {
					continue
				}
				position := sort.Search(len(candidates), func(i int) bool { return before(key, candidates[i]) })
				if position >= in.Page.PageSize+1 {
					continue
				}
				if len(candidates) < in.Page.PageSize+1 {
					candidates = append(candidates, memoryEvidenceCandidate{})
				}
				copy(candidates[position+1:], candidates[position:])
				candidates[position] = key
			}
			for _, c := range candidates {
				if err := ctx.Err(); err != nil {
					return err
				}
				cursor = &memoryEvidenceCandidate{id: c.id, created: c.created}
				if c.id == "" || !memoryGovernanceText(c.id, 1024) {
					return evidencequery.ErrConflict
				}
				point, err := readMemoryEvidencePoint(ctx, s, in.TenantID, c.id, guard)
				if errors.Is(err, application.ErrForbidden) {
					continue
				}
				if errors.Is(err, evidencequery.ErrNotFound) {
					return evidencequery.ErrConflict
				}
				if err != nil {
					return err
				}
				if point.Item.ID != c.id || point.Item.TenantID != in.TenantID || !point.Item.CreatedAt.Equal(c.created) {
					return evidencequery.ErrConflict
				}
				if len(points) == in.Page.PageSize {
					last := points[len(points)-1].Item
					key := appquery.RecordSortKey(last.ID, last.CreatedAt, in.Page.Sort)
					out = appquery.Result[evidencequery.EvidencePoint]{Items: points, Next: &key}
					return ctx.Err()
				}
				raw, err := json.Marshal(point.Item)
				if err != nil || len(raw) > evidencequery.MaxEvidencePageBytes-encodedBytes {
					return evidencequery.ErrConflict
				}
				encodedBytes += len(raw)
				points = append(points, point)
			}
			if len(candidates) < in.Page.PageSize+1 {
				out = appquery.Result[evidencequery.EvidencePoint]{Items: points}
				return ctx.Err()
			}
		}
	})
	if err != nil {
		return empty, err
	}
	return out, nil
}
