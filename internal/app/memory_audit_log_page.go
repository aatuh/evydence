package app

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.AuditLogReader = memoryAuditRepository{}

// Match the native adapter's encoded metadata ceiling, including lookahead.
const maxMemoryAuditMetadataBytes = 1 << 20

// This typed test model selects at most page-size+1 coordinates before copying
// selected public records. It does not establish SQL work/transfer or durability.
func (r memoryAuditRepository) PageAuditLog(ctx context.Context, req verificationquery.AuditPageRequest) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	var out appquery.Result[verificationdomain.AuditChainEntry]
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return out, err
	}
	type candidate struct {
		id    string
		at    time.Time
		index int
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
		for index, entry := range s.AuditEntries[req.TenantID] {
			if err := ctx.Err(); err != nil {
				return err
			}
			c := candidate{id: entry.ID, at: entry.OccurredAt, index: index}
			if entry.TenantID != req.TenantID || req.Filter.SubjectType != "" && entry.SubjectType != req.Filter.SubjectType || req.Filter.SubjectID != "" && entry.SubjectID != req.Filter.SubjectID || req.Filter.Since != nil && entry.OccurredAt.Before(*req.Filter.Since) || cursor != nil && !before(*cursor, c) {
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
		items := make([]verificationdomain.AuditChainEntry, 0, len(points))
		for _, c := range points {
			if err := ctx.Err(); err != nil {
				return err
			}
			if c.id == "" || !memoryGovernanceText(c.id, 1024) {
				return verificationquery.ErrInvalidProjection
			}
			entry := s.AuditEntries[req.TenantID][c.index]
			raw, err := json.Marshal(entry.Metadata)
			if err != nil || len(raw) > maxMemoryAuditMetadataBytes {
				return verificationquery.ErrInvalidProjection
			}
			value := verificationdomain.AuditChainEntry(entry)
			value.OccurredAt = value.OccurredAt.UTC()
			value.Metadata = nil
			if err := json.Unmarshal(raw, &value.Metadata); err != nil {
				return verificationquery.ErrInvalidProjection
			}
			items = append(items, value)
		}
		out = appquery.Result[verificationdomain.AuditChainEntry]{Items: items}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
			last := out.Items[len(out.Items)-1]
			next := appquery.RecordSortKey(last.ID, last.OccurredAt, req.Page.Sort)
			out.Next = &next
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	return out, nil
}
