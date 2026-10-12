package app

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.LifecycleEventReader = memoryEvidenceRepository{}

// The selected parent/provenance and event page share one current typed view.
// This memory model does not establish SQL JSON shapes, work bounds or locks.
func (r memoryEvidenceRepository) PageLifecycleEvents(ctx context.Context, tenant, id string, request appquery.PageRequest, after *appquery.SortKey, guard evidencequery.EvidenceReadGuard) (evidencequery.LifecyclePage, error) {
	var empty evidencequery.LifecyclePage
	if ctx == nil || r.uow == nil || strings.TrimSpace(tenant) == "" || strings.TrimSpace(id) == "" || guard == nil {
		return empty, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	id = strings.TrimSpace(id)
	if len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
		return empty, evidencequery.ErrValidation
	}
	if err := appquery.Validate(request, after); err != nil {
		return empty, evidencequery.ErrValidation
	}
	var cursor domain.EvidenceLifecycleEvent
	if after != nil {
		cursor.ID = after.ID
		if request.Sort == appquery.SortID && after.Value != after.ID {
			return empty, evidencequery.ErrValidation
		}
		if request.Sort == appquery.SortCreatedAt {
			at, err := time.Parse(time.RFC3339Nano, after.Value)
			if err != nil || at.UTC().Format(time.RFC3339Nano) != after.Value {
				return empty, evidencequery.ErrValidation
			}
			cursor.CreatedAt = at
		}
	}
	less := func(a, b domain.EvidenceLifecycleEvent) bool {
		if request.Sort == appquery.SortCreatedAt && !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	}
	orderedBefore := func(a, b domain.EvidenceLifecycleEvent) bool {
		if request.Direction == appquery.Descending {
			return less(b, a)
		}
		return less(a, b)
	}
	var out evidencequery.LifecyclePage
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		point, err := readMemoryEvidencePoint(ctx, s, tenant, id, guard)
		if err != nil {
			return err
		}
		selected := make([]domain.EvidenceLifecycleEvent, 0, request.PageSize+1)
		for key, e := range s.EvidenceLifecycle {
			if err := ctx.Err(); err != nil {
				return err
			}
			if e.TenantID != tenant || e.EvidenceID != id || after != nil && !orderedBefore(cursor, e) {
				continue
			}
			if e.ID != key {
				return evidencequery.ErrConflict
			}
			position := sort.Search(len(selected), func(i int) bool { return orderedBefore(e, selected[i]) })
			if position >= request.PageSize+1 {
				continue
			}
			if len(selected) < request.PageSize+1 {
				selected = append(selected, domain.EvidenceLifecycleEvent{})
			}
			copy(selected[position+1:], selected[position:])
			selected[position] = e
		}
		remaining := evidencequery.MaxLifecyclePageBytes
		items := make([]evidencedomain.EvidenceLifecycleEvent, 0, len(selected))
		for _, e := range selected {
			if err := ctx.Err(); err != nil {
				return err
			}
			raw, err := memorySelectedEvidenceJSON(e, &remaining)
			if err != nil {
				return err
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var detached domain.EvidenceLifecycleEvent
			if err := decoder.Decode(&detached); err != nil {
				return evidencequery.ErrConflict
			}
			e = detached
			action, err := evidencedomain.ParseEvidenceLifecycleState(e.Action)
			if err != nil {
				return evidencequery.ErrConflict
			}
			items = append(items, evidencedomain.EvidenceLifecycleEvent{ID: e.ID, TenantID: e.TenantID, EvidenceID: e.EvidenceID, Action: action, Reason: e.Reason, Details: e.Details, ReplacementID: e.ReplacementID, ActorID: e.ActorID, SchemaVersion: e.SchemaVersion, CreatedAt: e.CreatedAt})
		}
		out = evidencequery.LifecyclePage{Point: point, Page: appquery.Result[evidencedomain.EvidenceLifecycleEvent]{Items: items}}
		if len(items) > request.PageSize {
			out.Page.Items = items[:request.PageSize]
			last := out.Page.Items[len(out.Page.Items)-1]
			key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Sort)
			out.Page.Next = &key
		}
		return ctx.Err()
	})
	if err != nil {
		return empty, err
	}
	return out, nil
}
