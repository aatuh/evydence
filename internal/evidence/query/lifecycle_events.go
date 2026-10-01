package query

import (
	"context"
	"errors"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// MaxLifecyclePageBytes bounds the selected serialized event page, including
// the pagination lookahead row. The evidence/provenance snapshot has its own
// independent byte budget.
const MaxLifecyclePageBytes = 8 * 1024 * 1024

// LifecyclePage keeps the evidence authorization point and its bounded event
// page in one database snapshot, including selected worker-owned provenance.
type LifecyclePage struct {
	Point EvidencePoint
	Page  appquery.Result[evidencedomain.EvidenceLifecycleEvent]
}

type LifecycleEventReader interface {
	PageLifecycleEvents(context.Context, string, string, appquery.PageRequest, *appquery.SortKey, EvidenceReadGuard) (LifecyclePage, error)
}

type LifecycleEvents struct{ reader LifecycleEventReader }

func NewLifecycleEvents(reader LifecycleEventReader) (*LifecycleEvents, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &LifecycleEvents{reader: reader}, nil
}

func (s *LifecycleEvents) ListPage(ctx context.Context, actor identitydomain.Actor, id string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.EvidenceLifecycleEvent], error) {
	var empty appquery.Result[evidencedomain.EvidenceLifecycleEvent]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return empty, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return empty, ErrNotFound
	}
	if !validEvidenceReadID(id) {
		return empty, ErrValidation
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrValidation
	}
	result, err := s.reader.PageLifecycleEvents(ctx, actor.TenantID, id, page, after, evidenceReadGuard(ctx, actor))
	if errors.Is(err, appquery.ErrInvalidCursor) || errors.Is(err, appquery.ErrInvalidPage) {
		return empty, ErrValidation
	}
	if err != nil {
		return empty, err
	}
	if !validEvidencePoint(result.Point, actor.TenantID, id) || len(result.Page.Items) > page.PageSize {
		return empty, ErrConflict
	}
	if err := authorizeEvidenceRead(actor, result.Point, false); err != nil {
		return empty, err
	}
	for _, event := range result.Page.Items {
		if event.ID == "" || event.TenantID != actor.TenantID || event.EvidenceID != id || event.Action.IsZero() ||
			strings.TrimSpace(event.ID) != event.ID || strings.TrimSpace(event.ReplacementID) != event.ReplacementID || event.CreatedAt.IsZero() {
			return empty, ErrConflict
		}
	}
	if result.Page.Next != nil {
		if len(result.Page.Items) == 0 {
			return empty, ErrConflict
		}
		last := result.Page.Items[len(result.Page.Items)-1]
		if *result.Page.Next != appquery.RecordSortKey(last.ID, last.CreatedAt, page.Sort) {
			return empty, ErrConflict
		}
	}
	return result.Page, nil
}
