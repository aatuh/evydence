package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.LifecycleEventReader = (*Store)(nil)

// PageLifecycleEvents resolves evidence and selected worker provenance, then
// its event page, in one tenant-scoped logically read-only snapshot.
func (s *Store) PageLifecycleEvents(ctx context.Context, tenantID, evidenceID string, page appquery.PageRequest, after *appquery.SortKey, guard evidencequery.EvidenceReadGuard) (evidencequery.LifecyclePage, error) {
	var empty evidencequery.LifecyclePage
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(evidenceID) == "" || guard == nil {
		return empty, evidencequery.ErrValidation
	}
	evidenceID = strings.TrimSpace(evidenceID)
	if len(evidenceID) > 1024 || !utf8.ValidString(evidenceID) || strings.ContainsRune(evidenceID, 0) {
		return empty, evidencequery.ErrValidation
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, evidencequery.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return empty, fmt.Errorf("begin lifecycle event snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	point, err := loadEvidencePointInTx(ctx, tx, tenantID, evidenceID, guard)
	if err != nil {
		return empty, err
	}
	where := []string{"e.tenant_id = $1", "e.evidence_id = $2"}
	args := []any{tenantID, evidenceID}
	where, args, order, err := appendCreatedAtKeyset("e", where, args, page, after)
	if err != nil {
		return empty, err
	}
	args = append(args, evidencequery.MaxLifecyclePageBytes)
	budgetParam := len(args)
	args = append(args, page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT CASE WHEN octet_length(projection.body::text) <= $%d THEN projection.body ELSE NULL END
		FROM evidence_lifecycle_events AS e
		CROSS JOIN LATERAL (SELECT jsonb_build_object(
			'id', e.id, 'tenant_id', e.tenant_id, 'evidence_id', e.evidence_id,
			'action', e.action, 'reason', e.reason, 'details', e.details,
			'replacement_id', e.replacement_id, 'actor_id', e.actor_id,
			'schema_version', e.schema_version,
			'created_at', to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
		) AS body) AS projection
		WHERE %s
		ORDER BY %s LIMIT $%d`, budgetParam, strings.Join(where, " AND "), order, len(args))
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page lifecycle events: %w", err)
	}
	defer rows.Close()
	items := make([]evidencedomain.EvidenceLifecycleEvent, 0, page.PageSize+1)
	remaining := evidencequery.MaxLifecyclePageBytes
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return empty, fmt.Errorf("scan lifecycle event page: %w", err)
		}
		if len(body) == 0 || len(body) > remaining {
			return empty, evidencequery.ErrConflict
		}
		remaining -= len(body)
		var event domain.EvidenceLifecycleEvent
		if err := json.Unmarshal(body, &event); err != nil {
			return empty, evidencequery.ErrConflict
		}
		state, err := evidencedomain.ParseEvidenceLifecycleState(event.Action)
		if err != nil {
			return empty, evidencequery.ErrConflict
		}
		items = append(items, evidencedomain.EvidenceLifecycleEvent{
			ID: event.ID, TenantID: event.TenantID, EvidenceID: event.EvidenceID,
			Action: state, Reason: event.Reason, Details: event.Details,
			ReplacementID: event.ReplacementID, ActorID: event.ActorID,
			SchemaVersion: event.SchemaVersion, CreatedAt: event.CreatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("read lifecycle event page: %w", err)
	}
	result := evidencequery.LifecyclePage{Point: point, Page: appquery.Result[evidencedomain.EvidenceLifecycleEvent]{Items: items}}
	if len(items) > page.PageSize {
		result.Page.Items = items[:page.PageSize]
		last := result.Page.Items[len(result.Page.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, page.Sort)
		result.Page.Next = &key
	}
	return result, nil
}
