package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.LifecycleEventReader = (*Store)(nil)

// PageLifecycleEvents resolves the ordinary evidence authorization point and
// its append-only event page in one tenant-scoped, read-only snapshot.
func (s *Store) PageLifecycleEvents(ctx context.Context, tenantID, evidenceID string, page appquery.PageRequest, after *appquery.SortKey) (evidencequery.LifecyclePage, error) {
	var empty evidencequery.LifecyclePage
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(evidenceID) == "" {
		return empty, evidencequery.ErrValidation
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, evidencequery.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin lifecycle event snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	point, err := loadEvidencePointInTx(ctx, tx, tenantID, evidenceID)
	if err != nil {
		return empty, err
	}
	where := []string{"e.tenant_id = $1", "e.evidence_id = $2"}
	args := []any{tenantID, evidenceID}
	where, args, order, err := appendCreatedAtKeyset("e", where, args, page, after)
	if err != nil {
		return empty, err
	}
	args = append(args, page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT e.id, e.tenant_id, e.evidence_id, e.action, e.reason,
		       e.details, e.replacement_id, e.actor_id, e.schema_version, e.created_at
		FROM evidence_lifecycle_events AS e
		WHERE %s
		ORDER BY %s LIMIT $%d`, strings.Join(where, " AND "), order, len(args))
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page lifecycle events: %w", err)
	}
	defer rows.Close()
	items := make([]evidencedomain.EvidenceLifecycleEvent, 0, page.PageSize+1)
	for rows.Next() {
		var event evidencedomain.EvidenceLifecycleEvent
		var action string
		var details []byte
		var replacement sql.NullString
		if err := rows.Scan(&event.ID, &event.TenantID, &event.EvidenceID,
			&action, &event.Reason, &details, &replacement, &event.ActorID,
			&event.SchemaVersion, &event.CreatedAt); err != nil {
			return empty, fmt.Errorf("scan lifecycle event page: %w", err)
		}
		state, err := evidencedomain.ParseEvidenceLifecycleState(action)
		if err != nil || json.Unmarshal(details, &event.Details) != nil {
			return empty, evidencequery.ErrConflict
		}
		event.Action = state
		event.ReplacementID = nullableSQLString(replacement)
		items = append(items, event)
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
