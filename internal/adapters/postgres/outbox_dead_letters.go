package postgres

import (
	"context"
	"fmt"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.OutboxDeadLetterReader = (*Store)(nil)

// ReadOutboxDeadLettersPage seeks by binary-collated ID using a partial index. It
// selects neither tenant/subject identifiers nor payload/raw-error columns.
// The caller supplies instance authority through the Operations query service.
func (s *Store) ReadOutboxDeadLettersPage(ctx context.Context, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsquery.OutboxDeadLetter], error) {
	var empty appquery.Result[operationsquery.OutboxDeadLetter]
	if s == nil || s.pool == nil || ctx == nil {
		return empty, operationsquery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	statement, args, err := outboxDeadLetterPageSQL(page, after)
	if err != nil {
		return empty, err
	}
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("read outbox dead-letter page: %w", err)
	}
	defer rows.Close()
	result := appquery.Result[operationsquery.OutboxDeadLetter]{Items: make([]operationsquery.OutboxDeadLetter, 0, page.PageSize)}
	for rows.Next() {
		if len(result.Items) == page.PageSize {
			last := result.Items[len(result.Items)-1]
			result.Next = &appquery.SortKey{Value: last.ID, ID: last.ID}
			continue // The single lookahead is not part of this page's projection.
		}
		var item operationsquery.OutboxDeadLetter
		var terminal *time.Time
		var oversized bool
		if err := rows.Scan(&item.ID, &item.Kind, &item.Attempts, &item.MaxAttempts, &item.FailureClass, &item.FailureCode, &item.CreatedAt, &terminal, &oversized); err != nil {
			return empty, fmt.Errorf("decode outbox dead-letter page: %w", err)
		}
		item.Status, item.CreatedAt = "dead_letter", item.CreatedAt.UTC()
		if terminal != nil {
			item.TerminalAt = terminal.UTC()
		}
		if oversized || operationsquery.ValidateOutboxDeadLetter(item) != nil {
			return empty, operationsquery.ErrInvalidProjection
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("finish outbox dead-letter page: %w", err)
	}
	return result, nil
}

// Keep the executed statement available to the focused plan/seek regression.
func outboxDeadLetterPageSQL(page appquery.PageRequest, after *appquery.SortKey) (string, []any, error) {
	if err := operationsquery.ValidateOutboxDeadLetterPage(page, after); err != nil {
		return "", nil, err
	}
	direction, operator := "ASC", ">"
	if page.Direction == appquery.Descending {
		direction, operator = "DESC", "<"
	}
	where := "jobs.status = 'dead_letter'"
	args := make([]any, 0, 2)
	if after != nil {
		where += " AND jobs.id COLLATE \"C\" " + operator + " $1"
		args = append(args, after.ID)
	}
	args = append(args, page.PageSize+1)
	statement := fmt.Sprintf(`SELECT left(jobs.id,1025),left(jobs.kind,97),jobs.attempts,jobs.max_attempts,
 left(COALESCE(jobs.failure_class,''),17),left(COALESCE(jobs.failure_code,''),97),jobs.created_at,jobs.terminal_at,
 octet_length(jobs.id)>1024 OR octet_length(jobs.kind)>96 OR
 octet_length(COALESCE(jobs.failure_class,''))>16 OR octet_length(COALESCE(jobs.failure_code,''))>96
 FROM outbox_jobs jobs WHERE %s ORDER BY jobs.id COLLATE "C" %s LIMIT $%d`, where, direction, len(args))
	return statement, args, nil
}
