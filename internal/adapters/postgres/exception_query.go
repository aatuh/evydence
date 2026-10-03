package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ExceptionReader = (*Store)(nil)

// PageExceptions resolves a filtered release and grant-filtered exception
// points in one tenant-scoped snapshot before applying the keyset limit.
func (s *Store) PageExceptions(ctx context.Context, request riskquery.ExceptionPageRequest) (riskquery.ExceptionPage, error) {
	var empty riskquery.ExceptionPage
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedReleaseIDs) != 0) {
		return empty, riskquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return empty, riskquery.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin exception snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	result := riskquery.ExceptionPage{}
	if request.ReleaseID != "" {
		err := tx.QueryRow(ctx, `
			SELECT r.id, p.id FROM releases AS r
			JOIN products AS p ON p.id = r.product_id AND p.tenant_id = r.tenant_id
			WHERE r.tenant_id = $1 AND r.id = $2`, request.TenantID, request.ReleaseID).Scan(
			&result.FilterRelease.ID, &result.FilterRelease.ProductID)
		if errors.Is(err, pgx.ErrNoRows) {
			return empty, riskquery.ErrNotFound
		}
		if err != nil {
			return empty, fmt.Errorf("resolve exception release: %w", err)
		}
	}
	where := []string{"x.tenant_id = $1"}
	args := []any{request.TenantID}
	if request.ReleaseID != "" {
		args = append(args, request.ReleaseID)
		where = append(where, fmt.Sprintf("x.release_id = $%d", len(args)))
	}
	if !request.TenantWide {
		args = append(args, request.AllowedProductIDs, request.AllowedReleaseIDs)
		where = append(where, fmt.Sprintf("(p.id = ANY($%d::text[]) OR x.release_id = ANY($%d::text[]))", len(args)-1, len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("x", where, args, request.Page, request.After)
	if err != nil {
		return empty, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT x.id, x.tenant_id, x.release_id, p.id, x.finding_id, x.control_id,
		       x.reason, x.owner, x.expires_at, x.approved, x.approved_by,
		       x.approved_at, x.created_at
		FROM exceptions AS x
		JOIN releases AS r ON r.id = x.release_id AND r.tenant_id = x.tenant_id
		JOIN products AS p ON p.id = r.product_id AND p.tenant_id = x.tenant_id
		WHERE %s
		ORDER BY %s LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page scoped exceptions: %w", err)
	}
	defer rows.Close()
	items := make([]riskquery.ExceptionPoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		var point riskquery.ExceptionPoint
		var findingID, controlID, approvedBy sql.NullString
		var approvedAt sql.NullTime
		value := &point.Exception
		if err := rows.Scan(&value.ID, &value.TenantID, &value.ReleaseID, &point.ProductID,
			&findingID, &controlID, &value.Reason, &value.Owner, &value.ExpiresAt,
			&value.Approved, &approvedBy, &approvedAt, &value.CreatedAt); err != nil {
			return empty, fmt.Errorf("scan exception page: %w", err)
		}
		value.FindingID = nullableSQLString(findingID)
		value.ControlID = nullableSQLString(controlID)
		value.ApprovedBy = nullableSQLString(approvedBy)
		value.ApprovedAt = nullableSQLTime(approvedAt)
		items = append(items, point)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("read exception page: %w", err)
	}
	result.Page = appquery.Result[riskquery.ExceptionPoint]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Page.Items = items[:request.Page.PageSize]
		last := result.Page.Items[len(result.Page.Items)-1].Exception
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Page.Next = &key
	}
	return result, nil
}
