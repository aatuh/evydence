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
	"github.com/aatuh/evydence/internal/application"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

var _ packagequery.AnswerLibraryReader = (*Store)(nil)

// PageAnswerLibrary resolves requested filters and current parents in one
// repeatable-read snapshot. Visibility is applied before the SQL keyset limit.
func (s *Store) PageAnswerLibrary(ctx context.Context, request packagequery.AnswerLibraryPageRequest) (appquery.Result[packagequery.AnswerLibraryPoint], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, packagequery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, fmt.Errorf("begin answer library snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	filterReleaseProductID, err := validateAnswerLibraryFilters(ctx, tx, request)
	if err != nil {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, err
	}
	where := []string{
		"e.tenant_id = $1",
		"(e.product_id IS NULL OR p.id IS NOT NULL)",
		"(e.release_id IS NULL OR r.id IS NOT NULL)",
		"(e.product_id IS NULL OR e.release_id IS NULL OR e.product_id = r.product_id)",
		"(e.control_id IS NULL OR f.id IS NOT NULL)",
		`NOT EXISTS (
			SELECT 1 FROM unnest(e.evidence_ids) AS ref(id)
			LEFT JOIN evidence_items AS ev ON ev.id = ref.id AND ev.tenant_id = e.tenant_id
			WHERE ev.id IS NULL
			   OR (e.product_id IS NOT NULL AND ev.product_id IS DISTINCT FROM e.product_id)
			   OR (e.release_id IS NOT NULL AND ev.release_id IS DISTINCT FROM e.release_id)
		)`,
	}
	args := []any{request.TenantID}
	if request.Filter.QuestionID != "" {
		args = append(args, request.Filter.QuestionID)
		where = append(where, fmt.Sprintf("e.question_id = $%d", len(args)))
	}
	if request.Filter.ProductID != "" {
		args = append(args, request.Filter.ProductID)
		where = append(where, fmt.Sprintf("(p.id = $%d OR p.id IS NULL)", len(args)))
	}
	if request.Filter.ReleaseID != "" {
		args = append(args, request.Filter.ReleaseID)
		where = append(where, fmt.Sprintf("(e.release_id = $%d OR e.release_id IS NULL)", len(args)))
		args = append(args, filterReleaseProductID)
		where = append(where, fmt.Sprintf("(p.id = $%d OR p.id IS NULL)", len(args)))
	}
	if !request.TenantWide {
		args = append(args, request.AllowedProductIDs, request.AllowedReleaseIDs)
		where = append(where, fmt.Sprintf("(p.id = ANY($%d::text[]) OR e.release_id = ANY($%d::text[]))", len(args)-1, len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("e", where, args, request.Page, request.After)
	if err != nil {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT e.id, e.tenant_id, e.question_id, e.evidence_type, e.control_id,
		       e.product_id, e.release_id, e.answer, e.evidence_ids, e.limitations,
		       e.schema_version, e.created_at, p.id
		FROM questionnaire_answer_library AS e
		LEFT JOIN releases AS r ON r.id = e.release_id AND r.tenant_id = e.tenant_id
		LEFT JOIN products AS p ON p.id = COALESCE(e.product_id, r.product_id) AND p.tenant_id = e.tenant_id
		LEFT JOIN security_controls AS c ON c.id = e.control_id AND c.tenant_id = e.tenant_id
		LEFT JOIN control_frameworks AS f ON f.id = c.framework_id AND f.tenant_id = c.tenant_id
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, fmt.Errorf("page answer library: %w", err)
	}
	items := make([]packagequery.AnswerLibraryPoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		var point packagequery.AnswerLibraryPoint
		var questionID, evidenceType, controlID, productID, releaseID, effectiveProductID sql.NullString
		entry := &point.Entry
		if err := rows.Scan(&entry.ID, &entry.TenantID, &questionID, &evidenceType, &controlID,
			&productID, &releaseID, &entry.Answer, &entry.EvidenceIDs, &entry.Limitations,
			&entry.SchemaVersion, &entry.CreatedAt, &effectiveProductID); err != nil {
			rows.Close()
			return appquery.Result[packagequery.AnswerLibraryPoint]{}, fmt.Errorf("scan answer library page: %w", err)
		}
		entry.QuestionID = nullableSQLString(questionID)
		entry.EvidenceType = nullableSQLString(evidenceType)
		entry.ControlID = nullableSQLString(controlID)
		entry.ProductID = nullableSQLString(productID)
		entry.ReleaseID = nullableSQLString(releaseID)
		point.EffectiveProductID = nullableSQLString(effectiveProductID)
		items = append(items, point)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, fmt.Errorf("iterate answer library page: %w", err)
	}
	rows.Close()
	result := appquery.Result[packagequery.AnswerLibraryPoint]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1].Entry
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	if err := tx.Commit(ctx); err != nil {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, fmt.Errorf("commit answer library snapshot: %w", err)
	}
	return result, nil
}

func validateAnswerLibraryFilters(ctx context.Context, tx pgx.Tx, request packagequery.AnswerLibraryPageRequest) (string, error) {
	filter := request.Filter
	if filter.ProductID != "" {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id FROM products WHERE tenant_id = $1 AND id = $2`, request.TenantID, filter.ProductID).Scan(&id); errors.Is(err, pgx.ErrNoRows) {
			return "", packagequery.ErrNotFound
		} else if err != nil {
			return "", fmt.Errorf("resolve answer library product filter: %w", err)
		}
		if !request.TenantWide && !containsString(request.AllowedProductIDs, filter.ProductID) {
			return "", application.ErrForbidden
		}
	}
	if filter.ReleaseID != "" {
		var productID string
		if err := tx.QueryRow(ctx, `SELECT product_id FROM releases WHERE tenant_id = $1 AND id = $2`, request.TenantID, filter.ReleaseID).Scan(&productID); errors.Is(err, pgx.ErrNoRows) {
			return "", packagequery.ErrNotFound
		} else if err != nil {
			return "", fmt.Errorf("resolve answer library release filter: %w", err)
		}
		if filter.ProductID != "" && filter.ProductID != productID {
			return "", packagequery.ErrValidation
		}
		if !request.TenantWide && !containsString(request.AllowedReleaseIDs, filter.ReleaseID) && !containsString(request.AllowedProductIDs, productID) {
			return "", application.ErrForbidden
		}
		return productID, nil
	}
	return "", nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
