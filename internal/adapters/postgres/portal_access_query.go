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

var _ packagequery.PortalAccessReader = (*Store)(nil)

// PagePortalAccess validates the optional package filter and pages only
// current, tenant-owned, grant-visible package links in one read-only snapshot.
// The token hash is deliberately absent from the SELECT list.
func (s *Store) PagePortalAccess(ctx context.Context, request packagequery.PortalAccessPageRequest) (appquery.Result[packagequery.PortalAccessPoint], error) {
	var empty appquery.Result[packagequery.PortalAccessPoint]
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedPackageIDs) != 0 || len(request.AllowedProductIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedPackageIDs) == 0 && len(request.AllowedProductIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return empty, packagequery.ErrPortalAccessValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin portal access snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	if request.PackageID != "" {
		var productID string
		var releaseID sql.NullString
		err := tx.QueryRow(ctx, `
			SELECT p.product_id, p.release_id
			FROM customer_security_packages AS p
			JOIN products AS pr ON pr.id = p.product_id AND pr.tenant_id = p.tenant_id
			LEFT JOIN releases AS r ON r.id = p.release_id AND r.tenant_id = p.tenant_id AND r.product_id = p.product_id
			WHERE p.tenant_id = $1 AND p.id = $2 AND (p.release_id IS NULL OR r.id IS NOT NULL)`,
			request.TenantID, request.PackageID).Scan(&productID, &releaseID)
		if errors.Is(err, pgx.ErrNoRows) {
			return empty, packagequery.ErrPortalAccessNotFound
		}
		if err != nil {
			return empty, fmt.Errorf("resolve portal access package filter: %w", err)
		}
		if !request.TenantWide && !containsString(request.AllowedPackageIDs, request.PackageID) &&
			!containsString(request.AllowedProductIDs, productID) && !containsString(request.AllowedReleaseIDs, nullableSQLString(releaseID)) {
			return empty, application.ErrForbidden
		}
	}
	where := []string{"a.tenant_id = $1", "(p.release_id IS NULL OR r.id IS NOT NULL)"}
	args := []any{request.TenantID}
	if request.PackageID != "" {
		args = append(args, request.PackageID)
		where = append(where, fmt.Sprintf("p.id = $%d", len(args)))
	}
	if !request.TenantWide {
		args = append(args, request.AllowedPackageIDs, request.AllowedProductIDs, request.AllowedReleaseIDs)
		where = append(where, fmt.Sprintf("(p.id = ANY($%d::text[]) OR p.product_id = ANY($%d::text[]) OR p.release_id = ANY($%d::text[]))", len(args)-2, len(args)-1, len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("a", where, args, request.Page, request.After)
	if err != nil {
		return empty, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT a.id, a.tenant_id, a.package_id, a.customer_name,
		       a.reviewer_name, a.reviewer_email, a.require_nda, a.nda_accepted_at,
		       a.nda_accepted_by, a.watermark, a.prefix, a.expires_at,
		       a.revoked_at, a.access_count, a.failed_access_count,
		       a.last_accessed_at, a.last_failed_at, a.schema_version, a.created_at,
		       p.product_id, p.release_id
		FROM customer_portal_access AS a
		JOIN customer_security_packages AS p ON p.id = a.package_id AND p.tenant_id = a.tenant_id
		JOIN products AS pr ON pr.id = p.product_id AND pr.tenant_id = p.tenant_id
		LEFT JOIN releases AS r ON r.id = p.release_id AND r.tenant_id = p.tenant_id AND r.product_id = p.product_id
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page portal access: %w", err)
	}
	items := make([]packagequery.PortalAccessPoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		var point packagequery.PortalAccessPoint
		var reviewerName, reviewerEmail, ndaAcceptedBy, watermark, releaseID sql.NullString
		var ndaAcceptedAt, revokedAt, lastAccessedAt, lastFailedAt sql.NullTime
		a := &point.Access
		if err := rows.Scan(&a.ID, &a.TenantID, &a.PackageID, &a.CustomerName,
			&reviewerName, &reviewerEmail, &a.RequireNDA, &ndaAcceptedAt,
			&ndaAcceptedBy, &watermark, &a.Prefix, &a.ExpiresAt,
			&revokedAt, &a.AccessCount, &a.FailedAccessCount,
			&lastAccessedAt, &lastFailedAt, &a.SchemaVersion, &a.CreatedAt,
			&point.ProductID, &releaseID); err != nil {
			rows.Close()
			return empty, fmt.Errorf("scan portal access page: %w", err)
		}
		a.ReviewerName = nullableSQLString(reviewerName)
		a.ReviewerEmail = nullableSQLString(reviewerEmail)
		a.NDAAcceptedAt = nullableSQLTime(ndaAcceptedAt)
		a.NDAAcceptedBy = nullableSQLString(ndaAcceptedBy)
		a.Watermark = nullableSQLString(watermark)
		a.RevokedAt = nullableSQLTime(revokedAt)
		a.LastAccessedAt = nullableSQLTime(lastAccessedAt)
		a.LastFailedAt = nullableSQLTime(lastFailedAt)
		point.ReleaseID = nullableSQLString(releaseID)
		items = append(items, point)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return empty, fmt.Errorf("iterate portal access page: %w", err)
	}
	rows.Close()
	result := appquery.Result[packagequery.PortalAccessPoint]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1].Access
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit portal access snapshot: %w", err)
	}
	return result, nil
}
