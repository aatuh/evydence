package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.ReleaseCandidateReader = (*Store)(nil)

// GetReleaseCandidatePoint resolves the candidate, release and product from
// one tenant-filtered statement. A dangling or cross-tenant parent is absent.
func (s *Store) GetReleaseCandidatePoint(ctx context.Context, tenantID, id string) (releasequery.ReleaseCandidatePoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return releasequery.ReleaseCandidatePoint{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasequery.ReleaseCandidatePoint{}, releasequery.ErrNotFound
	}
	point, err := scanReleaseCandidatePoint(s.pool.QueryRow(ctx, `
		SELECT c.id, c.tenant_id, c.release_id, p.id, c.name, c.state,
		       c.snapshot_hash, c.document, c.schema_version, c.revision,
		       c.created_at, c.promoted_at, c.rejected_at
		FROM release_candidates AS c
		JOIN releases AS r ON r.id = c.release_id AND r.tenant_id = c.tenant_id
		JOIN products AS p ON p.id = r.product_id AND p.tenant_id = c.tenant_id
		WHERE c.tenant_id = $1 AND c.id = $2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return releasequery.ReleaseCandidatePoint{}, releasequery.ErrNotFound
	}
	if err != nil {
		return releasequery.ReleaseCandidatePoint{}, fmt.Errorf("get release candidate point: %w", err)
	}
	return point, nil
}

// PageReleaseCandidates applies current parent and grant visibility before
// LIMIT; only one bounded SQL page is decoded into the HTTP projection.
func (s *Store) PageReleaseCandidates(ctx context.Context, request releasequery.ReleaseCandidatePageRequest) (appquery.Result[releasequery.ReleaseCandidatePoint], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, app.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, err
	}
	where := []string{"c.tenant_id = $1"}
	args := []any{request.TenantID}
	if request.ReleaseID != "" {
		args = append(args, request.ReleaseID)
		where = append(where, fmt.Sprintf("c.release_id = $%d", len(args)))
	}
	if !request.TenantWide {
		args = append(args, request.AllowedProductIDs, request.AllowedReleaseIDs)
		where = append(where, fmt.Sprintf("(p.id = ANY($%d::text[]) OR c.release_id = ANY($%d::text[]))", len(args)-1, len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("c", where, args, request.Page, request.After)
	if err != nil {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT c.id, c.tenant_id, c.release_id, p.id, c.name, c.state,
		       c.snapshot_hash, c.document, c.schema_version, c.revision,
		       c.created_at, c.promoted_at, c.rejected_at
		FROM release_candidates AS c
		JOIN releases AS r ON r.id = c.release_id AND r.tenant_id = c.tenant_id
		JOIN products AS p ON p.id = r.product_id AND p.tenant_id = c.tenant_id
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, fmt.Errorf("page release candidates: %w", err)
	}
	defer rows.Close()
	items := make([]releasequery.ReleaseCandidatePoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		point, err := scanReleaseCandidatePoint(rows)
		if err != nil {
			return appquery.Result[releasequery.ReleaseCandidatePoint]{}, fmt.Errorf("scan release candidate page: %w", err)
		}
		items = append(items, point)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, fmt.Errorf("iterate release candidate page: %w", err)
	}
	result := appquery.Result[releasequery.ReleaseCandidatePoint]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1].Candidate
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}

func scanReleaseCandidatePoint(row interface{ Scan(...any) error }) (releasequery.ReleaseCandidatePoint, error) {
	var point releasequery.ReleaseCandidatePoint
	var state string
	var document []byte
	var promotedAt, rejectedAt sql.NullTime
	candidate := &point.Candidate
	if err := row.Scan(&candidate.ID, &candidate.TenantID, &candidate.ReleaseID, &point.ProductID,
		&candidate.Name, &state, &candidate.SnapshotHash, &document, &candidate.SchemaVersion,
		&candidate.Revision, &candidate.CreatedAt, &promotedAt, &rejectedAt); err != nil {
		return releasequery.ReleaseCandidatePoint{}, err
	}
	var embedded domain.ReleaseCandidate
	if err := decodeJSON(document, &embedded); err != nil {
		return releasequery.ReleaseCandidatePoint{}, releasequery.ErrInvalidProjection
	}
	parsed, err := releasedomain.ParseReleaseCandidateState(state)
	if err != nil {
		return releasequery.ReleaseCandidatePoint{}, releasequery.ErrInvalidProjection
	}
	candidate.State = parsed
	candidate.BuildIDs = embedded.BuildIDs
	candidate.ArtifactIDs = embedded.ArtifactIDs
	candidate.SBOMIDs = embedded.SBOMIDs
	candidate.ScanIDs = embedded.ScanIDs
	candidate.VEXIDs = embedded.VEXIDs
	candidate.ContractIDs = embedded.ContractIDs
	candidate.BundleIDs = embedded.BundleIDs
	candidate.PromotedAt = nullableSQLTime(promotedAt)
	candidate.RejectedAt = nullableSQLTime(rejectedAt)
	return point, nil
}
