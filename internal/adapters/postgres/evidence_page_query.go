package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.EvidencePageReader = (*Store)(nil)

// PageEvidence selects authorized candidate IDs before LIMIT, then rechecks
// ownership and worker provenance before metadata in one repeatable-read view.
// Selected worker proof rows may require share locks; rollback is unconditional.
func (s *Store) PageEvidence(ctx context.Context, in evidencequery.EvidencePageRequest, guard evidencequery.EvidenceReadGuard) (appquery.Result[evidencequery.EvidencePoint], error) {
	var empty appquery.Result[evidencequery.EvidencePoint]
	if s == nil || s.pool == nil || ctx == nil || in.TenantID == "" || guard == nil {
		return empty, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := appquery.Validate(in.Page, in.After); err != nil {
		return empty, err
	}
	f := in.Filter
	where, args := searchEvidenceWhere(app.EvidenceSearchPageRequest{TenantID: in.TenantID, Filter: app.EvidenceSearchInput{ProductID: f.ProductID, ProjectID: f.ProjectID, ReleaseID: f.ReleaseID, BuildID: f.BuildID, DeploymentID: f.DeploymentID, Type: f.Type, Subtype: f.Subtype, SourceSystem: f.SourceSystem, CollectorID: f.CollectorID, VerificationStatus: f.VerificationStatus, SubjectType: f.SubjectType, SubjectID: f.SubjectID, Tag: f.Tag, CreatedAfter: f.CreatedAfter, CreatedBefore: f.CreatedBefore}})
	visibility, args := evidencePageVisibilitySQL(in, args)
	where = append(where, visibility)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return empty, fmt.Errorf("begin evidence page snapshot: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	points := make([]evidencequery.EvidencePoint, 0, in.Page.PageSize)
	bytes := 0
	cursor := in.After
	for {
		candidates, err := readEvidencePageCandidates(ctx, tx, in.Page, cursor, where, args)
		if err != nil {
			return empty, err
		}
		for _, c := range candidates {
			key := appquery.RecordSortKey(c.id, c.created, in.Page.Sort)
			cursor = &key
			point, err := loadEvidencePointInTx(ctx, tx, in.TenantID, c.id, guard)
			if err != nil {
				// Visibility is a conservative candidate prefilter, not authority.
				// Suppress only an actual policy denial, never malformed provenance.
				if errors.Is(err, application.ErrForbidden) {
					continue
				}
				if errors.Is(err, evidencequery.ErrNotFound) {
					return empty, evidencequery.ErrConflict
				}
				return empty, err
			}
			if point.Item.ID != c.id || point.Item.TenantID != in.TenantID || !point.Item.CreatedAt.Equal(c.created) {
				return empty, evidencequery.ErrConflict
			}
			if len(points) == in.Page.PageSize {
				last := points[len(points)-1].Item
				key := appquery.RecordSortKey(last.ID, last.CreatedAt, in.Page.Sort)
				return appquery.Result[evidencequery.EvidencePoint]{Items: points, Next: &key}, nil
			}
			raw, err := json.Marshal(point.Item)
			if err != nil || len(raw) > evidencequery.MaxEvidencePageBytes-bytes {
				return empty, evidencequery.ErrConflict
			}
			bytes += len(raw)
			points = append(points, point)
		}
		if len(candidates) < in.Page.PageSize+1 {
			return appquery.Result[evidencequery.EvidencePoint]{Items: points}, nil
		}
	}
}

type evidencePageCandidate struct {
	id      string
	created time.Time
}

func readEvidencePageCandidates(ctx context.Context, tx pgx.Tx, page appquery.PageRequest, after *appquery.SortKey, where []string, args []any) ([]evidencePageCandidate, error) {
	where, args, orderBy, err := evidencePageWindow(page, after, append([]string(nil), where...), append([]any(nil), args...))
	if err != nil {
		return nil, err
	}
	args = append(args, page.PageSize+1)
	statement := fmt.Sprintf(`SELECT left(id,1025),created_at,octet_length(id)>1024 FROM evidence_items WHERE %s ORDER BY %s LIMIT $%d`, joinAnd(where), orderBy, len(args))
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("select evidence page identities: %w", err)
	}
	defer rows.Close()
	candidates := make([]evidencePageCandidate, 0, page.PageSize+1)
	for rows.Next() {
		var c evidencePageCandidate
		var oversized bool
		if err := rows.Scan(&c.id, &c.created, &oversized); err != nil {
			return nil, err
		}
		if oversized || strings.TrimSpace(c.id) == "" {
			return nil, evidencequery.ErrConflict
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}

// Include direct and inferred associations so an inconsistent candidate that
// appears granted reaches the current-coordinate validator, not a silent drop.
func evidencePageVisibilitySQL(in evidencequery.EvidencePageRequest, args []any) (string, []any) {
	if in.TenantWide {
		return "TRUE", args
	}
	clauses := make([]string, 0, 3)
	if len(in.AllowedProductIDs) > 0 {
		args = append(args, in.AllowedProductIDs)
		n := len(args)
		clauses = append(clauses, fmt.Sprintf(`(product_id=ANY($%[1]d::text[]) OR EXISTS(SELECT 1 FROM projects p WHERE p.tenant_id=evidence_items.tenant_id AND p.id=evidence_items.project_id AND p.product_id=ANY($%[1]d::text[])) OR EXISTS(SELECT 1 FROM releases r WHERE r.tenant_id=evidence_items.tenant_id AND r.id=evidence_items.release_id AND r.product_id=ANY($%[1]d::text[])) OR EXISTS(SELECT 1 FROM build_runs b JOIN projects p ON p.tenant_id=b.tenant_id AND p.id=b.project_id WHERE b.tenant_id=evidence_items.tenant_id AND b.id=evidence_items.build_id AND p.product_id=ANY($%[1]d::text[])) OR EXISTS(SELECT 1 FROM deployment_events d JOIN deployment_environments e ON e.tenant_id=d.tenant_id AND e.id=d.environment_id WHERE d.tenant_id=evidence_items.tenant_id AND d.id=evidence_items.deployment_id AND e.product_id=ANY($%[1]d::text[])))`, n))
	}
	if len(in.AllowedProjectIDs) > 0 {
		args = append(args, in.AllowedProjectIDs)
		n := len(args)
		clauses = append(clauses, fmt.Sprintf(`(project_id=ANY($%[1]d::text[]) OR EXISTS(SELECT 1 FROM build_runs b WHERE b.tenant_id=evidence_items.tenant_id AND b.id=evidence_items.build_id AND b.project_id=ANY($%[1]d::text[])))`, n))
	}
	if len(in.AllowedReleaseIDs) > 0 {
		args = append(args, in.AllowedReleaseIDs)
		n := len(args)
		clauses = append(clauses, fmt.Sprintf(`(release_id=ANY($%[1]d::text[]) OR EXISTS(SELECT 1 FROM build_runs b WHERE b.tenant_id=evidence_items.tenant_id AND b.id=evidence_items.build_id AND b.release_id=ANY($%[1]d::text[])) OR EXISTS(SELECT 1 FROM deployment_events d WHERE d.tenant_id=evidence_items.tenant_id AND d.id=evidence_items.deployment_id AND d.release_id=ANY($%[1]d::text[])))`, n))
	}
	if len(clauses) == 0 {
		return "FALSE", args
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}
