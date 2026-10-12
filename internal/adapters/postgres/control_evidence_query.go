package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ControlEvidenceReader = (*Store)(nil)

// PageControlEvidence resolves a current tenant-owned subject and its scope
// before applying the SQL keyset limit. Stored link coordinates alone never
// authorize a scoped human read.
func (s *Store) PageControlEvidence(ctx context.Context, request riskquery.ControlEvidencePageRequest) (appquery.Result[riskquery.ControlEvidencePoint], error) {
	if s == nil || s.pool == nil {
		return appquery.Result[riskquery.ControlEvidencePoint]{}, riskquery.ErrValidation
	}
	return pageControlEvidence(ctx, s.pool, request, "", "", "")
}

type controlEvidenceQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func pageControlEvidence(ctx context.Context, queryer controlEvidenceQueryer, request riskquery.ControlEvidencePageRequest, scopeFrameworkID, scopeProductID, scopeReleaseID string) (appquery.Result[riskquery.ControlEvidencePoint], error) {
	var empty appquery.Result[riskquery.ControlEvidencePoint]
	if queryer == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" ||
		request.TenantWide && (len(request.AllowedProductIDs) != 0 || len(request.AllowedProjectIDs) != 0 || len(request.AllowedReleaseIDs) != 0) ||
		!request.TenantWide && len(request.AllowedProductIDs) == 0 && len(request.AllowedProjectIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
		return empty, riskquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return empty, err
	}
	where := []string{"l.tenant_id = $1", "(l.product_id IS NULL OR lp.id IS NOT NULL)", "(l.release_id IS NULL OR lr.id IS NOT NULL)", "(l.product_id IS NULL OR l.release_id IS NULL OR lr.product_id = lp.id)"}
	args := []any{request.TenantID, request.TenantWide, request.AllowedProductIDs, request.AllowedProjectIDs, request.AllowedReleaseIDs}
	if scopeFrameworkID != "" {
		args = append(args, scopeFrameworkID)
		where = append(where, fmt.Sprintf("f.id = $%d", len(args)))
	}
	if request.Filter.ControlID != "" {
		args = append(args, request.Filter.ControlID)
		where = append(where, fmt.Sprintf("l.control_id = $%d", len(args)))
	}
	if request.Filter.ProductID != "" {
		args = append(args, request.Filter.ProductID)
		where = append(where, fmt.Sprintf("l.product_id = $%d", len(args)))
	}
	if request.Filter.ReleaseID != "" {
		args = append(args, request.Filter.ReleaseID)
		where = append(where, fmt.Sprintf("l.release_id = $%d", len(args)))
	}
	if scopeProductID != "" {
		args = append(args, scopeProductID)
		where = append(where, fmt.Sprintf("(subject.product_id IS NULL OR subject.product_id = $%d)", len(args)))
		where = append(where, fmt.Sprintf("(l.product_id IS NULL OR l.product_id = $%d)", len(args)))
	}
	if scopeReleaseID != "" {
		args = append(args, scopeReleaseID)
		where = append(where, fmt.Sprintf("(subject.release_id IS NULL OR subject.release_id = $%d)", len(args)))
		where = append(where, fmt.Sprintf("(l.release_id IS NULL OR l.release_id = $%d)", len(args)))
	}
	where, args, order, err := appendCreatedAtKeyset("l", where, args, request.Page, request.After)
	if err != nil {
		return empty, err
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		WITH valid_projects AS NOT MATERIALIZED (
			SELECT p.* FROM projects AS p
			JOIN products AS owner ON owner.id = p.product_id AND owner.tenant_id = p.tenant_id
		), valid_releases AS NOT MATERIALIZED (
			SELECT r.* FROM releases AS r
			JOIN products AS owner ON owner.id = r.product_id AND owner.tenant_id = r.tenant_id
		), valid_evidence AS NOT MATERIALIZED (
			SELECT e.*, COALESCE(e.product_id, p.product_id, r.product_id) AS effective_product_id
			FROM evidence_items AS e
			LEFT JOIN products AS ep ON ep.id = e.product_id AND ep.tenant_id = e.tenant_id
			LEFT JOIN valid_projects AS p ON p.id = e.project_id AND p.tenant_id = e.tenant_id
			LEFT JOIN valid_releases AS r ON r.id = e.release_id AND r.tenant_id = e.tenant_id
			WHERE (e.product_id IS NULL OR ep.id IS NOT NULL)
			  AND (e.project_id IS NULL OR p.id IS NOT NULL)
			  AND (e.release_id IS NULL OR r.id IS NOT NULL)
			  AND (e.product_id IS NULL OR p.id IS NULL OR e.product_id = p.product_id)
			  AND (e.product_id IS NULL OR r.id IS NULL OR e.product_id = r.product_id)
			  AND (p.id IS NULL OR r.id IS NULL OR p.product_id = r.product_id)
		)
		SELECT l.id, l.tenant_id, l.control_id, l.evidence_type,
		       l.subject_type, l.subject_id, l.product_id, l.release_id,
		       l.confidence, l.notes, l.schema_version, l.created_at,
		       subject.product_id, subject.project_id, subject.release_id,
		       COALESCE(subject.observed_at, l.created_at)
		FROM control_evidence AS l
		JOIN security_controls AS c ON c.id = l.control_id AND c.tenant_id = l.tenant_id
		JOIN control_frameworks AS f ON f.id = c.framework_id AND f.tenant_id = c.tenant_id
		LEFT JOIN products AS lp ON lp.id = l.product_id AND lp.tenant_id = l.tenant_id
		LEFT JOIN valid_releases AS lr ON lr.id = l.release_id AND lr.tenant_id = l.tenant_id
		JOIN LATERAL (
			SELECT candidate.product_id, candidate.project_id, candidate.release_id, candidate.observed_at
			FROM (
				SELECT e.effective_product_id AS product_id,
				       e.project_id, e.release_id, e.observed_at
				FROM valid_evidence AS e
				WHERE l.subject_type IN ('evidence', 'evidence_item') AND e.id = l.subject_id AND e.tenant_id = l.tenant_id
				UNION ALL
				SELECT p.id, NULL::text, NULL::text, NULL::timestamptz
				FROM products AS p WHERE l.subject_type = 'product' AND p.id = l.subject_id AND p.tenant_id = l.tenant_id
				UNION ALL
				SELECT r.product_id, NULL::text, r.id, NULL::timestamptz
				FROM valid_releases AS r
				WHERE l.subject_type = 'release' AND r.id = l.subject_id AND r.tenant_id = l.tenant_id
				UNION ALL
				SELECT NULL::text, NULL::text, NULL::text, NULL::timestamptz
				FROM artifacts AS a WHERE l.subject_type = 'artifact' AND a.id = l.subject_id AND a.tenant_id = l.tenant_id AND $2
				UNION ALL
				SELECT e.effective_product_id, e.project_id, e.release_id, NULL::timestamptz
				FROM artifacts AS a
				JOIN valid_evidence AS e ON e.tenant_id = a.tenant_id
				  AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type', 'artifact', 'id', a.id))
				WHERE l.subject_type = 'artifact' AND a.id = l.subject_id AND a.tenant_id = l.tenant_id
				UNION ALL
				SELECT r.product_id, b.project_id, b.release_id, NULL::timestamptz
				FROM artifacts AS a
				JOIN build_runs AS b ON b.tenant_id = a.tenant_id
				  AND b.outputs @> jsonb_build_array(jsonb_build_object('artifact_id', a.id, 'digest', a.digest))
				JOIN valid_projects AS p ON p.id = b.project_id AND p.tenant_id = b.tenant_id
				JOIN valid_releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id AND r.product_id = p.product_id
				WHERE l.subject_type = 'artifact' AND a.id = l.subject_id AND a.tenant_id = l.tenant_id
				UNION ALL
				SELECT COALESCE(e.effective_product_id, r.product_id), e.project_id, COALESCE(s.release_id, e.release_id), s.created_at
				FROM sboms AS s
				JOIN valid_evidence AS e ON e.id = s.evidence_id AND e.tenant_id = s.tenant_id
				LEFT JOIN valid_releases AS r ON r.id = COALESCE(s.release_id, e.release_id) AND r.tenant_id = s.tenant_id
				WHERE l.subject_type = 'sbom' AND s.id = l.subject_id AND s.tenant_id = l.tenant_id
				  AND (COALESCE(s.release_id, e.release_id) IS NULL OR r.id IS NOT NULL)
				  AND (e.release_id IS NULL OR s.release_id IS NULL OR e.release_id = s.release_id)
				  AND (e.effective_product_id IS NULL OR r.id IS NULL OR e.effective_product_id = r.product_id)
				UNION ALL
				SELECT COALESCE(e.effective_product_id, r.product_id), e.project_id, COALESCE(v.release_id, e.release_id), v.created_at
				FROM vulnerability_scans AS v
				JOIN valid_evidence AS e ON e.id = v.evidence_id AND e.tenant_id = v.tenant_id
				LEFT JOIN valid_releases AS r ON r.id = COALESCE(v.release_id, e.release_id) AND r.tenant_id = v.tenant_id
				WHERE l.subject_type = 'vulnerability_scan' AND v.id = l.subject_id AND v.tenant_id = l.tenant_id
				  AND (COALESCE(v.release_id, e.release_id) IS NULL OR r.id IS NOT NULL)
				  AND (e.release_id IS NULL OR v.release_id IS NULL OR e.release_id = v.release_id)
				  AND (e.effective_product_id IS NULL OR r.id IS NULL OR e.effective_product_id = r.product_id)
				UNION ALL
				SELECT COALESCE(e.effective_product_id, r.product_id), e.project_id, COALESCE(v.release_id, e.release_id), v.created_at
				FROM vex_documents AS v
				JOIN valid_evidence AS e ON e.id = v.evidence_id AND e.tenant_id = v.tenant_id
				LEFT JOIN valid_releases AS r ON r.id = COALESCE(v.release_id, e.release_id) AND r.tenant_id = v.tenant_id
				WHERE l.subject_type = 'vex' AND v.id = l.subject_id AND v.tenant_id = l.tenant_id
				  AND (COALESCE(v.release_id, e.release_id) IS NULL OR r.id IS NOT NULL)
				  AND (e.release_id IS NULL OR v.release_id IS NULL OR e.release_id = v.release_id)
				  AND (e.effective_product_id IS NULL OR r.id IS NULL OR e.effective_product_id = r.product_id)
				UNION ALL
				SELECT COALESCE(e.effective_product_id, r.product_id), e.project_id, COALESCE(d.release_id, v.release_id, e.release_id), d.created_at
				FROM vulnerability_decision_projection AS d
				JOIN vulnerability_scans AS v ON v.id = d.scan_id AND v.tenant_id = d.tenant_id
				JOIN valid_evidence AS e ON e.id = v.evidence_id AND e.tenant_id = v.tenant_id
				LEFT JOIN valid_releases AS r ON r.id = COALESCE(d.release_id, v.release_id, e.release_id) AND r.tenant_id = d.tenant_id
				WHERE l.subject_type = 'vulnerability_decision' AND d.id = l.subject_id AND d.tenant_id = l.tenant_id
				  AND (COALESCE(d.release_id, v.release_id, e.release_id) IS NULL OR r.id IS NOT NULL)
				  AND (d.release_id IS NULL OR v.release_id IS NULL OR d.release_id = v.release_id)
				  AND (e.release_id IS NULL OR d.release_id IS NULL OR e.release_id = d.release_id)
				  AND (e.release_id IS NULL OR v.release_id IS NULL OR e.release_id = v.release_id)
				  AND (e.effective_product_id IS NULL OR r.id IS NULL OR e.effective_product_id = r.product_id)
				UNION ALL
				SELECT COALESCE(e.effective_product_id, r.product_id), e.project_id, COALESCE(v.release_id, e.release_id), NULL::timestamptz
				FROM vulnerability_scans AS v
				JOIN valid_evidence AS e ON e.id = v.evidence_id AND e.tenant_id = v.tenant_id
				LEFT JOIN valid_releases AS r ON r.id = COALESCE(v.release_id, e.release_id) AND r.tenant_id = v.tenant_id
				WHERE l.subject_type IN ('finding', 'vulnerability_finding') AND v.tenant_id = l.tenant_id
				  AND v.findings @> jsonb_build_array(jsonb_build_object('id', l.subject_id))
				  AND (COALESCE(v.release_id, e.release_id) IS NULL OR r.id IS NOT NULL)
				  AND (e.release_id IS NULL OR v.release_id IS NULL OR e.release_id = v.release_id)
				  AND (e.effective_product_id IS NULL OR r.id IS NULL OR e.effective_product_id = r.product_id)
				UNION ALL
				SELECT r.product_id, NULL::text, x.release_id, x.created_at
				FROM exceptions AS x JOIN valid_releases AS r ON r.id = x.release_id AND r.tenant_id = x.tenant_id
				WHERE l.subject_type = 'exception' AND x.id = l.subject_id AND x.tenant_id = l.tenant_id
				UNION ALL
				SELECT r.product_id, b.project_id, b.release_id, b.created_at
				FROM build_runs AS b
				JOIN valid_projects AS p ON p.id = b.project_id AND p.tenant_id = b.tenant_id
				JOIN valid_releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id AND r.product_id = p.product_id
				WHERE l.subject_type = 'build' AND b.id = l.subject_id AND b.tenant_id = l.tenant_id
				UNION ALL
				SELECT r.product_id, b.project_id, b.release_id, a.created_at
				FROM build_attestations AS a
				JOIN build_runs AS b ON b.id = a.build_id AND b.tenant_id = a.tenant_id
				JOIN valid_evidence AS e ON e.id = a.evidence_id AND e.tenant_id = a.tenant_id
				JOIN valid_projects AS p ON p.id = b.project_id AND p.tenant_id = b.tenant_id
				JOIN valid_releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id AND r.product_id = p.product_id
				WHERE l.subject_type = 'build_attestation' AND a.id = l.subject_id AND a.tenant_id = l.tenant_id
				  AND (e.effective_product_id IS NULL OR e.effective_product_id = r.product_id)
				  AND (e.project_id IS NULL OR e.project_id = b.project_id)
				  AND (e.release_id IS NULL OR e.release_id = b.release_id)
				UNION ALL
				SELECT c.product_id, NULL::text, c.release_id, c.created_at
				FROM openapi_contracts AS c
				JOIN products AS p ON p.id = c.product_id AND p.tenant_id = c.tenant_id
				JOIN valid_evidence AS e ON e.id = c.evidence_id AND e.tenant_id = c.tenant_id
				LEFT JOIN valid_releases AS r ON r.id = c.release_id AND r.tenant_id = c.tenant_id AND r.product_id = c.product_id
				WHERE l.subject_type = 'openapi_contract' AND c.id = l.subject_id AND c.tenant_id = l.tenant_id
				  AND (c.release_id IS NULL OR r.id IS NOT NULL)
				  AND (e.effective_product_id IS NULL OR e.effective_product_id = c.product_id)
				  AND (e.release_id IS NULL OR c.release_id IS NULL OR e.release_id = c.release_id)
				UNION ALL
				SELECT r.product_id, NULL::text, b.release_id, b.created_at
				FROM release_bundles AS b JOIN valid_releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id
				WHERE l.subject_type = 'release_bundle' AND b.id = l.subject_id AND b.tenant_id = l.tenant_id
			) AS candidate
			WHERE (l.product_id IS NULL OR l.product_id = candidate.product_id)
			  AND (l.release_id IS NULL OR l.release_id = candidate.release_id)
			  AND ($2 OR candidate.product_id = ANY($3::text[]) OR candidate.project_id = ANY($4::text[]) OR candidate.release_id = ANY($5::text[]))
			LIMIT 1
		) AS subject ON true
		WHERE %s
		ORDER BY %s LIMIT $%d`, joinAnd(where), order, len(args))
	rows, err := queryer.Query(ctx, statement, args...)
	if err != nil {
		return empty, fmt.Errorf("page control evidence: %w", err)
	}
	defer rows.Close()
	items := make([]riskquery.ControlEvidencePoint, 0, request.Page.PageSize+1)
	for rows.Next() {
		var point riskquery.ControlEvidencePoint
		var linkProduct, linkRelease, notes, subjectProduct, subjectProject, subjectRelease sql.NullString
		link := &point.Link
		if err := rows.Scan(&link.ID, &link.TenantID, &link.ControlID,
			&link.EvidenceType, &link.SubjectType, &link.SubjectID,
			&linkProduct, &linkRelease, &link.Confidence, &notes,
			&link.SchemaVersion, &link.CreatedAt, &subjectProduct,
			&subjectProject, &subjectRelease, &point.ObservedAt); err != nil {
			return empty, fmt.Errorf("scan control evidence page: %w", err)
		}
		link.ProductID = nullableSQLString(linkProduct)
		link.ReleaseID = nullableSQLString(linkRelease)
		link.Notes = nullableSQLString(notes)
		point.ProductID = nullableSQLString(subjectProduct)
		point.ProjectID = nullableSQLString(subjectProject)
		point.ReleaseID = nullableSQLString(subjectRelease)
		items = append(items, point)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("iterate control evidence page: %w", err)
	}
	result := appquery.Result[riskquery.ControlEvidencePoint]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1].Link
		key := appquery.RecordSortKey(last.ID, last.CreatedAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}
