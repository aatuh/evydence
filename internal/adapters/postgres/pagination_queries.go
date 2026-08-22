package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

// ListEvidencePage executes a tenant-bound keyset query. It intentionally
// fetches one additional row only, so response memory is O(page size), not
// O(number of tenant evidence records).
func (s *Store) ListEvidencePage(ctx context.Context, request app.EvidencePageRequest) (appquery.Result[domain.EvidenceItem], error) {
	if s == nil || s.pool == nil || request.TenantID == "" {
		return appquery.Result[domain.EvidenceItem]{}, app.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}

	where := []string{"tenant_id = $1"}
	args := []any{request.TenantID}
	if request.ReleaseID != "" {
		args = append(args, request.ReleaseID)
		where = append(where, fmt.Sprintf("release_id = $%d", len(args)))
	}
	if request.Type != "" {
		args = append(args, request.Type)
		where = append(where, fmt.Sprintf("type = $%d", len(args)))
	}

	return s.pageEvidenceWhere(ctx, request.Page, request.After, where, args)
}

// SearchEvidencePage executes the full deterministic evidence search in
// PostgreSQL before keyset pagination. Predicate values are always positional
// parameters; only fixed sort clauses are selected by the validated enum.
func (s *Store) SearchEvidencePage(ctx context.Context, request app.EvidenceSearchPageRequest) (appquery.Result[domain.EvidenceItem], error) {
	if s == nil || s.pool == nil || request.TenantID == "" {
		return appquery.Result[domain.EvidenceItem]{}, app.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	where := []string{"tenant_id = $1"}
	args := []any{request.TenantID}
	addEquals := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	filter := request.Filter
	addEquals("product_id", filter.ProductID)
	addEquals("project_id", filter.ProjectID)
	addEquals("release_id", filter.ReleaseID)
	addEquals("build_id", filter.BuildID)
	addEquals("deployment_id", filter.DeploymentID)
	addEquals("type", filter.Type)
	addEquals("subtype", filter.Subtype)
	addEquals("source_system", filter.SourceSystem)
	addEquals("collector_id", filter.CollectorID)
	addEquals("verification_status", filter.VerificationStatus)
	if !filter.CreatedAfter.IsZero() {
		args = append(args, filter.CreatedAfter.UTC())
		where = append(where, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !filter.CreatedBefore.IsZero() {
		args = append(args, filter.CreatedBefore.UTC())
		where = append(where, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if filter.Tag != "" {
		args = append(args, filter.Tag)
		where = append(where, fmt.Sprintf("tags ? $%d", len(args)))
	}
	if filter.SubjectType != "" || filter.SubjectID != "" {
		args = append(args, filter.SubjectType, filter.SubjectID)
		where = append(where, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM jsonb_array_elements(COALESCE(subject_refs, '[]'::jsonb)) AS subject_ref
			WHERE ($%d = '' OR subject_ref ->> 'type' = $%d)
			  AND ($%d = '' OR subject_ref ->> 'id' = $%d OR subject_ref ->> 'digest' = $%d)
		)`, len(args)-1, len(args)-1, len(args), len(args), len(args)))
	}
	return s.pageEvidenceWhere(ctx, request.Page, request.After, where, args)
}

func (s *Store) pageEvidenceWhere(ctx context.Context, pageRequest appquery.PageRequest, after *appquery.SortKey, where []string, args []any) (appquery.Result[domain.EvidenceItem], error) {
	orderBy := "created_at ASC, id ASC"
	if pageRequest.Direction == appquery.Descending {
		orderBy = "created_at DESC, id DESC"
	}
	switch pageRequest.Sort {
	case appquery.SortCreatedAt:
		if after != nil {
			createdAt, err := time.Parse(time.RFC3339Nano, after.Value)
			if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != after.Value {
				return appquery.Result[domain.EvidenceItem]{}, appquery.ErrInvalidCursor
			}
			args = append(args, createdAt, after.ID)
			operator := ">"
			if pageRequest.Direction == appquery.Descending {
				operator = "<"
			}
			where = append(where, fmt.Sprintf("(created_at %s $%d OR (created_at = $%d AND id %s $%d))", operator, len(args)-1, len(args)-1, operator, len(args)))
		}
	case appquery.SortID:
		orderBy = "id ASC"
		if pageRequest.Direction == appquery.Descending {
			orderBy = "id DESC"
		}
		if after != nil {
			if after.Value != after.ID {
				return appquery.Result[domain.EvidenceItem]{}, appquery.ErrInvalidCursor
			}
			args = append(args, after.ID)
			operator := ">"
			if pageRequest.Direction == appquery.Descending {
				operator = "<"
			}
			where = append(where, fmt.Sprintf("id %s $%d", operator, len(args)))
		}
	default:
		return appquery.Result[domain.EvidenceItem]{}, appquery.ErrInvalidPage
	}
	args = append(args, pageRequest.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
		       type, subtype, title, source_system, source_identity, collector_id,
		       uploaded_by, observed_at, evidence_version, schema_version, payload_ref,
		       payload_hash, payload_media_type, payload_size, canonical_hash,
		       canonicalization, subject_refs, related_evidence_refs, supersedes,
		       superseded_by, trust_level, verification_status, signature_refs,
		       chain_entry_id, tags, metadata, warnings, limitations, created_at
		FROM evidence_items
		WHERE %s
		ORDER BY %s
		LIMIT $%d`, joinAnd(where), orderBy, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[domain.EvidenceItem]{}, fmt.Errorf("page evidence items: %w", err)
	}
	defer rows.Close()

	items := make([]domain.EvidenceItem, 0, pageRequest.PageSize+1)
	for rows.Next() {
		item, err := scanEvidencePageRow(rows)
		if err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, fmt.Errorf("iterate evidence page: %w", err)
	}
	result := appquery.Result[domain.EvidenceItem]{Items: items}
	if len(items) > pageRequest.PageSize {
		result.Items = items[:pageRequest.PageSize]
		key := appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, pageRequest.Sort)
		result.Next = &key
	}
	return result, nil
}

func joinAnd(clauses []string) string {
	if len(clauses) == 0 {
		return "FALSE"
	}
	result := clauses[0]
	for _, clause := range clauses[1:] {
		result += " AND " + clause
	}
	return result
}

type evidencePageRow interface {
	Scan(...any) error
}

func scanEvidencePageRow(row evidencePageRow) (domain.EvidenceItem, error) {
	var evidence domain.EvidenceItem
	var productID, projectID, releaseID, buildID, deploymentID, subtype, collectorID, uploadedBy, payloadRef, payloadMediaType, supersedes, supersededBy, chainEntryID sql.NullString
	var payloadSize sql.NullInt64
	var sourceIdentity, subjectRefs, relatedRefs, signatureRefs, tags, metadata, warnings, limitations []byte
	if err := row.Scan(
		&evidence.ID, &evidence.TenantID, &productID, &projectID, &releaseID, &buildID, &deploymentID,
		&evidence.Type, &subtype, &evidence.Title, &evidence.SourceSystem, &sourceIdentity, &collectorID,
		&uploadedBy, &evidence.ObservedAt, &evidence.EvidenceVersion, &evidence.SchemaVersion, &payloadRef,
		&evidence.PayloadHash, &payloadMediaType, &payloadSize, &evidence.CanonicalHash,
		&evidence.Canonicalization, &subjectRefs, &relatedRefs, &supersedes,
		&supersededBy, &evidence.TrustLevel, &evidence.VerificationStatus, &signatureRefs,
		&chainEntryID, &tags, &metadata, &warnings, &limitations, &evidence.CreatedAt,
	); err != nil {
		return domain.EvidenceItem{}, fmt.Errorf("scan evidence page item: %w", err)
	}
	evidence.ProductID = nullableSQLString(productID)
	evidence.ProjectID = nullableSQLString(projectID)
	evidence.ReleaseID = nullableSQLString(releaseID)
	evidence.BuildID = nullableSQLString(buildID)
	evidence.DeploymentID = nullableSQLString(deploymentID)
	evidence.Subtype = nullableSQLString(subtype)
	evidence.CollectorID = nullableSQLString(collectorID)
	evidence.UploadedBy = nullableSQLString(uploadedBy)
	evidence.PayloadRef = nullableSQLString(payloadRef)
	evidence.PayloadMediaType = nullableSQLString(payloadMediaType)
	if payloadSize.Valid {
		evidence.PayloadSize = payloadSize.Int64
	}
	evidence.Supersedes = nullableSQLString(supersedes)
	evidence.SupersededBy = nullableSQLString(supersededBy)
	evidence.ChainEntryID = nullableSQLString(chainEntryID)
	for _, payload := range []struct {
		raw    []byte
		target any
	}{
		{sourceIdentity, &evidence.SourceIdentity},
		{subjectRefs, &evidence.SubjectRefs},
		{relatedRefs, &evidence.RelatedEvidenceRefs},
		{signatureRefs, &evidence.SignatureRefs},
		{tags, &evidence.Tags},
		{metadata, &evidence.Metadata},
		{warnings, &evidence.Warnings},
		{limitations, &evidence.Limitations},
	} {
		if err := decodeJSON(payload.raw, payload.target); err != nil {
			return domain.EvidenceItem{}, fmt.Errorf("decode evidence page item: %w", err)
		}
	}
	return evidence, nil
}
