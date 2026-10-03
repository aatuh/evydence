package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

var _ packageapp.EvidenceSummaryReader = futureExtensions{}

// Reads only root coordinates and locks them through summary/audit commit.
// Package manifests and evidence payloads are never loaded.
func (r futureExtensions) ReadEvidenceSummaryScope(ctx context.Context, tenant, kind, id string) (packageapp.EvidenceSummaryScope, error) {
	scope := packageapp.EvidenceSummaryScope{TenantID: tenant, SubjectType: kind, SubjectID: id}
	var raw application.ResourceReferences
	var err error
	switch kind {
	case "tenant":
		if id != tenant {
			return scope, app.ErrNotFound
		}
		err = requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant)
	case "product":
		err = requireRow(ctx, r.tx, `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id)
		raw.ProductID = id
	case "evidence":
		raw, err = ReadEvidenceBundleCoordinates(ctx, r.tx, tenant, id, true)
	case "release":
		raw.ReleaseID = id
		err = readSummaryParentCoordinates(ctx, r.tx, `SELECT left(product_id,1025),'',octet_length(product_id)>1024 FROM releases WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id, &raw.ProductID, &raw.ProjectID)
	case "build":
		err = readSummaryParentCoordinates(ctx, r.tx, `SELECT left(project_id,1025),left(release_id,1025),octet_length(project_id)>1024 OR octet_length(release_id)>1024 FROM build_runs WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id, &raw.ProjectID, &raw.ReleaseID)
	case "customer_package":
		raw.CustomerPackageID = id
		err = readSummaryParentCoordinates(ctx, r.tx, `SELECT left(product_id,1025),left(coalesce(release_id,''),1025),octet_length(product_id)>1024 OR coalesce(octet_length(release_id)>1024,false) FROM customer_security_packages WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id, &raw.ProductID, &raw.ReleaseID)
	default:
		return scope, app.ErrValidation
	}
	if err != nil {
		return scope, err
	}
	scope.Filter = raw
	refs, err := ResolveEvidenceBundleCoordinates(ctx, r.tx, tenant, raw)
	if errors.Is(err, evidencequery.ErrNotFound) {
		return scope, app.ErrConflict
	}
	if err != nil {
		return scope, err
	}
	if refs.ProductID != "" {
		if err := requireRow(ctx, r.tx, `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, refs.ProductID); err != nil {
			return scope, err
		}
	}
	if err := evidence(r).ValidateEvidenceScope(ctx, tenant, refs.ProductID, refs.ProjectID, refs.ReleaseID, refs.BuildID, refs.DeploymentID); err != nil {
		return scope, err
	}
	scope.Resources = refs
	return scope, nil
}

func readSummaryParentCoordinates(ctx context.Context, tx pgx.Tx, statement, tenant, id string, first, second *string) error {
	var oversized bool
	err := tx.QueryRow(ctx, statement, tenant, id).Scan(first, second, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read summary root coordinates: %w", err)
	}
	if oversized {
		return app.ErrConflict
	}
	return nil
}

// The preflight returns at most limit+1 IDs, lengths, and bounded selection
// coordinates. Row locks make the size-checked metadata fetch stable, including
// when an operator bypasses the shared writer fence. No raw payload is selected.
func (r futureExtensions) ReadEvidenceSummaryItems(ctx context.Context, s packageapp.EvidenceSummaryScope, ids []string) ([]packageapp.EvidenceSummaryItem, error) {
	if len(ids) > packageapp.MaxEvidenceSummaryItems {
		return nil, app.ErrValidation
	}
	if ids == nil {
		ids = []string{}
	}
	rows, err := r.tx.Query(ctx, `SELECT left(id,1025),octet_length(id),octet_length(type),octet_length(title),octet_length(canonical_hash),
left(coalesce(product_id,''),1025),left(coalesce(project_id,''),1025),left(coalesce(release_id,''),1025),
coalesce(octet_length(product_id)>1024,false) OR coalesce(octet_length(project_id)>1024,false) OR coalesce(octet_length(release_id)>1024,false)
FROM evidence_items WHERE tenant_id=$1 AND (
 (cardinality($5::text[])>0 AND id=ANY($5::text[])) OR
 (cardinality($5::text[])=0 AND ($2='' OR product_id=$2) AND ($3='' OR project_id=$3) AND ($4='' OR release_id=$4)))
ORDER BY id LIMIT $6 FOR SHARE`, s.TenantID, s.Filter.ProductID, s.Filter.ProjectID, s.Filter.ReleaseID, ids, packageapp.MaxEvidenceSummaryItems+1)
	if err != nil {
		return nil, fmt.Errorf("preflight summary citations: %w", err)
	}
	defer rows.Close()
	items := make([]packageapp.EvidenceSummaryItem, 0)
	total := 0
	for rows.Next() {
		var v packageapp.EvidenceSummaryItem
		var idBytes, typeBytes, titleBytes, hashBytes int
		var oversized bool
		if err := rows.Scan(&v.ID, &idBytes, &typeBytes, &titleBytes, &hashBytes, &v.Resources.ProductID, &v.Resources.ProjectID, &v.Resources.ReleaseID, &oversized); err != nil {
			return nil, err
		}
		if oversized {
			return nil, app.ErrConflict
		}
		if idBytes > packageapp.MaxEvidenceSummaryIDBytes || typeBytes > packageapp.MaxEvidenceSummaryTypeBytes || titleBytes > packageapp.MaxEvidenceSummaryTitleBytes || hashBytes > packageapp.MaxEvidenceSummaryIDBytes {
			return nil, app.ErrValidation
		}
		total += idBytes + typeBytes + titleBytes + hashBytes + len(v.Resources.ProductID) + len(v.Resources.ProjectID) + len(v.Resources.ReleaseID)
		if total > packageapp.MaxGeneratedReportBytes || len(items) == packageapp.MaxEvidenceSummaryItems {
			return nil, app.ErrValidation
		}
		v.TenantID = s.TenantID
		items = append(items, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if len(items) == 0 {
		return items, nil
	}
	selected := make([]string, len(items))
	for i := range items {
		selected[i] = items[i].ID
	}
	metadata, err := r.tx.Query(ctx, `SELECT id,type,title,canonical_hash FROM evidence_items WHERE tenant_id=$1 AND id=ANY($2::text[]) ORDER BY id`, s.TenantID, selected)
	if err != nil {
		return nil, fmt.Errorf("read bounded summary citations: %w", err)
	}
	defer metadata.Close()
	i := 0
	for metadata.Next() {
		var id string
		if i == len(items) {
			return nil, app.ErrConflict
		}
		if err := metadata.Scan(&id, &items[i].Type, &items[i].Title, &items[i].CanonicalHash); err != nil {
			return nil, err
		}
		if id != items[i].ID {
			return nil, app.ErrConflict
		}
		i++
	}
	if err := metadata.Err(); err != nil {
		return nil, err
	}
	if i != len(items) {
		return nil, app.ErrConflict
	}
	return items, nil
}
