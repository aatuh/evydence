package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

// This private projection is only the catalog component of a complete
// customer-package snapshot. It must be composed with the remaining sections
// in one read-only repeatable-read transaction before production binding.
type customerPackageCatalogSnapshot struct {
	Tenant, Organization, Product, Release map[string]any
	Evidence                               []packageapp.EvidenceReference
	Artifacts                              []map[string]any
}

type customerSnapshotBudget struct{ remainingBytes int }

func customerSnapshotID(value string, optional bool) bool {
	return (optional || value != "") && value == strings.TrimSpace(value) &&
		len(value) <= packageapp.MaxCustomerPackageIDBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func readCustomerPackageCatalogTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, budget *customerSnapshotBudget) (customerPackageCatalogSnapshot, error) {
	var empty customerPackageCatalogSnapshot
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return empty, err
	}
	// Publish consumption only after this complete component succeeds.
	working := *budget
	roots, err := readCustomerSnapshotMetadataRows(ctx, tx, customerCatalogRootsSQL, tenant, product, release, &working)
	if err != nil {
		return empty, err
	}
	if len(roots) != 1 {
		return empty, packageapp.ErrNotFound
	}
	out := customerPackageCatalogSnapshot{
		Tenant: roots[0]["tenant"].(map[string]any), Product: roots[0]["product"].(map[string]any),
		Release: map[string]any{}, Evidence: []packageapp.EvidenceReference{}, Artifacts: []map[string]any{},
	}
	if release != "" {
		rows, err := readCustomerSnapshotMetadataRows(ctx, tx, customerCatalogReleaseSQL, tenant, product, release, &working)
		if err != nil {
			return empty, err
		}
		if len(rows) != 1 {
			return empty, packageapp.ErrNotFound
		}
		out.Release = rows[0]
	}
	organizations, err := readCustomerSnapshotMetadataRows(ctx, tx, customerCatalogOrganizationsSQL, tenant, product, release, &working)
	if err != nil {
		return empty, err
	}
	out.Organization = map[string]any{
		"records": organizations,
		"limitations": []string{
			"Organization records are included only as tenant metadata; product-to-organization ownership is not inferred by this package schema.",
		},
	}
	evidence, err := readCustomerSnapshotMetadataRows(ctx, tx, customerCatalogEvidenceSQL, tenant, product, release, &working)
	if err != nil {
		return empty, err
	}
	for _, row := range evidence {
		out.Evidence = append(out.Evidence, packageapp.EvidenceReference{ID: row["id"].(string), Type: row["type"].(string)})
	}
	// The existing package format lists artifact metadata only for a selected
	// release. Product-only evidence references remain product-scoped.
	if release != "" {
		if err := checkCustomerCatalogAssociationBudget(ctx, tx, tenant, product, release); err != nil {
			return empty, err
		}
		out.Artifacts, err = readCustomerSnapshotMetadataRows(ctx, tx, customerCatalogArtifactsSQL, tenant, product, release, &working)
		if err != nil {
			return empty, err
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	*budget = working
	return out, nil
}

// The projection SQL is fixed internally, not caller-provided SQL. All scope
// coordinates and limits stay bound parameters. PostgreSQL computes the row,
// metadata-byte, and validity budgets before transferring any selected JSON;
// on overflow only null metadata and a rejection flag cross the driver.
func readCustomerSnapshotMetadataRows(ctx context.Context, tx pgx.Tx, projection, tenant, product, release string, budget *customerSnapshotBudget) ([]map[string]any, error) {
	rows, err := tx.Query(ctx, `WITH scope AS (
		SELECT $1::text AS tenant_id,$2::text AS product_id,$3::text AS release_id
	), records AS MATERIALIZED (`+projection+` LIMIT $5), bounds AS (
		SELECT count(*) >= $5 OR coalesce(sum(octet_length(metadata::text)),0)>$4 OR coalesce(bool_or(invalid),false) AS rejected FROM records
	)
	SELECT CASE WHEN bounds.rejected THEN NULL ELSE records.metadata END,bounds.rejected
	FROM records CROSS JOIN bounds ORDER BY records.sort_id COLLATE "C"`, tenant, product, release, budget.remainingBytes, packageapp.MaxSecurityReviewEvidenceIDs+1)
	if err != nil {
		return nil, fmt.Errorf("read customer-package snapshot metadata: %w", err)
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	used := 0
	for rows.Next() {
		var raw []byte
		var rejected bool
		if err := rows.Scan(&raw, &rejected); err != nil {
			return nil, fmt.Errorf("scan customer-package snapshot metadata: %w", err)
		}
		if rejected || len(raw) == 0 || len(raw) > budget.remainingBytes-used || len(out) == packageapp.MaxSecurityReviewEvidenceIDs ||
			jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 32, MaxObjectKeys: 4096, MaxArrayItems: packageapp.MaxSecurityReviewEvidenceIDs, MaxStringBytes: packageapp.MaxCustomerPackageManifestBytes}) != nil {
			return nil, packageapp.ErrConflict
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var row map[string]any
		if err := decoder.Decode(&row); err != nil || row == nil {
			return nil, packageapp.ErrConflict
		}
		if value, present := row["id"]; present {
			id, ok := value.(string)
			if !ok || !customerSnapshotID(id, false) {
				return nil, packageapp.ErrConflict
			}
		}
		used += len(raw)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate customer-package snapshot metadata: %w", err)
	}
	budget.remainingBytes -= used
	return out, nil
}

const customerCatalogRootsSQL = `SELECT p.id AS sort_id,
	jsonb_build_object('tenant',jsonb_build_object('id',t.id,'name',t.name),
	'product',jsonb_build_object('id',p.id,'name',p.name,'slug',p.slug,
	'created_at',to_char(p.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'))) AS metadata,
	NOT isfinite(p.created_at) AS invalid
	FROM scope s JOIN tenants t ON t.id=s.tenant_id JOIN products p ON p.tenant_id=t.id AND p.id=s.product_id
	ORDER BY p.id`

const customerCatalogReleaseSQL = `SELECT r.id AS sort_id,
	jsonb_strip_nulls(jsonb_build_object('id',r.id,'product_id',r.product_id,'version',r.version,'state',r.state,
	'created_at',to_char(r.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'frozen_at',to_char(r.frozen_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'approved_at',to_char(r.approved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'))) AS metadata,
	(NOT isfinite(r.created_at) OR coalesce(NOT isfinite(r.frozen_at),false) OR coalesce(NOT isfinite(r.approved_at),false)) AS invalid
	FROM scope s JOIN releases r ON r.tenant_id=s.tenant_id AND r.product_id=s.product_id AND r.id=s.release_id
	ORDER BY r.id`

const customerCatalogOrganizationsSQL = `SELECT o.id AS sort_id,
	jsonb_build_object('id',o.id,'name',o.name,'slug',o.slug,'status',o.status,
	'created',to_char(o.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(o.id)>1024 OR btrim(o.id)='' OR o.id<>btrim(o.id) OR NOT isfinite(o.created_at)) AS invalid
	FROM scope s JOIN organizations o ON o.tenant_id=s.tenant_id ORDER BY o.id`

// Optional parent IDs must either be absent or resolve in this same tenant
// and selected product. A matching release ID alone is not product authority.
const customerCatalogEvidenceOwnershipSQL = `e.tenant_id=s.tenant_id
	AND (e.product_id=s.product_id OR (coalesce(e.product_id,'')='' AND (
	 EXISTS(SELECT 1 FROM projects p WHERE p.id=e.project_id AND p.tenant_id=s.tenant_id AND p.product_id=s.product_id)
	 OR EXISTS(SELECT 1 FROM releases r WHERE r.id=e.release_id AND r.tenant_id=s.tenant_id AND r.product_id=s.product_id)
	 OR EXISTS(SELECT 1 FROM build_runs b JOIN projects p ON p.id=b.project_id AND p.tenant_id=b.tenant_id AND p.product_id=s.product_id JOIN releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=s.product_id WHERE b.id=e.build_id AND b.tenant_id=s.tenant_id)
	 OR EXISTS(SELECT 1 FROM deployment_events d JOIN deployment_environments v ON v.id=d.environment_id AND v.tenant_id=d.tenant_id AND v.product_id=s.product_id JOIN releases r ON r.id=d.release_id AND r.tenant_id=d.tenant_id AND r.product_id=s.product_id WHERE d.id=e.deployment_id AND d.tenant_id=s.tenant_id)
	)))` + customerEvidenceParentConsistencySQL

const customerEvidenceParentConsistencySQL = `AND (coalesce(e.project_id,'')='' OR EXISTS(SELECT 1 FROM projects p WHERE p.id=e.project_id AND p.tenant_id=s.tenant_id AND p.product_id=s.product_id))
	AND (coalesce(e.release_id,'')='' OR EXISTS(SELECT 1 FROM releases r WHERE r.id=e.release_id AND r.tenant_id=s.tenant_id AND r.product_id=s.product_id))
	AND (coalesce(e.build_id,'')='' OR EXISTS(SELECT 1 FROM build_runs b
	 JOIN projects p ON p.id=b.project_id AND p.tenant_id=b.tenant_id AND p.product_id=s.product_id
	 JOIN releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=s.product_id
	 WHERE b.id=e.build_id AND b.tenant_id=s.tenant_id
	 AND (coalesce(e.project_id,'')='' OR e.project_id=b.project_id)
	 AND (coalesce(e.release_id,'')='' OR e.release_id=b.release_id)))
	AND (coalesce(e.deployment_id,'')='' OR EXISTS(SELECT 1 FROM deployment_events d
	 JOIN deployment_environments v ON v.id=d.environment_id AND v.tenant_id=d.tenant_id AND v.product_id=s.product_id
	 JOIN releases r ON r.id=d.release_id AND r.tenant_id=d.tenant_id AND r.product_id=s.product_id
	 WHERE d.id=e.deployment_id AND d.tenant_id=s.tenant_id
	 AND (coalesce(e.release_id,'')='' OR e.release_id=d.release_id)
	 AND (coalesce(e.build_id,'')='' OR EXISTS(SELECT 1 FROM build_runs b WHERE b.id=e.build_id AND b.tenant_id=s.tenant_id AND b.release_id=d.release_id))))`

const customerCatalogEvidenceScopeSQL = customerCatalogEvidenceOwnershipSQL + ` AND (s.release_id='' OR e.release_id=s.release_id)`

const customerCatalogEvidenceSQL = `SELECT e.id AS sort_id,jsonb_build_object('id',e.id,'type',e.type) AS metadata,
	(octet_length(e.id)>1024 OR btrim(e.id)='' OR e.id<>btrim(e.id) OR octet_length(e.type)>1024 OR btrim(e.type)='' OR e.type<>btrim(e.type)) AS invalid
	FROM scope s JOIN evidence_items e ON ` + customerCatalogEvidenceScopeSQL + ` ORDER BY e.id`

const customerCatalogBuildScopeSQL = `b.tenant_id=s.tenant_id AND b.release_id=s.release_id
	AND EXISTS(SELECT 1 FROM projects p WHERE p.id=b.project_id AND p.tenant_id=s.tenant_id AND p.product_id=s.product_id)
	AND EXISTS(SELECT 1 FROM releases r WHERE r.id=b.release_id AND r.tenant_id=s.tenant_id AND r.product_id=s.product_id)`

func checkCustomerCatalogAssociationBudget(ctx context.Context, tx pgx.Tx, tenant, product, release string) error {
	var count, size, elements int64
	var malformed bool
	err := tx.QueryRow(ctx, `WITH scope AS (
		SELECT $1::text AS tenant_id,$2::text AS product_id,$3::text AS release_id
	), selected AS MATERIALIZED (
		(SELECT 'evidence'::text AS kind,coalesce(nullif(e.subject_refs,'null'::jsonb),'[]'::jsonb) AS refs FROM scope s JOIN evidence_items e ON `+customerCatalogEvidenceScopeSQL+` LIMIT $4)
		UNION ALL (SELECT 'build'::text AS kind,coalesce(nullif(b.outputs,'null'::jsonb),'[]'::jsonb) FROM scope s JOIN build_runs b ON `+customerCatalogBuildScopeSQL+` LIMIT $4)
	)
	SELECT greatest(count(*) FILTER (WHERE kind='evidence'),count(*) FILTER (WHERE kind='build')),coalesce(sum(octet_length(refs::text)),0),
	coalesce(sum(CASE WHEN jsonb_typeof(refs)='array' THEN jsonb_array_length(refs) ELSE 0 END),0),
	coalesce(bool_or(CASE WHEN jsonb_typeof(refs) IS DISTINCT FROM 'array' THEN true
	 WHEN jsonb_array_length(refs)>=$4 THEN true
	 ELSE EXISTS(SELECT 1 FROM jsonb_array_elements(refs) r WHERE jsonb_typeof(r)<>'object') END),false)
	FROM selected`, tenant, product, release, packageapp.MaxSecurityReviewEvidenceIDs+1).Scan(&count, &size, &elements, &malformed)
	if err != nil {
		return fmt.Errorf("read customer-package association budget: %w", err)
	}
	if count > packageapp.MaxSecurityReviewEvidenceIDs || size > packageapp.MaxCustomerPackageManifestBytes || elements > packageapp.MaxSecurityReviewEvidenceIDs || malformed {
		return packageapp.ErrConflict
	}
	return nil
}

const customerCatalogArtifactsSQL = `SELECT a.id AS sort_id,
	jsonb_build_object('id',a.id,'name',a.name,'media_type',a.media_type,'size',a.size,'digest',a.digest,
	'created_at',to_char(a.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(a.id)>1024 OR btrim(a.id)='' OR a.id<>btrim(a.id) OR a.size<0 OR NOT isfinite(a.created_at)) AS invalid
	FROM scope s JOIN artifacts a ON a.tenant_id=s.tenant_id
	WHERE EXISTS(SELECT 1 FROM evidence_items e WHERE ` + customerCatalogEvidenceScopeSQL + `
	 AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type','artifact','id',a.id)))
	OR EXISTS(SELECT 1 FROM sboms d JOIN evidence_items e ON e.id=d.evidence_id AND e.tenant_id=d.tenant_id
	 WHERE d.tenant_id=s.tenant_id AND d.release_id=s.release_id AND d.artifact_id=a.id AND ` + customerCatalogEvidenceScopeSQL + `)
	OR EXISTS(SELECT 1 FROM vex_documents d JOIN evidence_items e ON e.id=d.evidence_id AND e.tenant_id=d.tenant_id
	 WHERE d.tenant_id=s.tenant_id AND d.release_id=s.release_id AND d.artifact_id=a.id AND ` + customerCatalogEvidenceScopeSQL + `)
	OR EXISTS(SELECT 1 FROM build_runs b WHERE ` + customerCatalogBuildScopeSQL + `
	 AND b.outputs @> jsonb_build_array(jsonb_build_object('artifact_id',a.id,'digest',a.digest)))
	ORDER BY a.id`
