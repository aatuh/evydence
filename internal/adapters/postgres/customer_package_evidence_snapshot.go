package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// A private component of the complete snapshot, not a standalone production
// reader. Catalog and the remaining components must share this transaction.
type customerPackageEvidenceSnapshot struct {
	SBOMs, Scans, VEX []map[string]any
	Contracts         map[string]any
}

func readCustomerPackageEvidenceTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, budget *customerSnapshotBudget) (customerPackageEvidenceSnapshot, error) {
	var empty customerPackageEvidenceSnapshot
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return empty, err
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return empty, err
	}
	working := *budget
	out := customerPackageEvidenceSnapshot{}
	for _, part := range []struct {
		query string
		rows  *[]map[string]any
	}{
		{customerEvidenceSBOMSQL, &out.SBOMs},
		{customerEvidenceScanSQL, &out.Scans},
		{customerEvidenceVEXSQL, &out.VEX},
	} {
		rows, err := readCustomerSnapshotMetadataRows(ctx, tx, part.query, tenant, product, release, &working)
		if err != nil {
			return empty, err
		}
		for _, row := range rows {
			for _, key := range []string{"summary", "status_summary"} {
				if counts, exists := row[key]; exists {
					value, err := customerSnapshotCountMap(counts)
					if err != nil {
						return empty, err
					}
					row[key] = value
				}
			}
		}
		*part.rows = rows
	}
	contracts, err := readCustomerSnapshotMetadataRows(ctx, tx, customerEvidenceContractsSQL, tenant, product, release, &working)
	if err != nil {
		return empty, err
	}
	for _, row := range contracts {
		before, _ := json.Marshal(row)
		if err := normalizeCustomerContractOperations(row); err != nil {
			return empty, err
		}
		after, err := json.Marshal(row)
		if err != nil || len(after)-len(before) > working.remainingBytes {
			return empty, packageapp.ErrConflict
		}
		// SQL charged the selected metadata. Also charge any expansion from
		// normalized operation labels and default public fields.
		if growth := len(after) - len(before); growth > 0 {
			working.remainingBytes -= growth
		}
	}
	diffs, err := readCustomerSnapshotMetadataRows(ctx, tx, customerEvidenceDiffsSQL, tenant, product, release, &working)
	if err != nil {
		return empty, err
	}
	for _, row := range diffs {
		for _, key := range []string{"breaking_changes", "non_breaking_changes"} {
			value, err := customerSnapshotStringList(row[key])
			if err != nil {
				return empty, err
			}
			row[key] = value
		}
	}
	out.Contracts = map[string]any{
		"openapi_contracts": contracts, "contract_diffs": diffs,
		"limitations": []string{
			"OpenAPI contract evidence includes stored metadata, hashes, and normalized operation summaries only.",
			"Raw OpenAPI document bytes, object-store payload references, and private/internal extensions are not included.",
			"Diff results summarize recorded contract evidence and do not make this package an API governance approval.",
		},
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	*budget = working
	return out, nil
}

func validateCustomerSnapshotRead(ctx context.Context, tx pgx.Tx, tenant, product, release string, budget *customerSnapshotBudget) error {
	if ctx == nil || tx == nil || budget == nil || budget.remainingBytes < 0 || budget.remainingBytes > packageapp.MaxCustomerPackageManifestBytes ||
		!customerSnapshotID(tenant, false) || !customerSnapshotID(product, false) || !customerSnapshotID(release, true) {
		return packageapp.ErrValidation
	}
	return ctx.Err()
}

func requireCustomerSnapshotScope(ctx context.Context, tx pgx.Tx, tenant, product, release string) error {
	var found int
	err := tx.QueryRow(ctx, `SELECT 1 FROM tenants t JOIN products p ON p.tenant_id=t.id
	 WHERE t.id=$1 AND p.id=$2 AND ($3::text='' OR EXISTS(SELECT 1 FROM releases r WHERE r.id=$3 AND r.tenant_id=t.id AND r.product_id=p.id))`, tenant, product, release).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return packageapp.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read customer-package scope: %w", err)
	}
	return nil
}

func customerSnapshotCountMap(value any) (map[string]int, error) {
	counts, ok := value.(map[string]any)
	if !ok {
		return nil, packageapp.ErrConflict
	}
	out := make(map[string]int, len(counts))
	for key, v := range counts {
		number, ok := v.(json.Number)
		if !ok {
			return nil, packageapp.ErrConflict
		}
		count, err := strconv.Atoi(number.String())
		if err != nil || count < 0 {
			return nil, packageapp.ErrConflict
		}
		out[key] = count
	}
	return out, nil
}

func customerSnapshotStringList(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, packageapp.ErrConflict
	}
	var out []string
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			return nil, packageapp.ErrConflict
		}
		out = append(out, s)
	}
	return out, nil
}

func normalizeCustomerContractOperations(row map[string]any) error {
	var stored []struct {
		Path                  string   `json:"path"`
		Method                string   `json:"method"`
		OperationID           string   `json:"operation_id"`
		Deprecated            bool     `json:"deprecated"`
		RequestBodyRequired   bool     `json:"request_body_required"`
		RequiredRequestFields []string `json:"required_request_fields"`
		ResponseStatuses      []string `json:"response_statuses"`
	}
	raw, err := json.Marshal(row["operations"])
	if err != nil || json.Unmarshal(raw, &stored) != nil {
		return packageapp.ErrConflict
	}
	inputs := make([]packageapp.CustomerPackageAPIOperation, 0, len(stored))
	for _, op := range stored {
		inputs = append(inputs, packageapp.CustomerPackageAPIOperation{Path: op.Path, Method: op.Method, OperationID: op.OperationID, Deprecated: op.Deprecated, RequestBodyRequired: op.RequestBodyRequired, RequiredRequestFields: op.RequiredRequestFields, ResponseStatuses: op.ResponseStatuses})
	}
	row["operations"] = packageapp.CustomerPackageOperationSummaries(inputs)
	return nil
}

// Parsed summaries must agree with their source's declared release. For a
// product-only package, preserve the existing unreleased-document selection,
// while deriving ownership from coherent source parents instead of the tenant.
const customerEvidenceParsedScopeSQL = `d.tenant_id=s.tenant_id AND coalesce(d.release_id,'')=s.release_id
	AND e.id=d.evidence_id AND e.tenant_id=d.tenant_id AND coalesce(e.release_id,'')=s.release_id AND ` + customerCatalogEvidenceOwnershipSQL

const customerEvidenceArtifactScopeSQL = `(coalesce(d.artifact_id,'')='' OR EXISTS(SELECT 1 FROM artifacts a WHERE a.id=d.artifact_id AND a.tenant_id=s.tenant_id))
	AND (coalesce(d.artifact_id,'')='' AND NOT coalesce(e.subject_refs,'[]') @> '[{"type":"artifact"}]'::jsonb
	OR coalesce(d.artifact_id,'')<>'' AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type','artifact','id',d.artifact_id))
	 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(e.subject_refs)='array' THEN e.subject_refs ELSE '[]'::jsonb END) ref
	 WHERE ref->>'type'='artifact' AND coalesce(ref->>'id','')<>'' AND ref->>'id'<>d.artifact_id))`

const customerEvidenceSBOMSQL = `SELECT d.id AS sort_id,
	jsonb_build_object('id',d.id,'evidence_id',d.evidence_id,'release_id',coalesce(d.release_id,''),'artifact_id',coalesce(d.artifact_id,''),
	'format',d.format,'spec_version',d.spec_version,'component_count',d.component_count,
	'created_at',to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(d.id)>1024 OR octet_length(d.evidence_id)>1024 OR octet_length(coalesce(d.artifact_id,''))>1024 OR d.component_count<0 OR NOT isfinite(d.created_at)) AS invalid
	FROM scope s JOIN sboms d ON d.tenant_id=s.tenant_id JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='sbom'
	WHERE ` + customerEvidenceArtifactScopeSQL + ` ORDER BY d.id`

// Only scalar findings count crosses the driver; finding records are never
// selected. JSON null is the legacy empty collection representation.
var customerEvidenceScanSQL = `SELECT d.id AS sort_id,
	jsonb_build_object('id',d.id,'evidence_id',d.evidence_id,'release_id',coalesce(d.release_id,''),
	'scanner',d.scanner,'target_ref',d.target_ref,'summary',coalesce(nullif(d.summary,'null'::jsonb),'{}'::jsonb),
	'finding_count',CASE WHEN jsonb_typeof(d.findings)='array' THEN jsonb_array_length(d.findings) ELSE 0 END,
	'created_at',to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(d.id)>1024 OR octet_length(d.evidence_id)>1024 OR NOT isfinite(d.created_at)
	OR coalesce(jsonb_typeof(d.findings) NOT IN ('array','null'),true) OR ` + customerSnapshotCountMapInvalidSQL("d.summary") + `) AS invalid
	FROM scope s JOIN vulnerability_scans d ON d.tenant_id=s.tenant_id JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='vulnerability_scan'
	WHERE NOT coalesce(e.subject_refs,'[]') @> '[{"type":"artifact"}]'::jsonb ORDER BY d.id`

var customerEvidenceVEXSQL = `SELECT d.id AS sort_id,
	jsonb_build_object('id',d.id,'evidence_id',d.evidence_id,'release_id',coalesce(d.release_id,''),'artifact_id',coalesce(d.artifact_id,''),
	'format',d.format,'version',coalesce(d.version,''),'statement_count',d.statement_count,'status_summary',coalesce(nullif(d.status_summary,'null'::jsonb),'{}'::jsonb),'schema_version',d.schema_version,
	'created_at',to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(d.id)>1024 OR octet_length(d.evidence_id)>1024 OR octet_length(coalesce(d.artifact_id,''))>1024 OR d.statement_count<0 OR NOT isfinite(d.created_at)
	OR ` + customerSnapshotCountMapInvalidSQL("d.status_summary") + `) AS invalid
	FROM scope s JOIN vex_documents d ON d.tenant_id=s.tenant_id JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='vex'
	WHERE ` + customerEvidenceArtifactScopeSQL + ` ORDER BY d.id`

// The expression is a private column constant. CASE protects all type-specific
// operations and numeric casts from malformed JSON before metadata transfer.
func customerSnapshotCountMapInvalidSQL(column string) string {
	return `CASE WHEN ` + column + ` IS NULL OR jsonb_typeof(` + column + `)='null' THEN false
	WHEN jsonb_typeof(` + column + `) IS DISTINCT FROM 'object' THEN true
	WHEN octet_length(` + column + `::text)>8388608 THEN true
	WHEN (SELECT count(*) FROM (SELECT 1 FROM jsonb_each(` + column + `) LIMIT 4097) bounded)>4096 THEN true
	ELSE EXISTS(SELECT 1 FROM jsonb_each(` + column + `) v WHERE CASE WHEN jsonb_typeof(v.value)<>'number' THEN true
	 WHEN v.value::text !~ '^[0-9]+$' THEN true ELSE v.value::text::numeric>9223372036854775807 END) END`
}

func customerSnapshotStringListInvalidSQL(column string) string {
	return `CASE WHEN ` + column + ` IS NULL OR jsonb_typeof(` + column + `)='null' THEN false
	WHEN jsonb_typeof(` + column + `) IS DISTINCT FROM 'array' THEN true
	WHEN jsonb_array_length(` + column + `)>4096 THEN true
	ELSE EXISTS(SELECT 1 FROM jsonb_array_elements(` + column + `) v WHERE jsonb_typeof(v) IS DISTINCT FROM 'string') END`
}

var customerSnapshotOperationInvalidSQL = `CASE WHEN jsonb_typeof(o) IS DISTINCT FROM 'object' THEN true ELSE
	(NOT coalesce(jsonb_typeof(o->'path') IN ('string','null'),true)
	OR NOT coalesce(jsonb_typeof(o->'method') IN ('string','null'),true)
	OR NOT coalesce(jsonb_typeof(o->'operation_id') IN ('string','null'),true)
	OR NOT coalesce(jsonb_typeof(o->'deprecated') IN ('boolean','null'),true)
	OR NOT coalesce(jsonb_typeof(o->'request_body_required') IN ('boolean','null'),true)
	OR ` + customerSnapshotStringListInvalidSQL("o->'required_request_fields'") + `
	OR ` + customerSnapshotStringListInvalidSQL("o->'response_statuses'") + `) END`

const customerEvidenceContractOwnershipSQL = `c.tenant_id=s.tenant_id AND c.product_id=s.product_id
	AND e.id=c.evidence_id AND e.tenant_id=c.tenant_id AND e.type='openapi_contract'
	AND (coalesce(e.product_id,'')='' OR e.product_id=s.product_id)
	AND (coalesce(e.release_id,'')='' OR e.release_id=c.release_id) ` + customerEvidenceParentConsistencySQL

var customerEvidenceContractsSQL = `SELECT c.id AS sort_id,
	jsonb_build_object('id',c.id,'evidence_id',c.evidence_id,'product_id',c.product_id,'release_id',coalesce(c.release_id,''),
	'version',c.version,'hash',c.hash,'path_count',c.path_count,
	'operation_count',CASE WHEN jsonb_typeof(c.operations)='array' THEN jsonb_array_length(c.operations) ELSE 0 END,
	'operations',CASE WHEN jsonb_typeof(c.operations)='array' AND octet_length(c.operations::text)<=8388608 THEN
	 CASE WHEN jsonb_array_length(c.operations)<=4096 THEN (SELECT coalesce(jsonb_agg(jsonb_build_object(
	 'path',o->'path','method',o->'method','operation_id',o->'operation_id','deprecated',o->'deprecated',
	 'request_body_required',o->'request_body_required','required_request_fields',o->'required_request_fields','response_statuses',o->'response_statuses')),'[]'::jsonb) FROM jsonb_array_elements(c.operations)o) ELSE '[]'::jsonb END
	 ELSE '[]'::jsonb END,
	'created_at',to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(c.id)>1024 OR octet_length(c.evidence_id)>1024 OR c.path_count<0 OR NOT isfinite(c.created_at)
	OR CASE WHEN jsonb_typeof(c.operations)='null' THEN false WHEN jsonb_typeof(c.operations) IS DISTINCT FROM 'array' THEN true
	 WHEN jsonb_array_length(c.operations)>4096 OR octet_length(c.operations::text)>8388608 THEN true
	 ELSE EXISTS(SELECT 1 FROM jsonb_array_elements(c.operations)o WHERE ` + customerSnapshotOperationInvalidSQL + `) END) AS invalid
	FROM scope s JOIN openapi_contracts c ON c.tenant_id=s.tenant_id JOIN evidence_items e ON ` + customerEvidenceContractOwnershipSQL + `
	WHERE coalesce(c.release_id,'')=s.release_id ORDER BY c.id`

var customerEvidenceDiffsSQL = `SELECT d.id AS sort_id,
	jsonb_build_object('id',d.id,'base_contract_id',d.base_contract_id,'target_contract_id',d.target_contract_id,
	'product_id',d.product_id,'release_id',coalesce(d.release_id,''),'result',d.result,
	'breaking_changes',d.document->'breaking_changes','non_breaking_changes',d.document->'non_breaking_changes',
	'schema_version',d.schema_version,'created_at',to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(d.id)>1024 OR octet_length(d.base_contract_id)>1024 OR octet_length(d.target_contract_id)>1024 OR NOT isfinite(d.created_at)
	OR jsonb_typeof(d.document) IS DISTINCT FROM 'object'
	OR ` + customerSnapshotStringListInvalidSQL("d.document->'breaking_changes'") + `
	OR ` + customerSnapshotStringListInvalidSQL("d.document->'non_breaking_changes'") + `) AS invalid
	FROM scope s JOIN contract_diffs d ON d.tenant_id=s.tenant_id AND d.product_id=s.product_id AND coalesce(d.release_id,'')=s.release_id
	WHERE EXISTS(SELECT 1 FROM openapi_contracts c JOIN evidence_items e ON ` + customerEvidenceContractOwnershipSQL + ` WHERE c.id=d.base_contract_id)
	AND EXISTS(SELECT 1 FROM openapi_contracts c JOIN evidence_items e ON ` + customerEvidenceContractOwnershipSQL + ` WHERE c.id=d.target_contract_id)
	ORDER BY d.id`
