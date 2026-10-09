package postgres

// Resolve product authority from the tenant-owned release, never from a
// parsed projection's claimed release ID. Reuse the package reader's parent
// predicates so recorded readiness and exported metadata agree on ownership.
const releaseReadinessScopeCTE = `WITH scope AS (
	SELECT r.tenant_id,r.product_id,r.id AS release_id FROM releases r
	JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
	WHERE r.tenant_id=$1 AND r.id=$2
) `

var releaseReadinessScansFromSQL = `FROM scope s JOIN vulnerability_scans d ON d.tenant_id=s.tenant_id
	JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='vulnerability_scan'`

// Finding identity includes the vulnerability and optional component, not
// merely a reused finding ID. Ambiguous duplicate IDs cannot grant handling.
const readinessDecisionFindingMatchSQL = `d.findings @> jsonb_build_array(jsonb_build_object('id',v.finding_id,'vulnerability',v.vulnerability))
	AND EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.findings)='array' THEN d.findings ELSE '[]'::jsonb END) f
	 WHERE f->>'id'=v.finding_id AND coalesce(f->>'component','')=coalesce(v.component,''))
	AND (SELECT count(*) FROM (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.findings)='array' THEN d.findings ELSE '[]'::jsonb END) f WHERE f->>'id'=v.finding_id LIMIT 2) matches)=1`

var readinessDecisionOwnershipSQL = `v.tenant_id=s.tenant_id AND v.release_id=s.release_id
	AND EXISTS(SELECT 1 ` + releaseReadinessScansFromSQL + ` WHERE d.id=v.scan_id AND ` + readinessDecisionFindingMatchSQL + `)`

var readinessExceptionOwnershipSQL = `x.tenant_id=s.tenant_id AND x.release_id=s.release_id
	AND ` + customerGovernanceControlRefSQL("x.control_id") + ` AND ` + customerGovernanceFindingRefSQL("x.finding_id")
