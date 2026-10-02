package repositories

// Identifier-only parent projections. All relationship arrays/documents are
// queried inside PostgreSQL, never scanned into the command service.
const controlEvidenceParentCTEs = `WITH valid_projects AS NOT MATERIALIZED (
 SELECT j.id,j.tenant_id,j.product_id FROM projects j JOIN products p ON p.id=j.product_id AND p.tenant_id=j.tenant_id WHERE j.tenant_id=$1
),valid_releases AS NOT MATERIALIZED (
 SELECT r.id,r.tenant_id,r.product_id FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1
),valid_evidence AS NOT MATERIALIZED (
 SELECT e.id,e.tenant_id,e.type,e.project_id,e.release_id,e.subject_refs,COALESCE(e.product_id,j.product_id,r.product_id) AS product_id
 FROM evidence_items e
 LEFT JOIN products p ON p.id=e.product_id AND p.tenant_id=e.tenant_id
 LEFT JOIN valid_projects j ON j.id=e.project_id AND j.tenant_id=e.tenant_id
 LEFT JOIN valid_releases r ON r.id=e.release_id AND r.tenant_id=e.tenant_id
 WHERE e.tenant_id=$1 AND (e.product_id IS NULL OR p.id IS NOT NULL) AND (e.project_id IS NULL OR j.id IS NOT NULL) AND (e.release_id IS NULL OR r.id IS NOT NULL)
 AND (e.product_id IS NULL OR j.id IS NULL OR e.product_id=j.product_id) AND (e.product_id IS NULL OR r.id IS NULL OR e.product_id=r.product_id) AND (j.id IS NULL OR r.id IS NULL OR j.product_id=r.product_id)
) `

const controlEvidenceArtifactAssociations = `
 SELECT e.product_id,e.project_id,e.release_id FROM artifacts a JOIN valid_evidence e ON e.tenant_id=a.tenant_id AND e.subject_refs @> jsonb_build_array(jsonb_build_object('type','artifact','id',a.id)) WHERE a.tenant_id=$1 AND a.id=$2
 UNION ALL
 SELECT r.product_id,b.project_id,b.release_id FROM artifacts a JOIN build_runs b ON b.tenant_id=a.tenant_id AND b.outputs @> jsonb_build_array(jsonb_build_object('artifact_id',a.id,'digest',a.digest)) JOIN valid_projects j ON j.id=b.project_id AND j.tenant_id=b.tenant_id JOIN valid_releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=j.product_id WHERE a.tenant_id=$1 AND a.id=$2`

const parsedControlSubjectAgreement = ` AND (COALESCE(s.release_id,e.release_id) IS NULL OR r.id IS NOT NULL) AND (s.release_id IS NULL OR e.release_id IS NULL OR s.release_id=e.release_id) AND (e.product_id IS NULL OR r.id IS NULL OR e.product_id=r.product_id)`

func controlEvidenceSubjectProjection(kind string) string {
	switch kind {
	case "evidence", "evidence_item":
		return `SELECT e.product_id,e.project_id,e.release_id FROM valid_evidence e WHERE e.id=$2`
	case "product":
		return `SELECT p.id AS product_id,NULL::text AS project_id,NULL::text AS release_id FROM products p WHERE p.tenant_id=$1 AND p.id=$2`
	case "release":
		return `SELECT r.product_id,NULL::text AS project_id,r.id AS release_id FROM valid_releases r WHERE r.id=$2`
	case "artifact":
		return `SELECT NULL::text AS product_id,NULL::text AS project_id,NULL::text AS release_id FROM artifacts a WHERE a.tenant_id=$1 AND a.id=$2 AND $3::text='' AND $4::text='' UNION ALL ` + controlEvidenceArtifactAssociations
	case "sbom", "vulnerability_scan", "vex":
		table, source := "sboms", "sbom"
		if kind == "vulnerability_scan" {
			table, source = "vulnerability_scans", "vulnerability_scan"
		}
		if kind == "vex" {
			table, source = "vex_documents", "vex"
		}
		artifactParent := ""
		if kind != "vulnerability_scan" {
			artifactParent = ` AND (s.artifact_id IS NULL OR EXISTS(SELECT 1 FROM artifacts a WHERE a.id=s.artifact_id AND a.tenant_id=s.tenant_id))`
		}
		// Both strings are closed, internal constants; never request values.
		return `SELECT COALESCE(e.product_id,r.product_id) AS product_id,e.project_id,COALESCE(s.release_id,e.release_id) AS release_id FROM ` + table + ` s JOIN valid_evidence e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id AND e.type='` + source + `' LEFT JOIN valid_releases r ON r.id=COALESCE(s.release_id,e.release_id) AND r.tenant_id=s.tenant_id WHERE s.tenant_id=$1 AND s.id=$2` + parsedControlSubjectAgreement + artifactParent
	case "finding", "vulnerability_finding":
		return `SELECT COALESCE(e.product_id,r.product_id) AS product_id,e.project_id,COALESCE(s.release_id,e.release_id) AS release_id FROM vulnerability_scans s JOIN valid_evidence e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id AND e.type='vulnerability_scan' LEFT JOIN valid_releases r ON r.id=COALESCE(s.release_id,e.release_id) AND r.tenant_id=s.tenant_id WHERE s.tenant_id=$1 AND s.findings @> jsonb_build_array(jsonb_build_object('id',$2::text))` + parsedControlSubjectAgreement
	case "vulnerability_decision":
		return `SELECT COALESCE(e.product_id,r.product_id) AS product_id,e.project_id,COALESCE(d.release_id,s.release_id,e.release_id) AS release_id FROM vulnerability_decisions d JOIN vulnerability_scans s ON s.id=d.scan_id AND s.tenant_id=d.tenant_id AND s.findings @> jsonb_build_array(jsonb_build_object('id',d.finding_id)) JOIN valid_evidence e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id AND e.type='vulnerability_scan' LEFT JOIN valid_releases r ON r.id=COALESCE(d.release_id,s.release_id,e.release_id) AND r.tenant_id=d.tenant_id WHERE d.tenant_id=$1 AND d.id=$2 AND (COALESCE(d.release_id,s.release_id,e.release_id) IS NULL OR r.id IS NOT NULL) AND (d.release_id IS NULL OR s.release_id IS NULL OR d.release_id=s.release_id) AND (d.release_id IS NULL OR e.release_id IS NULL OR d.release_id=e.release_id) AND (s.release_id IS NULL OR e.release_id IS NULL OR s.release_id=e.release_id) AND (e.product_id IS NULL OR r.id IS NULL OR e.product_id=r.product_id)`
	case "exception":
		return `SELECT r.product_id,NULL::text AS project_id,x.release_id FROM exceptions x JOIN valid_releases r ON r.id=x.release_id AND r.tenant_id=x.tenant_id WHERE x.tenant_id=$1 AND x.id=$2`
	case "build":
		return `SELECT r.product_id,b.project_id,b.release_id FROM build_runs b JOIN valid_projects j ON j.id=b.project_id AND j.tenant_id=b.tenant_id JOIN valid_releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=j.product_id WHERE b.tenant_id=$1 AND b.id=$2`
	case "build_attestation":
		return `SELECT r.product_id,b.project_id,b.release_id FROM build_attestations a JOIN build_runs b ON b.id=a.build_id AND b.tenant_id=a.tenant_id JOIN valid_evidence e ON e.id=a.evidence_id AND e.tenant_id=a.tenant_id AND e.type='build_attestation' JOIN valid_projects j ON j.id=b.project_id AND j.tenant_id=b.tenant_id JOIN valid_releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=j.product_id WHERE a.tenant_id=$1 AND a.id=$2 AND (e.product_id IS NULL OR e.product_id=r.product_id) AND (e.project_id IS NULL OR e.project_id=b.project_id) AND (e.release_id IS NULL OR e.release_id=b.release_id)`
	case "openapi_contract":
		return `SELECT c.product_id,NULL::text AS project_id,c.release_id FROM openapi_contracts c JOIN products p ON p.id=c.product_id AND p.tenant_id=c.tenant_id JOIN valid_evidence e ON e.id=c.evidence_id AND e.tenant_id=c.tenant_id AND e.type='openapi_contract' LEFT JOIN valid_releases r ON r.id=c.release_id AND r.tenant_id=c.tenant_id AND r.product_id=c.product_id WHERE c.tenant_id=$1 AND c.id=$2 AND (c.release_id IS NULL OR r.id IS NOT NULL) AND (e.product_id IS NULL OR e.product_id=c.product_id) AND (e.release_id IS NULL OR c.release_id IS NULL OR e.release_id=c.release_id)`
	case "release_bundle":
		return `SELECT r.product_id,NULL::text AS project_id,b.release_id FROM release_bundles b JOIN valid_releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id WHERE b.tenant_id=$1 AND b.id=$2`
	default:
		return ""
	}
}
