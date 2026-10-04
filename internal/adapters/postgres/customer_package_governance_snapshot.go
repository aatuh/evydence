package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// One private component, not a complete production reader. The caller must
// compose catalog, evidence, governance, and the remaining sections in the
// same read-only repeatable-read transaction with one metadata budget.
type customerPackageGovernanceSnapshot struct {
	Decisions, Approvals, Exceptions, Waivers, AnswerLibrary []map[string]any
}

func readCustomerPackageGovernanceTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, profile packagedomain.RedactionProfile, now time.Time, budget *customerSnapshotBudget) (customerPackageGovernanceSnapshot, error) {
	var empty customerPackageGovernanceSnapshot
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return empty, err
	}
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 || now.UTC().Year() < 1 || now.UTC().Year() > 9999 || profile.TenantID != tenant {
		return empty, packageapp.ErrValidation
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return empty, err
	}
	working := *budget
	out := customerPackageGovernanceSnapshot{}
	if packageapp.CustomerPackageIncludesType(profile, "vulnerability_decision") {
		decisions, err := readCustomerSnapshotMetadataRowsAt(ctx, tx, customerGovernanceDecisionsSQL, tenant, product, release, &working, now)
		if err != nil {
			return empty, err
		}
		values := make([]packagedomain.VulnerabilityDecisionSnapshot, 0, len(decisions))
		for _, row := range decisions {
			v, err := customerDecisionSnapshot(row)
			if err != nil {
				return empty, err
			}
			values = append(values, v)
		}
		out.Decisions = packageapp.CustomerPackageDecisionSummaries(values, profile)
	}
	for _, part := range []struct {
		query string
		rows  *[]map[string]any
	}{
		{customerGovernanceApprovalsSQL, &out.Approvals},
		{customerGovernanceExceptionsSQL, &out.Exceptions},
		{customerGovernanceWaiversSQL, &out.Waivers},
		{customerGovernanceAnswersSQL, &out.AnswerLibrary},
	} {
		rows, err := readCustomerSnapshotMetadataRowsAt(ctx, tx, part.query, tenant, product, release, &working, now)
		if err != nil {
			return empty, err
		}
		for _, row := range rows {
			for _, key := range []string{"evidence_ids", "limitations"} {
				if value, exists := row[key]; exists {
					list, err := customerSnapshotStringList(value)
					if err != nil {
						return empty, err
					}
					row[key] = list
				}
			}
		}
		*part.rows = rows
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	*budget = working
	return out, nil
}

func customerDecisionSnapshot(row map[string]any) (packagedomain.VulnerabilityDecisionSnapshot, error) {
	var v packagedomain.VulnerabilityDecisionSnapshot
	for key, target := range map[string]*string{
		"id": &v.ID, "finding_id": &v.FindingID, "scan_id": &v.ScanID, "release_id": &v.ReleaseID,
		"vulnerability": &v.Vulnerability, "component": &v.Component, "sbom_id": &v.SBOMID,
		"sbom_component_purl": &v.SBOMComponentPURL, "sbom_component_name": &v.SBOMComponentName,
		"status": &v.Status, "justification": &v.Justification, "impact_statement": &v.ImpactStatement,
		"action_statement": &v.ActionStatement, "source": &v.Source, "evidence_id": &v.EvidenceID, "vex_document_id": &v.VEXDocumentID,
	} {
		value, ok := row[key].(string)
		if !ok {
			return v, packageapp.ErrConflict
		}
		*target = value
	}
	for key, target := range map[string]**time.Time{"reviewed_at": &v.ReviewedAt, "review_due_at": &v.ReviewDueAt} {
		if row[key] != nil {
			value, ok := row[key].(string)
			at, err := time.Parse(time.RFC3339, value)
			if !ok || err != nil || at.Year() < 1 || at.Year() > 9999 {
				return v, packageapp.ErrConflict
			}
			*target = &at
		}
	}
	created, ok := row["created_at"].(string)
	var err error
	v.CreatedAt, err = time.Parse(time.RFC3339, created)
	if !ok || err != nil || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 {
		return v, packageapp.ErrConflict
	}
	v.EvidenceIDs, err = customerSnapshotStringList(row["evidence_ids"])
	if err != nil {
		return v, err
	}
	for _, id := range v.EvidenceIDs {
		if !customerSnapshotID(id, false) {
			return v, packageapp.ErrConflict
		}
	}
	// SQL has projected only these fields and checked their types and bounds.
	var refs []struct {
		Type   string `json:"type"`
		ID     string `json:"id"`
		Digest string `json:"digest"`
	}
	raw, err := json.Marshal(row["supporting_refs"])
	if err != nil || json.Unmarshal(raw, &refs) != nil {
		return v, packageapp.ErrConflict
	}
	for _, ref := range refs {
		if !customerSnapshotID(ref.ID, false) || !customerSnapshotID(ref.Type, false) {
			return v, packageapp.ErrConflict
		}
		v.SupportingRefs = append(v.SupportingRefs, packagedomain.SupportingReference{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
	}
	return v, nil
}

// All fragments and column names are internal constants. Package coordinates
// are SQL parameters; references resolve against the selected scope before
// any corresponding public statement is transferred.
func customerGovernanceEvidenceRefSQL(column string) string {
	return `(coalesce(` + column + `,'')='' OR EXISTS(SELECT 1 FROM evidence_items e WHERE e.id=` + column + ` AND ` + customerCatalogEvidenceScopeSQL + `))`
}

func customerGovernanceControlRefSQL(column string) string {
	return `(coalesce(` + column + `,'')='' OR EXISTS(SELECT 1 FROM security_controls c JOIN control_frameworks f ON f.id=c.framework_id AND f.tenant_id=c.tenant_id WHERE c.id=` + column + ` AND c.tenant_id=s.tenant_id))`
}

func customerGovernanceFindingRefSQL(column string) string {
	return `(coalesce(` + column + `,'')='' OR EXISTS(SELECT 1 FROM vulnerability_scans d JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='vulnerability_scan'
	 WHERE d.findings @> jsonb_build_array(jsonb_build_object('id',` + column + `))))`
}

const customerGovernanceSubjectSQL = `((a.subject_type='product' AND a.subject_id=s.product_id) OR (s.release_id<>'' AND a.subject_type='release' AND a.subject_id=s.release_id))`

var customerGovernanceApprovalsSQL = `SELECT a.id AS sort_id,jsonb_build_object('id',a.id,'subject_type',a.subject_type,'subject_id',a.subject_id,
	'decision',a.decision,'reason',a.reason,'evidence_id',coalesce(a.evidence_id,''),'created_at',to_char(a.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(a.id)>1024 OR ` + customerGovernanceTimeInvalidSQL("a.created_at") + `) AS invalid
	FROM scope s JOIN approval_records a ON a.tenant_id=s.tenant_id WHERE ` + customerGovernanceSubjectSQL + ` AND ` + customerGovernanceEvidenceRefSQL("a.evidence_id") + ` ORDER BY a.id`

var customerGovernanceExceptionsSQL = `SELECT x.id AS sort_id,jsonb_strip_nulls(jsonb_build_object('id',x.id,'release_id',x.release_id,
	'finding_id',coalesce(x.finding_id,''),'control_id',coalesce(x.control_id,''),'reason',x.reason,'owner',x.owner,'approved',x.approved,
	'expires_at',to_char(x.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'approved_at',to_char(x.approved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'created_at',to_char(x.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'))) AS metadata,
	(octet_length(x.id)>1024 OR ` + customerGovernanceTimeInvalidSQL("x.created_at") + ` OR ` + customerGovernanceTimeInvalidSQL("x.expires_at") + ` OR ` + customerGovernanceTimeInvalidSQL("x.approved_at") + `) AS invalid
	FROM scope s JOIN exceptions x ON x.tenant_id=s.tenant_id AND x.release_id=s.release_id AND s.release_id<>''
	WHERE x.approved AND x.expires_at>s.generated_at AND ` + customerGovernanceControlRefSQL("x.control_id") + ` AND ` + customerGovernanceFindingRefSQL("x.finding_id") + ` ORDER BY x.id`

var customerGovernanceWaiversSQL = `SELECT w.id AS sort_id,jsonb_strip_nulls(jsonb_build_object('id',w.id,'scope_type',w.scope_type,'scope_id',w.scope_id,
	'control_id',coalesce(w.control_id,''),'policy_id',coalesce(w.policy_id,''),'owner',w.owner,'risk',w.risk,'reason',w.reason,'approved',w.approved,
	'expires_at',to_char(w.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'approved_at',to_char(w.approved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'created_at',to_char(w.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'))) AS metadata,
	(octet_length(w.id)>1024 OR ` + customerGovernanceTimeInvalidSQL("w.created_at") + ` OR ` + customerGovernanceTimeInvalidSQL("w.expires_at") + ` OR ` + customerGovernanceTimeInvalidSQL("w.approved_at") + `) AS invalid
	FROM scope s JOIN waivers w ON w.tenant_id=s.tenant_id
	WHERE w.approved AND w.expires_at>s.generated_at AND ` + customerGovernanceWaiverOwnershipSQL + ` ORDER BY w.id`

var customerGovernanceAnswerListsInvalidSQL = `(` + customerGovernanceTextArrayInvalidSQL("a.evidence_ids") + ` OR ` + customerGovernanceTextArrayInvalidSQL("a.limitations") + `)`

var customerGovernanceAnswersSQL = `SELECT a.id AS sort_id,jsonb_build_object('id',a.id,'question_id',coalesce(a.question_id,''),'evidence_type',coalesce(a.evidence_type,''),
	'control_id',coalesce(a.control_id,''),'product_id',coalesce(a.product_id,''),'release_id',coalesce(a.release_id,''),'answer',a.answer,
	'evidence_ids',a.evidence_ids,'limitations',a.limitations,'created_at',to_char(a.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(a.id)>1024 OR ` + customerGovernanceTimeInvalidSQL("a.created_at") + ` OR ` + customerGovernanceAnswerListsInvalidSQL + `) AS invalid
	FROM scope s JOIN questionnaire_answer_library a ON a.tenant_id=s.tenant_id
	WHERE coalesce(a.product_id,s.product_id)=s.product_id AND coalesce(a.release_id,s.release_id)=s.release_id
	AND ` + customerGovernanceControlRefSQL("a.control_id") + `
	AND CASE WHEN ` + customerGovernanceAnswerListsInvalidSQL + ` THEN true ELSE NOT EXISTS(SELECT 1 FROM unnest(a.evidence_ids) ref(id) WHERE NOT ` + customerGovernanceEvidenceRefSQL("ref.id") + ` OR coalesce(ref.id,'')='') END ORDER BY a.id`

const customerGovernanceDecisionRefsInvalidSQL = `CASE WHEN jsonb_typeof(v.supporting_refs) NOT IN ('array','null') THEN true
	WHEN jsonb_typeof(v.supporting_refs)='array' AND jsonb_array_length(v.supporting_refs)>4096 THEN true
	WHEN octet_length(v.supporting_refs::text)>8388608 THEN true
	ELSE EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(v.supporting_refs)='array' THEN v.supporting_refs ELSE '[]'::jsonb END) ref
	 WHERE jsonb_typeof(ref) IS DISTINCT FROM 'object' OR jsonb_typeof(ref->'type') IS DISTINCT FROM 'string' OR jsonb_typeof(ref->'id') IS DISTINCT FROM 'string'
	 OR coalesce(ref->>'type','')='' OR coalesce(ref->>'id','')='' OR octet_length(ref->>'type')>1024 OR octet_length(ref->>'id')>1024
	 OR coalesce(jsonb_typeof(ref->'digest') NOT IN ('string','null'),false) OR octet_length(coalesce(ref->>'digest',''))>1024) END`

var customerGovernanceDecisionEvidenceInvalidSQL = customerGovernanceTextArrayInvalidSQL("v.evidence_ids")

var customerGovernanceDecisionsSQL = `SELECT v.id AS sort_id,jsonb_build_object('id',v.id,'finding_id',v.finding_id,'scan_id',v.scan_id,'release_id',coalesce(v.release_id,''),
	'vulnerability',v.vulnerability,'component',coalesce(v.component,''),'sbom_id',coalesce(v.sbom_id,''),'sbom_component_purl',coalesce(v.sbom_component_purl,''),'sbom_component_name',coalesce(v.sbom_component_name,''),
	'status',v.status,'impact_statement',coalesce(v.impact_statement,''),'source',v.source,'justification',v.justification,'action_statement',coalesce(v.action_statement,''),
	'evidence_id',coalesce(v.evidence_id,''),'evidence_ids',v.evidence_ids,'vex_document_id',coalesce(v.vex_document_id,''),
	'supporting_refs',CASE WHEN (` + customerGovernanceDecisionRefsInvalidSQL + `) THEN '[]'::jsonb ELSE
	 (SELECT coalesce(jsonb_agg(jsonb_build_object('type',ref->'type','id',ref->'id','digest',ref->'digest') ORDER BY position),'[]'::jsonb)
	 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(v.supporting_refs)='array' THEN v.supporting_refs ELSE '[]'::jsonb END) WITH ORDINALITY q(ref,position)) END,
	'reviewed_at',to_char(v.reviewed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'review_due_at',to_char(v.review_due_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'created_at',to_char(v.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(v.id)>1024 OR ` + customerGovernanceTimeInvalidSQL("v.created_at") + ` OR ` + customerGovernanceTimeInvalidSQL("v.reviewed_at") + ` OR ` + customerGovernanceTimeInvalidSQL("v.review_due_at") + `
	 OR ` + customerGovernanceDecisionEvidenceInvalidSQL + ` OR (` + customerGovernanceDecisionRefsInvalidSQL + `)) AS invalid
	FROM scope s JOIN vulnerability_decision_projection v ON v.tenant_id=s.tenant_id AND coalesce(v.release_id,'')=s.release_id
	JOIN vulnerability_scans d ON d.id=v.scan_id AND d.tenant_id=v.tenant_id
	JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='vulnerability_scan'
	WHERE v.customer_visible AND coalesce(v.superseded_by,'')='' AND d.findings @> jsonb_build_array(jsonb_build_object('id',v.finding_id,'vulnerability',v.vulnerability))
	AND (SELECT count(*) FROM (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(d.findings)='array' THEN d.findings ELSE '[]'::jsonb END) f WHERE f->>'id'=v.finding_id LIMIT 2) matches)=1
	AND ` + customerGovernanceEvidenceRefSQL("v.evidence_id") + `
	AND CASE WHEN ` + customerGovernanceDecisionEvidenceInvalidSQL + ` THEN true ELSE NOT EXISTS(SELECT 1 FROM unnest(v.evidence_ids) ref(id) WHERE NOT ` + customerGovernanceEvidenceRefSQL("ref.id") + ` OR coalesce(ref.id,'')='') END
	AND (coalesce(v.sbom_id,'')='' OR EXISTS(SELECT 1 FROM sboms d JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='sbom' WHERE d.id=v.sbom_id AND ` + customerEvidenceArtifactScopeSQL + `))
	AND (coalesce(v.vex_document_id,'')='' OR EXISTS(SELECT 1 FROM vex_documents d JOIN evidence_items e ON ` + customerEvidenceParsedScopeSQL + ` AND e.type='vex' WHERE d.id=v.vex_document_id AND ` + customerEvidenceArtifactScopeSQL + `))
	AND CASE WHEN (` + customerGovernanceDecisionRefsInvalidSQL + `) THEN true ELSE NOT EXISTS(
	 SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(v.supporting_refs)='array' THEN v.supporting_refs ELSE '[]'::jsonb END) ref
	 WHERE NOT (` + customerGovernanceSupportingOwnershipSQL + `)) END ORDER BY v.id`

// Support references retain the six kinds accepted by the decision command.
// They are identifiers/digests only; source objects and private text are never
// selected. Parent ownership is rechecked rather than trusting stored IDs.
var customerGovernanceSupportingOwnershipSQL = `(ref->>'type'='approval' AND EXISTS(SELECT 1 FROM approval_records a WHERE a.id=ref->>'id' AND a.tenant_id=s.tenant_id AND ` + customerGovernanceApprovalOwnershipSQL + ` AND ` + customerGovernanceEvidenceRefSQL("a.evidence_id") + `))
	OR (ref->>'type'='exception' AND EXISTS(SELECT 1 FROM exceptions x WHERE x.id=ref->>'id' AND x.tenant_id=s.tenant_id AND x.release_id=s.release_id AND ` + customerGovernanceControlRefSQL("x.control_id") + ` AND ` + customerGovernanceFindingRefSQL("x.finding_id") + `))
	OR (ref->>'type'='waiver' AND EXISTS(SELECT 1 FROM waivers w WHERE w.id=ref->>'id' AND w.tenant_id=s.tenant_id AND ` + customerGovernanceWaiverOwnershipSQL + `))
	OR (ref->>'type'='release_bundle' AND EXISTS(SELECT 1 FROM release_bundles b WHERE b.id=ref->>'id' AND b.tenant_id=s.tenant_id AND b.release_id=s.release_id AND s.release_id<>''))
	OR (ref->>'type'='incident' AND EXISTS(SELECT 1 FROM incidents i WHERE i.id=ref->>'id' AND i.tenant_id=s.tenant_id AND i.product_id=s.product_id AND i.release_id=s.release_id AND s.release_id<>''))
	OR (ref->>'type'='remediation_task' AND EXISTS(SELECT 1 FROM remediation_tasks t WHERE t.id=ref->>'id' AND t.tenant_id=s.tenant_id
	 AND (coalesce(t.release_id,'')='' OR t.release_id=s.release_id) AND ` + customerGovernanceEvidenceRefSQL("t.evidence_id") + `
	 AND (coalesce(t.incident_id,'')='' OR EXISTS(SELECT 1 FROM incidents i WHERE i.id=t.incident_id AND i.tenant_id=s.tenant_id AND i.product_id=s.product_id AND i.release_id=s.release_id))
	 AND (t.release_id=s.release_id AND s.release_id<>'' OR coalesce(t.incident_id,'')<>'')))`
