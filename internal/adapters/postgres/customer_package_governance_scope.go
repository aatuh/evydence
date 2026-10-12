package postgres

func customerGovernanceTextArrayInvalidSQL(column string) string {
	return `(CASE WHEN coalesce(array_ndims(` + column + `)>1,false) THEN true ELSE cardinality(` + column + `)>4096 OR array_position(` + column + `,NULL) IS NOT NULL END)`
}

func customerGovernanceTimeInvalidSQL(column string) string {
	return `coalesce(NOT isfinite(` + column + `) OR extract(year FROM ` + column + ` AT TIME ZONE 'UTC') NOT BETWEEN 1 AND 9999,false)`
}

// Private, fixed scope projections. These are read-only equivalents of the
// decision command's reference checks: no mutation fence, row lock, object
// payload, or approval/incident text is required by a package snapshot.
var customerGovernanceWaiverOwnershipSQL = `((w.scope_type='product' AND w.scope_id=s.product_id) OR (s.release_id<>'' AND w.scope_type='release' AND w.scope_id=s.release_id))
	AND ` + customerGovernanceControlRefSQL("w.control_id") + ` AND (coalesce(w.policy_id,'')='' OR EXISTS(SELECT 1 FROM custom_policies p WHERE p.id=w.policy_id AND p.tenant_id=s.tenant_id))`

var customerGovernanceApprovalOwnershipSQL = `(` + customerGovernanceSubjectSQL + `
	OR (a.subject_type='waiver' AND EXISTS(SELECT 1 FROM waivers w WHERE w.id=a.subject_id AND w.tenant_id=s.tenant_id AND ` + customerGovernanceWaiverOwnershipSQL + `))
	OR (a.subject_type='customer_package' AND EXISTS(SELECT 1 FROM customer_security_packages p JOIN redaction_profiles r ON r.id=p.redaction_profile_id AND r.tenant_id=p.tenant_id
	 WHERE p.id=a.subject_id AND p.tenant_id=s.tenant_id AND p.product_id=s.product_id AND coalesce(p.release_id,'')=s.release_id))
	OR (a.subject_type='contract_diff' AND EXISTS(SELECT 1 FROM contract_diffs d WHERE d.id=a.subject_id AND d.tenant_id=s.tenant_id AND d.product_id=s.product_id AND coalesce(d.release_id,'')=s.release_id
	 AND EXISTS(SELECT 1 FROM openapi_contracts c JOIN evidence_items e ON ` + customerEvidenceContractOwnershipSQL + `
	  WHERE c.id=d.base_contract_id AND (coalesce(c.release_id,'')='' OR EXISTS(SELECT 1 FROM releases r WHERE r.id=c.release_id AND r.tenant_id=s.tenant_id AND r.product_id=s.product_id)))
	 AND EXISTS(SELECT 1 FROM openapi_contracts c JOIN evidence_items e ON ` + customerEvidenceContractOwnershipSQL + `
	  WHERE c.id=d.target_contract_id AND (coalesce(c.release_id,'')='' OR EXISTS(SELECT 1 FROM releases r WHERE r.id=c.release_id AND r.tenant_id=s.tenant_id AND r.product_id=s.product_id)))))
	OR (a.subject_type='security_review' AND EXISTS(SELECT 1 FROM manual_security_documents d JOIN evidence_items e ON e.id=d.evidence_id AND e.tenant_id=d.tenant_id AND e.type='security_review'
	 WHERE d.id=a.subject_id AND d.tenant_id=s.tenant_id AND d.document_type='security_review' AND d.product_id=s.product_id AND coalesce(d.release_id,'')=s.release_id
	 AND coalesce(e.release_id,'')=s.release_id AND ` + customerCatalogEvidenceOwnershipSQL + `)))`
