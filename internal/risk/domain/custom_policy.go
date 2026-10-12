package domain

// ValidPolicyEvidenceType is the existing custom-policy evidence vocabulary.
func ValidPolicyEvidenceType(value string) bool {
	switch value {
	case "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "artifact", "build", "build_attestation", "openapi_contract", "release_bundle", "exception", "sast", "dast", "secret_scan", "license_scan", "api_security", "deployment", "threat_model", "security_review", "pen_test_report":
		return true
	default:
		return false
	}
}

// EvaluateCustomPolicyRule checks presence only, not payload trust, freshness,
// vulnerability status, approval, or compliance sufficiency.
func EvaluateCustomPolicyRule(rule PolicyRule, present bool) PolicyCheck {
	check := PolicyCheck{Name: rule.Name, Severity: rule.Severity, Result: "passed"}
	switch {
	case rule.EvidenceType == "":
		check.Explanation = "metadata-only custom policy rule recorded"
	case present:
		check.Explanation = rule.EvidenceType + " evidence exists"
	case rule.Required:
		check.Result = "failed"
		check.Missing = []string{rule.EvidenceType}
		check.Explanation = rule.EvidenceType + " evidence is missing"
	default:
		check.Explanation = "optional evidence not present"
	}
	return check
}
