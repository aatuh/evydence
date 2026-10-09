package domain

import "testing"

func TestControlEvidenceSubjectAndConfidenceRules(t *testing.T) {
	for _, subject := range []string{"evidence", "evidence_item", "product", "release", "artifact", "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "finding", "vulnerability_finding", "exception", "build", "build_attestation", "openapi_contract", "release_bundle"} {
		if !SupportedControlEvidenceSubject(subject) || !SupportedControlEvidenceSubject(" "+subject+" ") {
			t.Fatalf("supported subject rejected: %q", subject)
		}
	}
	// These may be valid references elsewhere, but the control-link command
	// has never accepted them as evidence subjects.
	for _, subject := range []string{"", "unknown", "security_scan", "incident", "deployment", "customer_package", "Evidence", "artifact\x00"} {
		if SupportedControlEvidenceSubject(subject) {
			t.Fatalf("unsupported subject accepted: %q", subject)
		}
	}
	for _, confidence := range []string{"high", "medium", "low", "unsupported"} {
		if !ValidControlConfidence(confidence) || !ValidControlConfidence(" "+confidence+" ") {
			t.Fatalf("supported confidence rejected: %q", confidence)
		}
	}
	for _, confidence := range []string{"", "certain", "High", "high\x00"} {
		if ValidControlConfidence(confidence) {
			t.Fatalf("unsupported confidence accepted: %q", confidence)
		}
	}
}
