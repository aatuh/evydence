package domain

import "testing"

func TestSupportedDecisionSupportingReferenceIsClosed(t *testing.T) {
	for _, kind := range []string{"approval", "exception", "waiver", "remediation_task", "release_bundle", "incident"} {
		if !SupportedDecisionSupportingReference(kind) {
			t.Fatal("supported decision reference rejected", kind)
		}
	}
	for _, kind := range []string{"", "artifact", "evidence", "vex", "product", "release", "unknown", " approval ", "APPROVAL", "approval\x00"} {
		if SupportedDecisionSupportingReference(kind) {
			t.Fatal("unsupported or unnormalized reference accepted", kind)
		}
	}
}
