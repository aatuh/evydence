package domain

import "testing"

func TestRequiresWorkerProjectionClassifiesProvenanceOwnedTypes(t *testing.T) {
	for _, evidenceType := range []string{"parser_normalization", "sbom", "vulnerability_scan", "openapi_contract", "vex", "build_attestation"} {
		if !RequiresWorkerProjection(evidenceType) {
			t.Fatalf("worker-owned evidence type %q used an unvalidated point read", evidenceType)
		}
	}
	for _, evidenceType := range []string{"", "document", "build", "deployment", "manual_security_document"} {
		if RequiresWorkerProjection(evidenceType) {
			t.Fatalf("ordinary evidence type %q required worker projection", evidenceType)
		}
	}
}
