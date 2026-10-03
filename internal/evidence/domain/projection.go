package domain

// RequiresWorkerProjection identifies evidence whose read-time provenance is
// validated against worker-owned records and audit facts. Until focused
// queries prove those relationships, they must use the validated projection.
func RequiresWorkerProjection(evidenceType string) bool {
	switch evidenceType {
	case "parser_normalization", "sbom", "vulnerability_scan", "openapi_contract", "vex", "build_attestation":
		return true
	default:
		return false
	}
}
