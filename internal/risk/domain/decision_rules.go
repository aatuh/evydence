package domain

// SupportedDecisionSupportingReference keeps the first-class decision support
// record vocabulary closed. Evidence IDs and VEX documents have separate inputs.
func SupportedDecisionSupportingReference(kind string) bool {
	switch kind {
	case "approval", "exception", "waiver", "remediation_task", "release_bundle", "incident":
		return true
	default:
		return false
	}
}
