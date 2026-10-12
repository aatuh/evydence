package domain

func VEXPreviewAssumptions() []string {
	return []string{
		"Preview results are computed from currently stored scan findings and active decisions for the requested release.",
		"Preview does not store raw VEX payloads, create evidence, create decisions, or enqueue parser jobs.",
	}
}

func VEXPreviewLimitations() []string {
	return []string{
		"Preview is advisory and may change if scans, decisions, exceptions, or releases change before upload.",
		"Preview does not prove legal compliance, complete vulnerability coverage, complete SBOM coverage, or release security.",
	}
}
