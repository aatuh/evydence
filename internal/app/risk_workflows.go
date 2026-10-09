package app

import (
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func validSeverity(severity string) bool {
	switch severity {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validSecurityScanCategory(category string) bool {
	switch category {
	case "sast", "dast", "secret_scan", "license_scan", "api_security":
		return true
	default:
		return false
	}
}

func validManualDocType(typ string) bool {
	switch typ {
	case "threat_model", "security_review", "pen_test_report":
		return true
	default:
		return false
	}
}

func validSensitivity(value string) bool {
	switch value {
	case "internal", "confidential", "restricted":
		return true
	default:
		return false
	}
}

func validVulnWorkflowAction(action string) bool {
	return riskdomain.ValidVulnerabilityWorkflowAction(action)
}

func validPolicyEvidenceType(typ string) bool {
	return riskdomain.ValidPolicyEvidenceType(typ)
}

func validContractDiffResult(result string) bool {
	switch result {
	case "unchanged", "changed", "breaking":
		return true
	default:
		return false
	}
}
