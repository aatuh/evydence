package domain

import (
	"errors"
	"strings"
)

// NormalizeControlRequirements preserves requirement order and rejects repeated
// evidence kinds. Starter controls and manual controls use the same rules.
func NormalizeControlRequirements(in []ControlEvidenceRequirement) ([]ControlEvidenceRequirement, error) {
	out := make([]ControlEvidenceRequirement, 0, len(in))
	seen := map[string]struct{}{}
	for _, req := range in {
		req.Type = strings.TrimSpace(req.Type)
		if !SupportedControlEvidenceType(req.Type) || req.FreshnessDays < 0 || req.FreshnessDays > 3650 {
			return nil, errors.New("invalid control evidence requirement")
		}
		if _, ok := seen[req.Type]; ok {
			return nil, errors.New("repeated control evidence requirement")
		}
		seen[req.Type] = struct{}{}
		out = append(out, req)
	}
	return out, nil
}

func SupportedControlEvidenceType(value string) bool {
	switch strings.TrimSpace(value) {
	case "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "artifact", "build", "build_attestation", "openapi_contract", "release_bundle", "exception":
		return true
	default:
		return false
	}
}

func SupportedControlEvidenceSubject(value string) bool {
	switch strings.TrimSpace(value) {
	case "evidence", "evidence_item", "product", "release", "artifact", "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "finding", "vulnerability_finding", "exception", "build", "build_attestation", "openapi_contract", "release_bundle":
		return true
	default:
		return false
	}
}

func ValidControlConfidence(value string) bool {
	switch strings.TrimSpace(value) {
	case "high", "medium", "low", "unsupported":
		return true
	default:
		return false
	}
}

// ControlFrameworkSlug retains the existing ASCII slug derivation for omitted
// manual-framework slugs. Explicit slugs are not rewritten.
func ControlFrameworkSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
