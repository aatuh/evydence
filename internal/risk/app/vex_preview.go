package app

import (
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Preview needs only immutable finding coordinates and active-decision presence,
// never decision text, private notes, or mutable aggregate state.
type VEXPreviewFinding struct {
	VEXFinding
	HasActiveDecision bool
}
type VEXDecisionPreviewInput struct {
	Format, TenantID, ReleaseID string
	Statements                  []VEXStatement
	Findings                    []VEXPreviewFinding
}
type VEXDecisionPreviewResult struct {
	WouldCreate, WouldSupersede int
	Warnings                    []string
	Failures                    []VEXMappingFailure
}

func PreviewVEXDecisionEffects(in VEXDecisionPreviewInput) (VEXDecisionPreviewResult, error) {
	if (in.Format != "openvex" && in.Format != "cyclonedx") || in.TenantID == "" || in.ReleaseID == "" || len(in.Statements) == 0 {
		return VEXDecisionPreviewResult{}, ErrValidation
	}
	byVulnerability := map[string][]VEXFinding{}
	active, seenIDs := map[string]bool{}, map[string]bool{}
	for _, f := range in.Findings {
		v := normalizeVEXFinding(f.VEXFinding)
		if v.TenantID != in.TenantID || v.ReleaseID != in.ReleaseID {
			return VEXDecisionPreviewResult{}, ErrNotFound
		}
		if v.ID == "" || v.ScanID == "" || v.Vulnerability == "" || seenIDs[v.ID] {
			return VEXDecisionPreviewResult{}, ErrValidation
		}
		seenIDs[v.ID], active[v.ID] = true, f.HasActiveDecision
		byVulnerability[v.Vulnerability] = append(byVulnerability[v.Vulnerability], v)
	}
	result := VEXDecisionPreviewResult{Warnings: []string{}, Failures: []VEXMappingFailure{}}
	seenFindings, seenIndexes := map[string]bool{}, map[int]bool{}
	for _, original := range in.Statements {
		s := normalizeVEXStatement(original)
		if s.Index <= 0 || seenIndexes[s.Index] || s.Vulnerability == "" {
			return VEXDecisionPreviewResult{}, ErrValidation
		}
		seenIndexes[s.Index] = true
		if _, err := riskdomain.ParseDecisionStatus(s.Status); err != nil {
			return VEXDecisionPreviewResult{}, ErrValidation
		}
		matches := matchingVEXFindings(byVulnerability[s.Vulnerability], s)
		detail, duplicateWarning := "this VEX statement", "Duplicate VEX statements for an already mapped finding were ignored."
		if in.Format == "cyclonedx" {
			detail, duplicateWarning = "this CycloneDX VEX vulnerability", "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored."
		}
		if !unambiguousVEXMatches(matches, s.Products) {
			result.Failures = append(result.Failures, VEXMappingFailure{StatementIndex: s.Index, Code: "ambiguous_finding", Detail: "Multiple plausible findings matched " + detail + "; no decision would be applied."})
			continue
		}
		if len(matches) == 0 {
			result.Failures = append(result.Failures, VEXMappingFailure{StatementIndex: s.Index, Code: "finding_not_found", Detail: "No matching vulnerability scan finding was found for " + detail + "."})
		}
		for _, f := range matches {
			if seenFindings[f.ID] {
				if len(result.Warnings) == 0 {
					result.Warnings = append(result.Warnings, duplicateWarning)
				}
				continue
			}
			seenFindings[f.ID] = true
			result.WouldCreate++
			if active[f.ID] {
				result.WouldSupersede++
			}
		}
	}
	return result, nil
}
