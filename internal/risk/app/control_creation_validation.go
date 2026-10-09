package app

import (
	"sort"
	"strings"

	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// NormalizeControlFrameworkInput bounds raw text before trimming or slug
// derivation. It is shared by fresh commands and read-only replay guards.
func NormalizeControlFrameworkInput(in CreateControlFrameworkInput) (CreateControlFrameworkInput, error) {
	if !validControlText(in.Name, 65536, true) || !validControlText(in.Slug, 1024, false) || !validControlText(in.Version, 1024, true) || !validControlText(in.Description, 65536, false) {
		return CreateControlFrameworkInput{}, ErrValidation
	}
	in.Name, in.Slug, in.Version, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Slug), strings.TrimSpace(in.Version), strings.TrimSpace(in.Description)
	if in.Slug == "" {
		in.Slug = riskdomain.ControlFrameworkSlug(in.Name)
	}
	if in.Name == "" || in.Slug == "" || in.Version == "" || len(in.Slug)+len(in.Version) > 1024 {
		return CreateControlFrameworkInput{}, ErrValidation
	}
	return in, nil
}

// NormalizeSecurityControlInput copies list fields and retains requirement
// order, sorted applicability with duplicates, and nonblank limitation order.
func NormalizeSecurityControlInput(in CreateSecurityControlInput) (CreateSecurityControlInput, error) {
	if !validControlText(in.FrameworkID, 1024, true) || !validControlText(in.Code, 1024, true) || !validControlText(in.Title, 65536, true) || !validControlText(in.Objective, 65536, true) || len(in.EvidenceRequirements) > 10 || !validControlLists(in.Applicability, in.Limitations) {
		return CreateSecurityControlInput{}, ErrValidation
	}
	in.FrameworkID, in.Code, in.Title, in.Objective = strings.TrimSpace(in.FrameworkID), strings.TrimSpace(in.Code), strings.TrimSpace(in.Title), strings.TrimSpace(in.Objective)
	if in.FrameworkID == "" || in.Code == "" || in.Title == "" || in.Objective == "" {
		return CreateSecurityControlInput{}, ErrValidation
	}
	for _, r := range in.EvidenceRequirements {
		if !validControlText(r.Type, 1024, true) {
			return CreateSecurityControlInput{}, ErrValidation
		}
	}
	requirements, err := riskdomain.NormalizeControlRequirements(in.EvidenceRequirements)
	if err != nil {
		return CreateSecurityControlInput{}, ErrValidation
	}
	in.EvidenceRequirements = requirements
	in.Applicability = append([]string(nil), in.Applicability...)
	for i := range in.Applicability {
		in.Applicability[i] = strings.TrimSpace(in.Applicability[i])
	}
	sort.Strings(in.Applicability)
	limitations := []string{}
	for _, v := range in.Limitations {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			limitations = append(limitations, trimmed)
		}
	}
	in.Limitations = limitations
	return in, nil
}

func validControlTenant(tenant string) bool {
	return validControlText(tenant, 1024, true) && strings.TrimSpace(tenant) == tenant
}
