package app

import (
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func validMemoryEvidencePageRequest(in evidencequery.EvidencePageRequest) bool {
	if in.TenantID == "" || strings.TrimSpace(in.TenantID) != in.TenantID || !memoryGovernanceText(in.TenantID, 1024) || in.TenantWide && len(in.AllowedProductIDs)+len(in.AllowedProjectIDs)+len(in.AllowedReleaseIDs) != 0 {
		return false
	}
	if appquery.Validate(in.Page, in.After) != nil {
		return false
	}
	f := in.Filter
	values := []string{f.ProductID, f.ProjectID, f.ReleaseID, f.BuildID, f.DeploymentID, f.Type, f.Subtype, f.SourceSystem, f.CollectorID, f.VerificationStatus, f.SubjectType, f.SubjectID, f.Tag}
	values = append(values, in.AllowedProductIDs...)
	values = append(values, in.AllowedProjectIDs...)
	values = append(values, in.AllowedReleaseIDs...)
	for _, v := range values {
		if !memoryGovernanceText(v, 1024) {
			return false
		}
	}
	for _, v := range []time.Time{f.CreatedAfter, f.CreatedBefore} {
		if !v.IsZero() && (v.UTC().Year() < 1 || v.UTC().Year() > 9999) {
			return false
		}
	}
	if in.After == nil {
		return true
	}
	if in.Page.Sort == appquery.SortID {
		return in.After.Value == in.After.ID
	}
	v, err := time.Parse(time.RFC3339Nano, in.After.Value)
	return err == nil && v.UTC().Year() >= 1 && v.UTC().Year() <= 9999 && v.UTC().Format(time.RFC3339Nano) == in.After.Value
}

// Exact stored fields, not inferred grant coordinates, define search matches.
// This shared pure predicate never clones or selects descriptive metadata.
func memoryEvidencePageMatches(e domain.EvidenceItem, f evidencequery.EvidencePageFilter) bool {
	return matchesEvidenceSearch(e, EvidenceSearchInput{ProductID: f.ProductID, ProjectID: f.ProjectID, ReleaseID: f.ReleaseID, BuildID: f.BuildID, DeploymentID: f.DeploymentID, Type: f.Type, Subtype: f.Subtype, SourceSystem: f.SourceSystem, CollectorID: f.CollectorID, VerificationStatus: f.VerificationStatus, SubjectType: f.SubjectType, SubjectID: f.SubjectID, Tag: f.Tag, CreatedAfter: f.CreatedAfter, CreatedBefore: f.CreatedBefore})
}
