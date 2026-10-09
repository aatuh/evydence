package app

import (
	"context"
	"slices"
	"sort"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Selection uses the stored product/project/release filter, not inferred
// authorization parents. Metadata is bounded before projection; payloads and
// arbitrary evidence fields never enter this test-adapter result.
func (r memoryFutureExtensionsRepository) ReadEvidenceSummaryItems(ctx context.Context, s packageapp.EvidenceSummaryScope, ids []string) ([]packageapp.EvidenceSummaryItem, error) {
	if len(ids) > packageapp.MaxEvidenceSummaryItems {
		return nil, ErrValidation
	}
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !memoryMembershipQueryText(id, packageapp.MaxEvidenceSummaryIDBytes) {
			return nil, ErrValidation
		}
		selected[id] = true
	}
	var out []packageapp.EvidenceSummaryItem
	err := memoryGovernanceRead(ctx, r.uow, s.TenantID, s.SubjectID, func(state *MemoryUnitOfWorkSnapshot) error {
		current, err := memorySummaryScope(state, s.TenantID, s.SubjectType, s.SubjectID)
		if err != nil {
			return err
		}
		if current != s {
			return ErrConflict
		}
		out = []packageapp.EvidenceSummaryItem{}
		total := 0
		for key, e := range state.Evidence {
			if e.TenantID != s.TenantID || len(ids) != 0 && !selected[key] {
				continue
			}
			refs := application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID}
			if len(ids) == 0 && (s.Filter.ProductID != "" && refs.ProductID != s.Filter.ProductID || s.Filter.ProjectID != "" && refs.ProjectID != s.Filter.ProjectID || s.Filter.ReleaseID != "" && refs.ReleaseID != s.Filter.ReleaseID) {
				continue
			}
			if len(out) == packageapp.MaxEvidenceSummaryItems {
				return ErrValidation
			}
			if key != e.ID {
				return ErrConflict
			}
			for _, value := range []string{refs.ProductID, refs.ProjectID, refs.ReleaseID} {
				if !memoryMembershipText(value, packageapp.MaxEvidenceSummaryIDBytes) {
					return ErrConflict
				}
				total += len(value)
			}
			for _, field := range []struct {
				value string
				limit int
			}{{e.ID, packageapp.MaxEvidenceSummaryIDBytes}, {e.Type, packageapp.MaxEvidenceSummaryTypeBytes}, {e.Title, packageapp.MaxEvidenceSummaryTitleBytes}, {e.CanonicalHash, packageapp.MaxEvidenceSummaryIDBytes}} {
				if !memoryMembershipText(field.value, field.limit) {
					return ErrValidation
				}
				total += len(field.value)
			}
			if total > packageapp.MaxGeneratedReportBytes {
				return ErrValidation
			}
			out = append(out, packageapp.EvidenceSummaryItem{ID: e.ID, TenantID: e.TenantID, Type: e.Type, Title: e.Title, CanonicalHash: e.CanonicalHash, Resources: refs})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r memoryFutureExtensionsRepository) InsertFocusedEvidenceSummary(ctx context.Context, v packagedomain.EvidenceSummary) error {
	if !memoryMembershipQueryText(v.ID, packageapp.MaxEvidenceSummaryIDBytes) || !memoryMembershipQueryText(v.TenantID, packageapp.MaxEvidenceSummaryIDBytes) ||
		v.SchemaVersion != packagedomain.EvidenceSummaryVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 ||
		len(v.EvidenceIDs) == 0 || len(v.Citations) != len(v.EvidenceIDs) || len(v.Citations) > packageapp.MaxEvidenceSummaryItems ||
		len(v.Assumptions) > packageapp.MaxGeneratedReportBytes || len(v.Limitations) > packageapp.MaxGeneratedReportBytes || v.Summary == "" {
		return ErrValidation
	}
	in, err := packageapp.NormalizeEvidenceSummaryInput(packageapp.CreateEvidenceSummaryInput{SubjectType: v.SubjectType, SubjectID: v.SubjectID, EvidenceIDs: v.EvidenceIDs})
	if err != nil || in.SubjectType != v.SubjectType || in.SubjectID != v.SubjectID || !slices.Equal(in.EvidenceIDs, v.EvidenceIDs) {
		return ErrValidation
	}
	total := 0
	for _, values := range [][]string{{v.ID, v.TenantID, v.SubjectType, v.SubjectID, v.Summary}, v.EvidenceIDs, v.Assumptions, v.Limitations} {
		for _, value := range values {
			if !memoryMembershipText(value, packageapp.MaxGeneratedReportBytes) {
				return ErrValidation
			}
			total += len(value)
			if total > packageapp.MaxGeneratedReportBytes {
				return ErrValidation
			}
		}
	}
	for _, c := range v.Citations {
		for _, value := range []string{c.EvidenceID, c.Type, c.Title, c.CanonicalHash} {
			if !memoryMembershipText(value, packageapp.MaxGeneratedReportBytes) {
				return ErrValidation
			}
			total += len(value)
			if total > packageapp.MaxGeneratedReportBytes {
				return ErrValidation
			}
		}
	}
	s, err := r.ReadEvidenceSummaryScope(ctx, v.TenantID, v.SubjectType, v.SubjectID)
	if err != nil {
		return err
	}
	items, err := r.ReadEvidenceSummaryItems(ctx, s, v.EvidenceIDs)
	if err != nil {
		return err
	}
	if len(items) != len(v.EvidenceIDs) {
		return ErrNotFound
	}
	citations := make([]domain.EvidenceCitation, len(items))
	for i, item := range items {
		c := v.Citations[i]
		if item.ID != v.EvidenceIDs[i] || item.ID != c.EvidenceID || item.Type != c.Type || item.Title != c.Title || item.CanonicalHash != c.CanonicalHash ||
			s.Filter.ProductID != "" && item.Resources.ProductID != s.Filter.ProductID || s.Filter.ProjectID != "" && item.Resources.ProjectID != s.Filter.ProjectID || s.Filter.ReleaseID != "" && item.Resources.ReleaseID != s.Filter.ReleaseID {
			return ErrValidation
		}
		citations[i] = domain.EvidenceCitation{EvidenceID: c.EvidenceID, Type: c.Type, Title: c.Title, CanonicalHash: c.CanonicalHash}
	}
	encoded, err := packageapp.EncodeEvidenceSummary(v)
	if err != nil || len(encoded) > packageapp.MaxGeneratedReportBytes {
		return ErrValidation
	}
	return r.InsertEvidenceSummary(ctx, domain.EvidenceSummary{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, EvidenceIDs: slices.Clone(v.EvidenceIDs), Summary: v.Summary, Citations: citations, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}

var _ packageapp.EvidenceSummaryReader = memoryFutureExtensionsRepository{}
