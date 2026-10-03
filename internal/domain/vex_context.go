package domain

import evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"

func VEXDocumentFromContext(v evidencedomain.VEXDocument) VEXDocument {
	var summary map[string]int
	if v.StatusSummary != nil {
		summary = make(map[string]int, len(v.StatusSummary))
		for k, n := range v.StatusSummary {
			summary[k] = n
		}
	}
	return VEXDocument{ID: v.ID, TenantID: v.TenantID, EvidenceID: v.EvidenceID, ReleaseID: v.ReleaseID, ArtifactID: v.ArtifactID, Format: v.Format, Author: v.Author, Version: v.Version, StatementCount: v.StatementCount, StatusSummary: summary, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func VEXImportReportFromContext(v evidencedomain.VEXImportReport) VEXImportReport {
	issues := func(values []evidencedomain.VEXImportIssue) []VEXImportIssue {
		result := make([]VEXImportIssue, 0, len(values))
		for _, i := range values {
			result = append(result, VEXImportIssue{StatementIndex: i.StatementIndex, Code: i.Code, Detail: i.Detail})
		}
		return result
	}
	return VEXImportReport{ID: v.ID, TenantID: v.TenantID, VEXDocumentID: v.VEXDocumentID, EvidenceID: v.EvidenceID, ReleaseID: v.ReleaseID, ArtifactID: v.ArtifactID, ParserVersion: v.ParserVersion, Status: v.Status, StatementCount: v.StatementCount, DecisionsCreated: v.DecisionsCreated, DecisionsSuperseded: v.DecisionsSuperseded, UnsupportedFields: append([]string(nil), v.UnsupportedFields...), Warnings: append([]string(nil), v.Warnings...), InvalidStatements: issues(v.InvalidStatements), MappingFailures: issues(v.MappingFailures), FailureCode: v.FailureCode, FailureDetail: v.FailureDetail, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}
