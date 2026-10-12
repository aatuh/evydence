package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func vexDocumentFromQuery(value evidencedomain.VEXDocument) domain.VEXDocument {
	document := domain.VEXDocument{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID,
		ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, Format: value.Format,
		Author: value.Author, Version: value.Version, StatementCount: value.StatementCount,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
	if value.StatusSummary != nil {
		document.StatusSummary = make(map[string]int, len(value.StatusSummary))
		for status, count := range value.StatusSummary {
			document.StatusSummary[status] = count
		}
	}
	return document
}

func vexImportReportFromQuery(value evidencedomain.VEXImportReport) domain.VEXImportReport {
	report := domain.VEXImportReport{
		ID: value.ID, TenantID: value.TenantID, VEXDocumentID: value.VEXDocumentID,
		EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID,
		ParserVersion: value.ParserVersion, Status: value.Status, StatementCount: value.StatementCount,
		DecisionsCreated: value.DecisionsCreated, DecisionsSuperseded: value.DecisionsSuperseded,
		UnsupportedFields: append([]string(nil), value.UnsupportedFields...),
		Warnings:          append([]string(nil), value.Warnings...), FailureCode: value.FailureCode,
		FailureDetail: value.FailureDetail, SchemaVersion: value.SchemaVersion,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
	if value.InvalidStatements != nil {
		report.InvalidStatements = make([]domain.VEXImportIssue, 0, len(value.InvalidStatements))
		for _, issue := range value.InvalidStatements {
			report.InvalidStatements = append(report.InvalidStatements, domain.VEXImportIssue{StatementIndex: issue.StatementIndex, Code: issue.Code, Detail: issue.Detail})
		}
	}
	if value.MappingFailures != nil {
		report.MappingFailures = make([]domain.VEXImportIssue, 0, len(value.MappingFailures))
		for _, issue := range value.MappingFailures {
			report.MappingFailures = append(report.MappingFailures, domain.VEXImportIssue{StatementIndex: issue.StatementIndex, Code: issue.Code, Detail: issue.Detail})
		}
	}
	return report
}
