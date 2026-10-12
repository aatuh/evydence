package app

import (
	"context"
	"errors"
	"slices"

	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// CompleteVEXImportReport models the worker's mutable accepted projection in a
// transaction. It is not a runtime worker, claim fence or durable SQL proof.
func (r memoryEvidenceRepository) CompleteVEXImportReport(ctx context.Context, report domain.VEXImportReport) error {
	if ctx == nil || r.uow == nil {
		return ErrValidation
	}
	report.Warnings = slices.Clone(report.Warnings)
	report.UnsupportedFields = slices.Clone(report.UnsupportedFields)
	report.InvalidStatements = slices.Clone(report.InvalidStatements)
	report.MappingFailures = slices.Clone(report.MappingFailures)
	return r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		old, ok := s.VEXImportReports[report.ID]
		if !ok || old.ID != report.ID || old.TenantID != report.TenantID {
			return ErrNotFound
		}
		if old.Status != "accepted" || report.Status != "parsed" || report.VEXDocumentID != old.VEXDocumentID || report.EvidenceID != old.EvidenceID || report.ReleaseID != old.ReleaseID || report.ArtifactID != old.ArtifactID || report.ParserVersion != old.ParserVersion || report.ParserVersion == "" || report.SchemaVersion != old.SchemaVersion || report.SchemaVersion == "" || report.StatementCount != old.StatementCount || report.StatementCount < 0 || !report.CreatedAt.Equal(old.CreatedAt) || report.CreatedAt.IsZero() || !slices.Equal(report.UnsupportedFields, old.UnsupportedFields) || !slices.Equal(report.InvalidStatements, old.InvalidStatements) || report.DecisionsCreated < 0 || report.DecisionsSuperseded < 0 || report.FailureCode != "" || report.FailureDetail != "" || report.UpdatedAt.Before(old.UpdatedAt) || report.UpdatedAt.Before(old.CreatedAt) || report.UpdatedAt.IsZero() {
			return ErrConflict
		}
		point, err := readMemoryVEXPoint(s, report.TenantID, report.VEXDocumentID)
		if errors.Is(err, evidencequery.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return ErrConflict
		}
		doc := point.Document
		if report.EvidenceID != doc.EvidenceID || report.ReleaseID != doc.ReleaseID || report.ArtifactID != doc.ArtifactID || report.StatementCount != doc.StatementCount || doc.Format == "" || doc.SchemaVersion == "" || doc.CreatedAt.IsZero() {
			return ErrConflict
		}
		for key, other := range s.VEXImportReports {
			if other.TenantID == report.TenantID && other.VEXDocumentID == report.VEXDocumentID && key != report.ID {
				return ErrConflict
			}
		}
		for _, value := range []any{report.Warnings, report.InvalidStatements, report.MappingFailures} {
			if !memoryVEXJSONFits(value) {
				return ErrConflict
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		s.VEXImportReports[report.ID] = report
		return nil
	})
}
