package app

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.VEXPointReader = memoryEvidenceRepository{}

const memoryVEXPointJSONBytes = 16 << 20

// Current typed VEX/source/parent rows model native point policy. Memory
// checks are not proof of SQL JSON shapes, work/transfer bounds or locks.
func (r memoryEvidenceRepository) GetVEXDocumentPoint(ctx context.Context, tenant, id string) (evidencequery.VEXDocumentPoint, error) {
	var out evidencequery.VEXDocumentPoint
	err := r.parsedPointRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot, id string) error {
		var err error
		out, err = readMemoryVEXPoint(s, tenant, id)
		return err
	})
	if err != nil {
		return evidencequery.VEXDocumentPoint{}, err
	}
	return out, nil
}

func (r memoryEvidenceRepository) GetVEXImportReportPoint(ctx context.Context, tenant, id string) (evidencequery.VEXImportReportPoint, error) {
	var out evidencequery.VEXImportReportPoint
	err := r.parsedPointRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot, id string) error {
		document, err := readMemoryVEXPoint(s, tenant, id)
		if err != nil {
			return err
		}
		var report domain.VEXImportReport
		found := false
		for key, candidate := range s.VEXImportReports {
			if err := ctx.Err(); err != nil {
				return err
			}
			if candidate.TenantID != tenant || candidate.VEXDocumentID != id {
				continue
			}
			if found || candidate.ID != key {
				return evidencequery.ErrConflict
			}
			report, found = candidate, true
		}
		if !found {
			return evidencequery.ErrNotFound
		}
		for _, value := range []any{report.Warnings, report.InvalidStatements, report.MappingFailures} {
			if !memoryVEXJSONFits(value) {
				return evidencequery.ErrConflict
			}
		}
		if report.UpdatedAt.Before(report.CreatedAt) && report.Status != "accepted" {
			report.UpdatedAt = report.CreatedAt
		}
		out = evidencequery.VEXImportReportPoint{Document: document, Report: evidencedomain.VEXImportReport{
			ID: report.ID, TenantID: report.TenantID, VEXDocumentID: report.VEXDocumentID, EvidenceID: report.EvidenceID, ReleaseID: report.ReleaseID, ArtifactID: report.ArtifactID,
			ParserVersion: report.ParserVersion, Status: report.Status, StatementCount: report.StatementCount, DecisionsCreated: report.DecisionsCreated, DecisionsSuperseded: report.DecisionsSuperseded,
			UnsupportedFields: slices.Clone(report.UnsupportedFields), Warnings: slices.Clone(report.Warnings), InvalidStatements: memoryVEXIssues(report.InvalidStatements), MappingFailures: memoryVEXIssues(report.MappingFailures),
			FailureCode: report.FailureCode, FailureDetail: report.FailureDetail, SchemaVersion: report.SchemaVersion, CreatedAt: report.CreatedAt, UpdatedAt: report.UpdatedAt,
		}}
		return nil
	})
	if err != nil {
		return evidencequery.VEXImportReportPoint{}, err
	}
	return out, nil
}

func readMemoryVEXPoint(s *MemoryUnitOfWorkSnapshot, tenant, id string) (evidencequery.VEXDocumentPoint, error) {
	var empty evidencequery.VEXDocumentPoint
	d, ok := s.VEXDocuments[id]
	if !ok || d.ID != id || d.TenantID != tenant {
		return empty, evidencequery.ErrNotFound
	}
	e, refs, err := memoryParsedSource(s, tenant, d.EvidenceID, "vex")
	if err != nil {
		return empty, err
	}
	if e.ReleaseID != d.ReleaseID || refs.ReleaseID != d.ReleaseID {
		return empty, evidencequery.ErrNotFound
	}
	artifacts := map[string]bool{}
	for _, ref := range e.SubjectRefs {
		if ref.Type == "artifact" && ref.ID != "" {
			artifacts[ref.ID] = true
		}
	}
	if d.ArtifactID == "" && len(artifacts) != 0 || d.ArtifactID != "" && (len(artifacts) != 1 || !artifacts[d.ArtifactID]) {
		return empty, evidencequery.ErrNotFound
	}
	if d.ArtifactID != "" {
		a, ok := s.Artifacts[d.ArtifactID]
		if !ok || a.ID != d.ArtifactID || a.TenantID != tenant {
			return empty, evidencequery.ErrNotFound
		}
	}
	if !memoryVEXJSONFits(d.StatusSummary) {
		return empty, evidencequery.ErrConflict
	}
	return evidencequery.VEXDocumentPoint{Document: vexDocumentToEvidenceContext(d), ProductID: refs.ProductID}, nil
}

func memoryVEXJSONFits(value any) bool {
	raw, err := json.Marshal(value)
	return err == nil && len(raw) <= memoryVEXPointJSONBytes
}

func memoryVEXIssues(values []domain.VEXImportIssue) []evidencedomain.VEXImportIssue {
	if values == nil {
		return nil
	}
	out := make([]evidencedomain.VEXImportIssue, len(values))
	for i, v := range values {
		out[i] = evidencedomain.VEXImportIssue{StatementIndex: v.StatementIndex, Code: v.Code, Detail: v.Detail}
	}
	return out
}
