package app

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical summary declarations retained unchanged for package-local tests.
// HTTP fixtures use focused commands and bounded repository projections;
// these methods are not a runtime backend or proof of native SQL behavior.

type CreateEvidenceSummaryInput struct {
	SubjectType string
	SubjectID   string
	EvidenceIDs []string
}

func (l *Ledger) CreateEvidenceSummary(ctx context.Context, actor domain.Actor, in CreateEvidenceSummaryInput) (domain.EvidenceSummary, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceSummary{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.EvidenceSummary{}, err
	}
	subjectType, subjectID := strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	if subjectType == "" || subjectID == "" {
		return domain.EvidenceSummary{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	refs, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID)
	if err != nil {
		return domain.EvidenceSummary{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, refs); err != nil {
		return domain.EvidenceSummary{}, err
	}
	evidenceIDs := sortedStrings(in.EvidenceIDs)
	if len(evidenceIDs) > MaxEvidenceSummaryItems {
		return domain.EvidenceSummary{}, ErrValidation
	}
	if len(evidenceIDs) == 0 {
		var exceeded bool
		evidenceIDs, exceeded = l.evidenceIDsForRefsBoundedLocked(actor.TenantID, refs, "", MaxEvidenceSummaryItems)
		if exceeded {
			return domain.EvidenceSummary{}, ErrValidation
		}
	}
	if len(evidenceIDs) == 0 {
		return domain.EvidenceSummary{}, ErrValidation
	}
	citations := make([]domain.EvidenceCitation, 0, len(evidenceIDs))
	titles := make([]string, 0, len(evidenceIDs))
	for _, id := range evidenceIDs {
		item, ok := l.evidence[id]
		if !ok || item.TenantID != actor.TenantID {
			return domain.EvidenceSummary{}, ErrNotFound
		}
		if !evidenceMatchesRefs(item, refs) {
			return domain.EvidenceSummary{}, ErrValidation
		}
		citations = append(citations, domain.EvidenceCitation{EvidenceID: item.ID, Type: item.Type, Title: item.Title, CanonicalHash: item.CanonicalHash})
		titles = append(titles, item.Title)
	}
	summaryText := "Technical evidence recorded for " + subjectType + " " + subjectID + ": " + strings.Join(titles, "; ") + "."
	summary := domain.EvidenceSummary{
		ID:            newID("sum"),
		TenantID:      actor.TenantID,
		SubjectType:   subjectType,
		SubjectID:     subjectID,
		EvidenceIDs:   evidenceIDs,
		Summary:       summaryText,
		Citations:     citations,
		Assumptions:   []string{"Summary is generated only from explicitly linked Evydence records."},
		Limitations:   []string{"This summary supports evidence review and does not assert legal compliance, certification, or release security."},
		SchemaVersion: domain.EvidenceSummaryVersion,
		CreatedAt:     l.now(),
	}
	encodedSummary, err := json.Marshal(summary)
	if err != nil {
		return domain.EvidenceSummary{}, err
	}
	if len(encodedSummary) > MaxGeneratedReportBytes {
		return domain.EvidenceSummary{}, ErrValidation
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertEvidenceSummary(ctx, summary); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(summary.CreatedAt, actor.TenantID, "evidence_summary.created", "evidence_summary", summary.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.EvidenceSummary{}, err
		}
		l.evidenceSummaries[summary.ID] = summary
		l.publishCommittedAuditEntryLocked(entry)
		return summary, nil
	}
	l.evidenceSummaries[summary.ID] = summary
	_, _ = l.appendChainLocked(actor.TenantID, "evidence_summary.created", "evidence_summary", summary.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceSummary{}, err
	}
	return summary, nil
}
