package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Historical package-local characterization only. Current HTTP and production
// writes compose the focused manual command and checked repository append.
func (l *Ledger) CreateVulnerabilityDecision(ctx context.Context, actor domain.Actor, findingID string, in CreateVulnerabilityDecisionInput) (domain.VulnerabilityDecision, error) {
	value, err := l.legacyRiskCommands().CreateVulnerabilityDecision(ctx, actor, findingID, riskapp.CreateVulnerabilityDecisionInput{
		Status: in.Status, Justification: in.Justification, ImpactStatement: in.ImpactStatement,
		ActionStatement: in.ActionStatement, CustomerVisible: in.CustomerVisible, InternalNotes: in.InternalNotes,
		EvidenceIDs: append([]string(nil), in.EvidenceIDs...), SupportingRefs: supportingRefsToRiskContext(in.SupportingRefs),
		VEXDocumentID: in.VEXDocumentID, ReviewedAt: cloneTimePtr(in.ReviewedAt), ReviewDueAt: cloneTimePtr(in.ReviewDueAt),
	})
	return domain.VulnerabilityDecisionFromContextModel(value), fromRiskContextError(err)
}

func supportingRefsToRiskContext(values []domain.SubjectRef) []riskdomain.SupportingReference {
	result := make([]riskdomain.SupportingReference, 0, len(values))
	for _, value := range values {
		result = append(result, riskdomain.SupportingReference{Type: value.Type, ID: value.ID, Digest: value.Digest})
	}
	return result
}

type CreateVulnerabilityDecisionInput struct {
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	CustomerVisible bool
	InternalNotes   string
	EvidenceIDs     []string
	SupportingRefs  []domain.SubjectRef
	VEXDocumentID   string
	ReviewedAt      *time.Time
	ReviewDueAt     *time.Time
}
