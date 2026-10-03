package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func (l *Ledger) CreateWaiver(ctx context.Context, actor domain.Actor, input CreateWaiverInput) (domain.Waiver, error) {
	value, err := l.riskCommands.CreateWaiver(ctx, actor, riskapp.CreateWaiverInput{
		ScopeType: input.ScopeType, ScopeID: input.ScopeID, ControlID: input.ControlID, PolicyID: input.PolicyID,
		Owner: input.Owner, Risk: input.Risk, Reason: input.Reason, ExpiresAt: input.ExpiresAt, Supersedes: input.Supersedes,
	})
	return waiverFromRiskContext(value), fromRiskContextError(err)
}

func (l *Ledger) ApproveWaiver(ctx context.Context, actor domain.Actor, id string) (domain.Waiver, error) {
	value, err := l.riskCommands.ApproveWaiver(ctx, actor, id)
	return waiverFromRiskContext(value), fromRiskContextError(err)
}

func (l *Ledger) CreateApprovalRecord(ctx context.Context, actor domain.Actor, input CreateApprovalInput) (domain.ApprovalRecord, error) {
	value, err := l.riskCommands.CreateApprovalRecord(ctx, actor, riskapp.CreateApprovalInput{
		SubjectType: input.SubjectType, SubjectID: input.SubjectID, Decision: input.Decision,
		Reason: input.Reason, EvidenceID: input.EvidenceID,
	})
	return approvalFromRiskContext(value), fromRiskContextError(err)
}

func (l *Ledger) EvaluateRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.PolicyEvaluation, error) {
	value, err := l.riskCommands.EvaluateRelease(ctx, actor, releaseID)
	return policyEvaluationFromRiskContext(value), fromRiskContextError(err)
}
