package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

// Unchanged aggregate governance facades and inputs are test oracles only.
type CreateWaiverInput struct {
	ScopeType  string
	ScopeID    string
	ControlID  string
	PolicyID   string
	Owner      string
	Risk       string
	Reason     string
	ExpiresAt  time.Time
	Supersedes string
}

type CreateApprovalInput struct {
	SubjectType string
	SubjectID   string
	Decision    string
	Reason      string
	EvidenceID  string
}

type CreateExceptionInput struct {
	ReleaseID string
	FindingID string
	ControlID string
	Reason    string
	Owner     string
	ExpiresAt time.Time
}

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

func (l *Ledger) CreateException(ctx context.Context, actor domain.Actor, in CreateExceptionInput) (domain.Exception, error) {
	value, err := l.riskCommands.CreateException(ctx, actor, riskapp.CreateExceptionInput{
		ReleaseID: in.ReleaseID, FindingID: in.FindingID, ControlID: in.ControlID,
		Reason: in.Reason, Owner: in.Owner, ExpiresAt: in.ExpiresAt,
	})
	return exceptionFromRiskContext(value), fromRiskContextError(err)
}

func (l *Ledger) ApproveException(ctx context.Context, actor domain.Actor, id string) (domain.Exception, error) {
	value, err := l.riskCommands.ApproveException(ctx, actor, id)
	return exceptionFromRiskContext(value), fromRiskContextError(err)
}
