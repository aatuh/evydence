package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// ApprovalReader returns only current subject ownership and evidence existence,
// never documents, package manifests, historical reasons, or tenant inventories.
type ApprovalReader interface {
	ReadApprovalSubject(context.Context, string, string, string) (GovernanceSubjectReference, error)
	ApprovalEvidenceExists(context.Context, string, string) (bool, error)
}
type ApprovalTransaction interface {
	ApprovalReader
	application.Authorizer
	application.AuditAppender
	InsertApprovalRecord(context.Context, riskdomain.ApprovalRecord) error
}
type ApprovalTransactionRunner interface {
	ExecuteApproval(context.Context, func(context.Context, ApprovalTransaction) error) error
}
type ApprovalCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ApprovalTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ApprovalCommands struct{ config ApprovalCommandConfig }

func NewApprovalCommands(config ApprovalCommandConfig) (*ApprovalCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ApprovalCommands{config}, nil
}

func (s *ApprovalCommands) prepare(ctx context.Context, actor identitydomain.Actor, input CreateApprovalInput) (CreateApprovalInput, error) {
	if s == nil {
		return input, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return input, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return input, err
	}
	for _, v := range []string{actor.TenantID, auditActorID(actor), input.SubjectID, input.EvidenceID} {
		if !validControlText(v, 1024, false) {
			return input, ErrValidation
		}
	}
	if !validControlText(input.SubjectType, 128, false) || !validControlText(input.Decision, 128, false) || !validControlText(input.Reason, 65536, false) {
		return input, ErrValidation
	}
	input.SubjectType, input.SubjectID, input.Decision = strings.TrimSpace(input.SubjectType), strings.TrimSpace(input.SubjectID), strings.TrimSpace(input.Decision)
	input.Reason, input.EvidenceID = strings.TrimSpace(input.Reason), strings.TrimSpace(input.EvidenceID)
	if strings.TrimSpace(actor.TenantID) == "" || strings.TrimSpace(auditActorID(actor)) == "" || !validApprovalSubject(input.SubjectType) || input.SubjectID == "" || !validApprovalDecision(input.Decision) || input.Reason == "" {
		return input, ErrValidation
	}
	return input, nil
}

// AuthorizeApproval runs before reservation/replay in the same durable unit of
// work. It does not append anything or load evidence payloads.
func (s *ApprovalCommands) AuthorizeApproval(ctx context.Context, actor identitydomain.Actor, input CreateApprovalInput) error {
	input, err := s.prepare(ctx, actor, input)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteApproval(ctx, func(ctx context.Context, tx ApprovalTransaction) error {
		return authorizeApprovalSubject(ctx, tx, actor, input)
	})
}

func authorizeApprovalSubject(ctx context.Context, tx ApprovalTransaction, actor identitydomain.Actor, input CreateApprovalInput) error {
	if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return err
	}
	subject, err := tx.ReadApprovalSubject(ctx, actor.TenantID, input.SubjectType, input.SubjectID)
	if err != nil {
		return err
	}
	if !validGovernanceSubject(subject, actor.TenantID, input.SubjectType, input.SubjectID) || subject.ProductID == "" && subject.ReleaseID != "" {
		return ErrNotFound
	}
	if subject.Type != "waiver" && subject.ProductID == "" || subject.Type == "release" && subject.ReleaseID != subject.ID {
		return ErrNotFound
	}
	if !validControlText(subject.ProductID, 1024, false) || !validControlText(subject.ReleaseID, 1024, false) {
		return ErrValidation
	}
	return tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: subjectResources(subject), TenantWide: subject.ProductID == ""})
}

func (s *ApprovalCommands) CreateApprovalRecord(ctx context.Context, actor identitydomain.Actor, input CreateApprovalInput) (riskdomain.ApprovalRecord, error) {
	input, err := s.prepare(ctx, actor, input)
	if err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	now := s.config.Clock.Now().UTC()
	if now.IsZero() {
		return riskdomain.ApprovalRecord{}, ErrValidation
	}
	var approval riskdomain.ApprovalRecord
	err = s.config.Transactions.ExecuteApproval(ctx, func(ctx context.Context, tx ApprovalTransaction) error {
		if err := authorizeApprovalSubject(ctx, tx, actor, input); err != nil {
			return err
		}
		if input.EvidenceID != "" {
			exists, err := tx.ApprovalEvidenceExists(ctx, actor.TenantID, input.EvidenceID)
			if err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
		}
		approval = riskdomain.ApprovalRecord{ID: s.config.IDs.NewID("apr"), TenantID: actor.TenantID, SubjectType: input.SubjectType, SubjectID: input.SubjectID, Decision: input.Decision, Reason: input.Reason, ApproverID: auditActorID(actor), EvidenceID: input.EvidenceID, SchemaVersion: riskdomain.ApprovalRecordSchemaVersion, CreatedAt: now}
		if !validControlText(approval.ID, 1024, true) {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertApprovalRecord(ctx, approval); err != nil {
			return err
		}
		event := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "approval.created", SubjectType: "approval", SubjectID: approval.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: now}
		if !validControlText(event.ID, 1024, true) {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, event)
		return err
	})
	if err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	return approval, nil
}
