package app

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const ScopePolicyWrite = "policy:write"

type GovernanceRepository interface {
	ResolveGovernanceSubject(context.Context, string, string, string) (GovernanceSubjectReference, error)
	GetWaiverForUpdate(context.Context, string, string) (riskdomain.Waiver, error)
	InsertWaiver(context.Context, riskdomain.Waiver) error
	ApproveWaiver(context.Context, riskdomain.Waiver) error
	InsertApprovalRecord(context.Context, riskdomain.ApprovalRecord) error
}

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

func (s *Service) CreateWaiver(ctx context.Context, actor identitydomain.Actor, input CreateWaiverInput) (riskdomain.Waiver, error) {
	if err := contextError(ctx); err != nil {
		return riskdomain.Waiver{}, err
	}
	if err := validateActor(actor); err != nil {
		return riskdomain.Waiver{}, err
	}
	if err := s.authorize(ctx, actor, ScopePolicyWrite, application.ResourceReferences{}, true); err != nil {
		return riskdomain.Waiver{}, err
	}
	input.ScopeType = strings.TrimSpace(input.ScopeType)
	input.ScopeID = strings.TrimSpace(input.ScopeID)
	input.ControlID = strings.TrimSpace(input.ControlID)
	input.PolicyID = strings.TrimSpace(input.PolicyID)
	input.Owner = strings.TrimSpace(input.Owner)
	input.Risk = strings.TrimSpace(input.Risk)
	input.Reason = strings.TrimSpace(input.Reason)
	input.Supersedes = strings.TrimSpace(input.Supersedes)
	now := s.clock.Now().UTC()
	if !validWaiverScope(input.ScopeType) || input.ScopeID == "" || input.Owner == "" || input.Risk == "" || input.Reason == "" || !input.ExpiresAt.After(now) {
		return riskdomain.Waiver{}, ErrValidation
	}
	if input.ScopeType == "finding" {
		if err := s.refresh(ctx, actor.TenantID); err != nil {
			return riskdomain.Waiver{}, err
		}
	}
	subject, err := s.reader.ResolveGovernanceSubject(ctx, actor.TenantID, input.ScopeType, input.ScopeID)
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	if !validGovernanceSubject(subject, actor.TenantID, input.ScopeType, input.ScopeID) {
		return riskdomain.Waiver{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopePolicyWrite, subjectResources(subject), false); err != nil {
		return riskdomain.Waiver{}, err
	}
	if input.ControlID != "" {
		if _, err := s.resolveGovernanceSubject(ctx, s.reader, actor.TenantID, "control", input.ControlID); err != nil {
			return riskdomain.Waiver{}, err
		}
	}
	if input.PolicyID != "" {
		if _, err := s.resolveGovernanceSubject(ctx, s.reader, actor.TenantID, "policy", input.PolicyID); err != nil {
			return riskdomain.Waiver{}, err
		}
	}
	if input.Supersedes != "" {
		prior, err := s.reader.ResolveGovernanceSubject(ctx, actor.TenantID, "waiver", input.Supersedes)
		if err != nil {
			return riskdomain.Waiver{}, err
		}
		if !validGovernanceSubject(prior, actor.TenantID, "waiver", input.Supersedes) {
			return riskdomain.Waiver{}, ErrNotFound
		}
	}

	waiver := riskdomain.Waiver{
		ID: s.ids.NewID("wv"), TenantID: actor.TenantID, ScopeType: input.ScopeType, ScopeID: input.ScopeID,
		ControlID: input.ControlID, PolicyID: input.PolicyID, Owner: input.Owner, Risk: input.Risk, Reason: input.Reason,
		ExpiresAt: input.ExpiresAt.UTC(), Supersedes: input.Supersedes, SchemaVersion: riskdomain.WaiverSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		current, err := tx.Governance().ResolveGovernanceSubject(ctx, actor.TenantID, input.ScopeType, input.ScopeID)
		if err != nil {
			return err
		}
		if current != subject {
			return ErrConflict
		}
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePolicyWrite, Resources: subjectResources(current)}); err != nil {
			return err
		}
		if input.ControlID != "" {
			if _, err := s.resolveGovernanceSubject(ctx, tx.Governance(), actor.TenantID, "control", input.ControlID); err != nil {
				return err
			}
		}
		if input.PolicyID != "" {
			if _, err := s.resolveGovernanceSubject(ctx, tx.Governance(), actor.TenantID, "policy", input.PolicyID); err != nil {
				return err
			}
		}
		if input.Supersedes != "" {
			previous, err := tx.Governance().GetWaiverForUpdate(ctx, actor.TenantID, input.Supersedes)
			if err != nil {
				return err
			}
			if previous.ID != input.Supersedes || previous.TenantID != actor.TenantID || previous.SupersededBy != "" {
				return ErrConflict
			}
		}
		if err := tx.Governance().InsertWaiver(ctx, waiver); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "waiver.created", "waiver", waiver.ID))
		return err
	})
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	return cloneWaiver(waiver), nil
}

func (s *Service) ApproveWaiver(ctx context.Context, actor identitydomain.Actor, id string) (riskdomain.Waiver, error) {
	if err := contextError(ctx); err != nil {
		return riskdomain.Waiver{}, err
	}
	if err := validateActor(actor); err != nil {
		return riskdomain.Waiver{}, err
	}
	if err := s.authorize(ctx, actor, ScopePolicyWrite, application.ResourceReferences{}, true); err != nil {
		return riskdomain.Waiver{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return riskdomain.Waiver{}, ErrNotFound
	}
	now := s.clock.Now().UTC()
	var result riskdomain.Waiver
	err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		waiver, err := tx.Governance().GetWaiverForUpdate(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if waiver.ID != id || waiver.TenantID != actor.TenantID {
			return ErrNotFound
		}
		if waiver.Approved || !waiver.ExpiresAt.After(now) {
			return ErrConflict
		}
		subject, err := tx.Governance().ResolveGovernanceSubject(ctx, actor.TenantID, waiver.ScopeType, waiver.ScopeID)
		if err != nil {
			return err
		}
		if !validGovernanceSubject(subject, actor.TenantID, waiver.ScopeType, waiver.ScopeID) {
			return ErrNotFound
		}
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePolicyWrite, Resources: subjectResources(subject)}); err != nil {
			return err
		}
		waiver.Approved = true
		waiver.ApprovedBy = auditActorID(actor)
		waiver.ApprovedAt = cloneTimePointer(&now)
		if err := tx.Governance().ApproveWaiver(ctx, waiver); err != nil {
			return err
		}
		if _, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "waiver.approved", "waiver", waiver.ID)); err != nil {
			return err
		}
		result = waiver
		return nil
	})
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	return cloneWaiver(result), nil
}

type CreateApprovalInput struct {
	SubjectType string
	SubjectID   string
	Decision    string
	Reason      string
	EvidenceID  string
}

func (s *Service) CreateApprovalRecord(ctx context.Context, actor identitydomain.Actor, input CreateApprovalInput) (riskdomain.ApprovalRecord, error) {
	if err := contextError(ctx); err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	if err := validateActor(actor); err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{}, true); err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	input.SubjectType = strings.TrimSpace(input.SubjectType)
	input.SubjectID = strings.TrimSpace(input.SubjectID)
	input.Decision = strings.TrimSpace(input.Decision)
	input.Reason = strings.TrimSpace(input.Reason)
	input.EvidenceID = strings.TrimSpace(input.EvidenceID)
	if !validApprovalSubject(input.SubjectType) || input.SubjectID == "" || !validApprovalDecision(input.Decision) || input.Reason == "" {
		return riskdomain.ApprovalRecord{}, ErrValidation
	}
	subject, err := s.reader.ResolveGovernanceSubject(ctx, actor.TenantID, input.SubjectType, input.SubjectID)
	if err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	if !validGovernanceSubject(subject, actor.TenantID, input.SubjectType, input.SubjectID) {
		return riskdomain.ApprovalRecord{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, subjectResources(subject), false); err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	if input.EvidenceID != "" {
		item, err := s.reader.GetEvidence(ctx, actor.TenantID, input.EvidenceID)
		if err != nil {
			return riskdomain.ApprovalRecord{}, err
		}
		if item.ID != input.EvidenceID || item.TenantID != actor.TenantID {
			return riskdomain.ApprovalRecord{}, ErrNotFound
		}
	}
	now := s.clock.Now().UTC()
	approval := riskdomain.ApprovalRecord{
		ID: s.ids.NewID("apr"), TenantID: actor.TenantID, SubjectType: input.SubjectType, SubjectID: input.SubjectID,
		Decision: input.Decision, Reason: input.Reason, ApproverID: auditActorID(actor), EvidenceID: input.EvidenceID,
		SchemaVersion: riskdomain.ApprovalRecordSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		current, err := tx.Governance().ResolveGovernanceSubject(ctx, actor.TenantID, input.SubjectType, input.SubjectID)
		if err != nil {
			return err
		}
		if current != subject {
			return ErrConflict
		}
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: subjectResources(current)}); err != nil {
			return err
		}
		if input.EvidenceID != "" {
			item, err := tx.Decisions().GetEvidence(ctx, actor.TenantID, input.EvidenceID)
			if err != nil {
				return err
			}
			if item.ID != input.EvidenceID || item.TenantID != actor.TenantID {
				return ErrNotFound
			}
		}
		if err := tx.Governance().InsertApprovalRecord(ctx, approval); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "approval.created", "approval", approval.ID))
		return err
	})
	if err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	return approval, nil
}

type governanceSubjectResolver interface {
	ResolveGovernanceSubject(context.Context, string, string, string) (GovernanceSubjectReference, error)
}

func (s *Service) resolveGovernanceSubject(ctx context.Context, resolver governanceSubjectResolver, tenantID, subjectType, id string) (GovernanceSubjectReference, error) {
	subject, err := resolver.ResolveGovernanceSubject(ctx, tenantID, subjectType, id)
	if err != nil {
		return GovernanceSubjectReference{}, err
	}
	if !validGovernanceSubject(subject, tenantID, subjectType, id) {
		return GovernanceSubjectReference{}, ErrNotFound
	}
	return subject, nil
}

func validGovernanceSubject(value GovernanceSubjectReference, tenantID, subjectType, id string) bool {
	return value.Type == subjectType && value.ID == id && value.TenantID == tenantID
}

func subjectResources(value GovernanceSubjectReference) application.ResourceReferences {
	return application.ResourceReferences{ProductID: value.ProductID, ReleaseID: value.ReleaseID}
}

func validWaiverScope(value string) bool {
	switch value {
	case "release", "finding", "control", "policy":
		return true
	default:
		return false
	}
}

func validApprovalSubject(value string) bool {
	switch value {
	case "release", "contract_diff", "waiver", "security_review", "customer_package":
		return true
	default:
		return false
	}
}

func validApprovalDecision(value string) bool {
	return value == "approved" || value == "rejected" || value == "accepted"
}

func cloneWaiver(value riskdomain.Waiver) riskdomain.Waiver {
	value.ApprovedAt = cloneTimePointer(value.ApprovedAt)
	return value
}
