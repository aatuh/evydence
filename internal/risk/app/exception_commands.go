package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// ExceptionTransitionState contains only authorization coordinates and state,
// not historical reasons or tenant-wide evidence/decision inventories.
type ExceptionTransitionState struct {
	ID, TenantID, ReleaseID, FindingID, ControlID string
	Approved                                      bool
	ExpiresAt                                     time.Time
}
type ExceptionCommandReader interface {
	ReadExceptionSubject(context.Context, string, string, string) (GovernanceSubjectReference, error)
	ReadExceptionTransitionState(context.Context, string, string) (ExceptionTransitionState, error)
	ReadExceptionForApproval(context.Context, string, string) (riskdomain.Exception, error)
}
type ExceptionTransaction interface {
	ExceptionCommandReader
	application.Authorizer
	application.AuditAppender
	InsertException(context.Context, riskdomain.Exception) error
	ApproveException(context.Context, riskdomain.Exception) error
}
type ExceptionTransactionRunner interface {
	ExecuteException(context.Context, func(context.Context, ExceptionTransaction) error) error
}
type ExceptionCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ExceptionTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ExceptionCommands struct{ config ExceptionCommandConfig }

func NewExceptionCommands(config ExceptionCommandConfig) (*ExceptionCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ExceptionCommands{config}, nil
}
func (s *ExceptionCommands) preflight(ctx context.Context, actor identitydomain.Actor) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if !validControlText(actor.TenantID, 1024, true) || !validControlText(auditActorID(actor), 1024, true) {
		return ErrValidation
	}
	return nil
}
func (s *ExceptionCommands) prepareCreate(ctx context.Context, actor identitydomain.Actor, in CreateExceptionInput) (CreateExceptionInput, error) {
	if err := s.preflight(ctx, actor); err != nil {
		return in, err
	}
	for _, v := range []string{in.ReleaseID, in.FindingID, in.ControlID, in.Owner} {
		if !validControlText(v, 1024, false) {
			return in, ErrValidation
		}
	}
	if !validControlText(in.Reason, 65536, false) {
		return in, ErrValidation
	}
	in.ReleaseID, in.FindingID, in.ControlID = strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.FindingID), strings.TrimSpace(in.ControlID)
	in.Reason, in.Owner = strings.TrimSpace(in.Reason), strings.TrimSpace(in.Owner)
	in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
	if in.ReleaseID == "" || in.Owner == "" || in.Reason == "" || !validRiskLifecycleTime(in.ExpiresAt) {
		return in, ErrValidation
	}
	return in, nil
}
func authorizeExceptionScope(ctx context.Context, tx ExceptionTransaction, actor identitydomain.Actor, releaseID, findingID, controlID string) error {
	if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if !validControlText(releaseID, 1024, true) || !validControlText(findingID, 1024, false) || !validControlText(controlID, 1024, false) {
		return ErrValidation
	}
	release, err := tx.ReadExceptionSubject(ctx, actor.TenantID, "release", releaseID)
	if err != nil {
		return err
	}
	if !validGovernanceSubject(release, actor.TenantID, "release", releaseID) || release.ProductID == "" || release.ReleaseID != releaseID {
		return ErrNotFound
	}
	if !validControlText(release.ProductID, 1024, true) {
		return ErrValidation
	}
	if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: subjectResources(release)}); err != nil {
		return err
	}
	if findingID != "" {
		finding, err := tx.ReadExceptionSubject(ctx, actor.TenantID, "finding", findingID)
		if err != nil {
			return err
		}
		if !validGovernanceSubject(finding, actor.TenantID, "finding", findingID) || finding.ProductID != release.ProductID || finding.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	if controlID != "" {
		control, err := tx.ReadExceptionSubject(ctx, actor.TenantID, "control", controlID)
		if err != nil {
			return err
		}
		if !validGovernanceSubject(control, actor.TenantID, "control", controlID) || control.ProductID != "" || control.ReleaseID != "" {
			return ErrNotFound
		}
	}
	return nil
}

// Replay authorization excludes expiry checks so a saved successful response
// stays replayable, but it never substitutes for current grants/ownership.
func (s *ExceptionCommands) AuthorizeCreateException(ctx context.Context, actor identitydomain.Actor, in CreateExceptionInput) error {
	in, err := s.prepareCreate(ctx, actor, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteException(ctx, func(ctx context.Context, tx ExceptionTransaction) error {
		return authorizeExceptionScope(ctx, tx, actor, in.ReleaseID, in.FindingID, in.ControlID)
	})
}
func (s *ExceptionCommands) CreateException(ctx context.Context, actor identitydomain.Actor, in CreateExceptionInput) (riskdomain.Exception, error) {
	in, err := s.prepareCreate(ctx, actor, in)
	if err != nil {
		return riskdomain.Exception{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !validRiskLifecycleTime(now) || !in.ExpiresAt.After(now) {
		return riskdomain.Exception{}, ErrValidation
	}
	v := riskdomain.Exception{ID: s.config.IDs.NewID("ex"), TenantID: actor.TenantID, ReleaseID: in.ReleaseID, FindingID: in.FindingID, ControlID: in.ControlID, Owner: in.Owner, Reason: in.Reason, ExpiresAt: in.ExpiresAt, CreatedAt: now}
	if !validControlText(v.ID, 1024, true) {
		return riskdomain.Exception{}, ErrValidation
	}
	err = s.config.Transactions.ExecuteException(ctx, func(ctx context.Context, tx ExceptionTransaction) error {
		if err := authorizeExceptionScope(ctx, tx, actor, in.ReleaseID, in.FindingID, in.ControlID); err != nil {
			return err
		}
		if err := tx.InsertException(ctx, v); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, now, "exception.created", v.ID)
	})
	if err != nil {
		return riskdomain.Exception{}, err
	}
	return v, nil
}
func (s *ExceptionCommands) prepareApproval(ctx context.Context, actor identitydomain.Actor, id string) (string, error) {
	if err := s.preflight(ctx, actor); err != nil {
		return "", err
	}
	if !validControlText(id, 1024, true) {
		return "", ErrValidation
	}
	return strings.TrimSpace(id), nil
}
func authorizeExceptionApproval(ctx context.Context, tx ExceptionTransaction, actor identitydomain.Actor, id string) (ExceptionTransitionState, error) {
	if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return ExceptionTransitionState{}, err
	}
	v, err := tx.ReadExceptionTransitionState(ctx, actor.TenantID, id)
	if err != nil {
		return v, err
	}
	if v.ID != id || v.TenantID != actor.TenantID {
		return ExceptionTransitionState{}, ErrNotFound
	}
	if !validRiskLifecycleTime(v.ExpiresAt) {
		return ExceptionTransitionState{}, ErrValidation
	}
	if err := authorizeExceptionScope(ctx, tx, actor, v.ReleaseID, v.FindingID, v.ControlID); err != nil {
		return ExceptionTransitionState{}, err
	}
	return v, nil
}
func (s *ExceptionCommands) AuthorizeApproveException(ctx context.Context, actor identitydomain.Actor, id string) error {
	id, err := s.prepareApproval(ctx, actor, id)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteException(ctx, func(ctx context.Context, tx ExceptionTransaction) error {
		_, err := authorizeExceptionApproval(ctx, tx, actor, id)
		return err
	})
}
func (s *ExceptionCommands) ApproveException(ctx context.Context, actor identitydomain.Actor, id string) (riskdomain.Exception, error) {
	id, err := s.prepareApproval(ctx, actor, id)
	if err != nil {
		return riskdomain.Exception{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !validRiskLifecycleTime(now) {
		return riskdomain.Exception{}, ErrValidation
	}
	var result riskdomain.Exception
	err = s.config.Transactions.ExecuteException(ctx, func(ctx context.Context, tx ExceptionTransaction) error {
		state, err := authorizeExceptionApproval(ctx, tx, actor, id)
		if err != nil {
			return err
		}
		if !state.ExpiresAt.After(now) {
			return ErrConflict
		}
		v, err := tx.ReadExceptionForApproval(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != actor.TenantID || v.ReleaseID != state.ReleaseID || v.FindingID != state.FindingID || v.ControlID != state.ControlID || v.Approved != state.Approved || !v.ExpiresAt.Equal(state.ExpiresAt) {
			return ErrConflict
		}
		if !validControlText(v.Owner, 1024, true) || !validControlText(v.Reason, 65536, true) || !validControlText(v.ApprovedBy, 1024, false) || !validRiskLifecycleTime(v.CreatedAt) {
			return ErrValidation
		}
		if v.Approved {
			if v.ApprovedBy == "" || v.ApprovedAt == nil || !validRiskLifecycleTime(*v.ApprovedAt) || !v.ExpiresAt.After(*v.ApprovedAt) {
				return ErrValidation
			}
			result = cloneException(v)
			return nil
		}
		if v.ApprovedBy != "" || v.ApprovedAt != nil {
			return ErrValidation
		}
		v.Approved, v.ApprovedBy, v.ApprovedAt = true, auditActorID(actor), cloneTimePointer(&now)
		if err := tx.ApproveException(ctx, v); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, now, "exception.approved", v.ID); err != nil {
			return err
		}
		result = cloneException(v)
		return nil
	})
	if err != nil {
		return riskdomain.Exception{}, err
	}
	return result, nil
}
func (s *ExceptionCommands) appendAudit(ctx context.Context, tx ExceptionTransaction, actor identitydomain.Actor, at time.Time, kind, id string) error {
	v := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: kind, SubjectType: "exception", SubjectID: id, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at}
	if !validControlText(v.ID, 1024, true) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, v)
	return err
}
