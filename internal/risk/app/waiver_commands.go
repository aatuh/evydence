package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// WaiverTransitionState excludes reasons and unrelated tenant inventory. Readers
// must lock the selected row and its current parent coordinates until commit.
type WaiverTransitionState struct {
	ID, TenantID, ScopeType, ScopeID, SupersededBy string
	Approved                                       bool
	ExpiresAt                                      time.Time
}
type WaiverCommandReader interface {
	ReadWaiverSubject(context.Context, string, string, string) (GovernanceSubjectReference, error)
	ReadWaiverTransitionState(context.Context, string, string) (WaiverTransitionState, error)
	// ReadWaiverForApproval returns one bounded record, only after authorization.
	ReadWaiverForApproval(context.Context, string, string) (riskdomain.Waiver, error)
}
type WaiverTransaction interface {
	WaiverCommandReader
	application.Authorizer
	application.AuditAppender
	InsertWaiver(context.Context, riskdomain.Waiver) error
	ApproveWaiver(context.Context, riskdomain.Waiver) error
}
type WaiverTransactionRunner interface {
	ExecuteWaiver(context.Context, func(context.Context, WaiverTransaction) error) error
}
type WaiverCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions WaiverTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type WaiverCommands struct{ config WaiverCommandConfig }

func NewWaiverCommands(config WaiverCommandConfig) (*WaiverCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &WaiverCommands{config}, nil
}
func (s *WaiverCommands) preflight(ctx context.Context, actor identitydomain.Actor) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePolicyWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if !validControlText(actor.TenantID, 1024, true) || !validControlText(auditActorID(actor), 1024, true) {
		return ErrValidation
	}
	return nil
}
func (s *WaiverCommands) prepareCreate(ctx context.Context, actor identitydomain.Actor, in CreateWaiverInput) (CreateWaiverInput, error) {
	if err := s.preflight(ctx, actor); err != nil {
		return in, err
	}
	for _, v := range []string{in.ScopeID, in.ControlID, in.PolicyID, in.Owner, in.Risk, in.Supersedes} {
		if !validControlText(v, 1024, false) {
			return in, ErrValidation
		}
	}
	if !validControlText(in.ScopeType, 128, false) || !validControlText(in.Reason, 65536, false) {
		return in, ErrValidation
	}
	in.ScopeType, in.ScopeID = strings.TrimSpace(in.ScopeType), strings.TrimSpace(in.ScopeID)
	in.ControlID, in.PolicyID = strings.TrimSpace(in.ControlID), strings.TrimSpace(in.PolicyID)
	in.Owner, in.Risk, in.Reason, in.Supersedes = strings.TrimSpace(in.Owner), strings.TrimSpace(in.Risk), strings.TrimSpace(in.Reason), strings.TrimSpace(in.Supersedes)
	in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
	if !validWaiverScope(in.ScopeType) || in.ScopeID == "" || in.Owner == "" || in.Risk == "" || in.Reason == "" || !validWaiverTime(in.ExpiresAt) {
		return in, ErrValidation
	}
	return in, nil
}
func validWaiverTime(v time.Time) bool { return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 }

func authorizeWaiverSubject(ctx context.Context, tx WaiverTransaction, actor identitydomain.Actor, kind, id string) error {
	if !validWaiverScope(kind) || !validControlText(id, 1024, true) {
		return ErrValidation
	}
	subject, err := tx.ReadWaiverSubject(ctx, actor.TenantID, kind, id)
	if err != nil {
		return err
	}
	if !validGovernanceSubject(subject, actor.TenantID, kind, id) {
		return ErrNotFound
	}
	if !validControlText(subject.ProductID, 1024, false) || !validControlText(subject.ReleaseID, 1024, false) {
		return ErrValidation
	}
	switch kind {
	case "release":
		if subject.ProductID == "" || subject.ReleaseID != id {
			return ErrNotFound
		}
	case "finding":
		if subject.ProductID == "" || subject.ReleaseID == "" {
			return ErrNotFound
		}
	case "control", "policy":
		if subject.ProductID != "" || subject.ReleaseID != "" {
			return ErrNotFound
		}
	}
	return tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePolicyWrite, Resources: subjectResources(subject), TenantWide: subject.ProductID == ""})
}
func readAuthorizedWaiverState(ctx context.Context, tx WaiverTransaction, actor identitydomain.Actor, id string) (WaiverTransitionState, error) {
	v, err := tx.ReadWaiverTransitionState(ctx, actor.TenantID, id)
	if err != nil {
		return v, err
	}
	if v.ID != id || v.TenantID != actor.TenantID {
		return WaiverTransitionState{}, ErrNotFound
	}
	if !validControlText(v.SupersededBy, 1024, false) || !validWaiverTime(v.ExpiresAt) {
		return WaiverTransitionState{}, ErrValidation
	}
	if err := authorizeWaiverSubject(ctx, tx, actor, v.ScopeType, v.ScopeID); err != nil {
		return WaiverTransitionState{}, err
	}
	return v, nil
}
func authorizeWaiverCreation(ctx context.Context, tx WaiverTransaction, actor identitydomain.Actor, in CreateWaiverInput) (WaiverTransitionState, error) {
	if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePolicyWrite, ScopeOnly: true}); err != nil {
		return WaiverTransitionState{}, err
	}
	if err := authorizeWaiverSubject(ctx, tx, actor, in.ScopeType, in.ScopeID); err != nil {
		return WaiverTransitionState{}, err
	}
	for _, linked := range []struct{ kind, id string }{{"control", in.ControlID}, {"policy", in.PolicyID}} {
		if linked.id == "" {
			continue
		}
		v, err := tx.ReadWaiverSubject(ctx, actor.TenantID, linked.kind, linked.id)
		if err != nil {
			return WaiverTransitionState{}, err
		}
		if !validGovernanceSubject(v, actor.TenantID, linked.kind, linked.id) || v.ProductID != "" || v.ReleaseID != "" {
			return WaiverTransitionState{}, ErrNotFound
		}
	}
	if in.Supersedes != "" {
		return readAuthorizedWaiverState(ctx, tx, actor, in.Supersedes)
	}
	return WaiverTransitionState{}, nil
}

// AuthorizeCreateWaiver deliberately excludes future-expiry and transition
// checks: a completed response remains replayable, but only to a current actor.
func (s *WaiverCommands) AuthorizeCreateWaiver(ctx context.Context, actor identitydomain.Actor, in CreateWaiverInput) error {
	in, err := s.prepareCreate(ctx, actor, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteWaiver(ctx, func(ctx context.Context, tx WaiverTransaction) error {
		_, err := authorizeWaiverCreation(ctx, tx, actor, in)
		return err
	})
}
func (s *WaiverCommands) CreateWaiver(ctx context.Context, actor identitydomain.Actor, in CreateWaiverInput) (riskdomain.Waiver, error) {
	in, err := s.prepareCreate(ctx, actor, in)
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !validWaiverTime(now) || !in.ExpiresAt.After(now) {
		return riskdomain.Waiver{}, ErrValidation
	}
	v := riskdomain.Waiver{ID: s.config.IDs.NewID("wv"), TenantID: actor.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, ControlID: in.ControlID, PolicyID: in.PolicyID, Owner: in.Owner, Risk: in.Risk, Reason: in.Reason, ExpiresAt: in.ExpiresAt, Supersedes: in.Supersedes, SchemaVersion: riskdomain.WaiverSchemaVersion, CreatedAt: now}
	if !validControlText(v.ID, 1024, true) {
		return riskdomain.Waiver{}, ErrValidation
	}
	err = s.config.Transactions.ExecuteWaiver(ctx, func(ctx context.Context, tx WaiverTransaction) error {
		prior, err := authorizeWaiverCreation(ctx, tx, actor, in)
		if err != nil {
			return err
		}
		if in.Supersedes != "" && prior.SupersededBy != "" {
			return ErrConflict
		}
		if err := tx.InsertWaiver(ctx, v); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, now, "waiver.created", v.ID)
	})
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	return v, nil
}
func (s *WaiverCommands) prepareApproval(ctx context.Context, actor identitydomain.Actor, id string) (string, error) {
	if err := s.preflight(ctx, actor); err != nil {
		return "", err
	}
	if !validControlText(id, 1024, true) {
		return "", ErrValidation
	}
	return strings.TrimSpace(id), nil
}
func authorizeWaiverApproval(ctx context.Context, tx WaiverTransaction, actor identitydomain.Actor, id string) (WaiverTransitionState, error) {
	if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePolicyWrite, ScopeOnly: true}); err != nil {
		return WaiverTransitionState{}, err
	}
	return readAuthorizedWaiverState(ctx, tx, actor, id)
}
func (s *WaiverCommands) AuthorizeApproveWaiver(ctx context.Context, actor identitydomain.Actor, id string) error {
	id, err := s.prepareApproval(ctx, actor, id)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteWaiver(ctx, func(ctx context.Context, tx WaiverTransaction) error {
		_, err := authorizeWaiverApproval(ctx, tx, actor, id)
		return err
	})
}
func (s *WaiverCommands) ApproveWaiver(ctx context.Context, actor identitydomain.Actor, id string) (riskdomain.Waiver, error) {
	id, err := s.prepareApproval(ctx, actor, id)
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !validWaiverTime(now) {
		return riskdomain.Waiver{}, ErrValidation
	}
	var result riskdomain.Waiver
	err = s.config.Transactions.ExecuteWaiver(ctx, func(ctx context.Context, tx WaiverTransaction) error {
		state, err := authorizeWaiverApproval(ctx, tx, actor, id)
		if err != nil {
			return err
		}
		if state.Approved || !state.ExpiresAt.After(now) {
			return ErrConflict
		}
		v, err := tx.ReadWaiverForApproval(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != actor.TenantID || v.ScopeType != state.ScopeType || v.ScopeID != state.ScopeID || v.Approved != state.Approved || !v.ExpiresAt.Equal(state.ExpiresAt) || v.SupersededBy != state.SupersededBy {
			return ErrConflict
		}
		for _, value := range []string{v.ControlID, v.PolicyID, v.Owner, v.Risk, v.ApprovedBy, v.Supersedes, v.SupersededBy, v.SchemaVersion} {
			if !validControlText(value, 1024, false) {
				return ErrValidation
			}
		}
		if !validControlText(v.Owner, 1024, true) || !validControlText(v.Risk, 1024, true) || !validControlText(v.Reason, 65536, true) || !validControlText(v.SchemaVersion, 1024, true) || !validWaiverTime(v.CreatedAt) || v.ApprovedBy != "" || v.ApprovedAt != nil {
			return ErrValidation
		}
		v.Approved, v.ApprovedBy, v.ApprovedAt = true, auditActorID(actor), cloneTimePointer(&now)
		if err := tx.ApproveWaiver(ctx, v); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, now, "waiver.approved", v.ID); err != nil {
			return err
		}
		result = cloneWaiver(v)
		return nil
	})
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	return result, nil
}
func (s *WaiverCommands) appendAudit(ctx context.Context, tx WaiverTransaction, actor identitydomain.Actor, at time.Time, kind, id string) error {
	event := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: kind, SubjectType: "waiver", SubjectID: id, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at}
	if !validControlText(event.ID, 1024, true) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, event)
	return err
}
