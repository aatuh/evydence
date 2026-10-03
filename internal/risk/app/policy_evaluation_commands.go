package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type PolicyEvaluationReleaseReader interface {
	ReadPolicyEvaluationRelease(context.Context, string, string) (GovernanceSubjectReference, error)
}
type PolicyEvaluationReader interface {
	PolicyEvaluationReleaseReader
	ReadPolicyEvaluationSnapshot(context.Context, string, string, time.Time) (ReadinessSnapshot, error)
}
type PolicyEvaluationTransaction interface {
	PolicyEvaluationReader
	application.Authorizer
	application.AuditAppender
	InsertPolicyEvaluation(context.Context, riskdomain.PolicyEvaluation) error
}
type PolicyEvaluationTransactionRunner interface {
	ExecutePolicyEvaluation(context.Context, func(context.Context, PolicyEvaluationTransaction) error) error
}
type PolicyEvaluationCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions PolicyEvaluationTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PolicyEvaluationCommands struct{ config PolicyEvaluationCommandConfig }

func NewPolicyEvaluationCommands(c PolicyEvaluationCommandConfig) (*PolicyEvaluationCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PolicyEvaluationCommands{c}, nil
}
func NewPolicyEvaluationAuthorizer() application.Authorizer {
	return riskResourceWriteAuthorizer{scope: ScopeVerifyRead}
}
func (s *PolicyEvaluationCommands) prepare(ctx context.Context, a identitydomain.Actor, release string) (string, error) {
	if s == nil {
		return "", ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return "", err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return "", err
	}
	if !validControlText(a.TenantID, 1024, true) || !validControlText(auditActorID(a), 1024, true) || !validControlText(release, 1024, true) {
		return "", ErrValidation
	}
	release = strings.TrimSpace(release)
	if release == "" {
		return "", ErrValidation
	}
	return release, nil
}
func authorizeEvaluationRelease(ctx context.Context, tx PolicyEvaluationTransaction, a identitydomain.Actor, id string) (GovernanceSubjectReference, error) {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return GovernanceSubjectReference{}, err
	}
	r, err := tx.ReadPolicyEvaluationRelease(ctx, a.TenantID, id)
	if err != nil {
		return r, err
	}
	if !validGovernanceSubject(r, a.TenantID, "release", id) || r.ReleaseID != id || r.ProductID == "" {
		return GovernanceSubjectReference{}, ErrNotFound
	}
	if !validControlText(r.ProductID, 1024, true) {
		return GovernanceSubjectReference{}, ErrValidation
	}
	return r, tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subjectResources(r)})
}

// AuthorizeEvaluateRelease checks current coordinates and grants before replay,
// without reading readiness facts, evaluation history, or scanner payloads.
func (s *PolicyEvaluationCommands) AuthorizeEvaluateRelease(ctx context.Context, a identitydomain.Actor, release string) error {
	release, err := s.prepare(ctx, a, release)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecutePolicyEvaluation(ctx, func(ctx context.Context, tx PolicyEvaluationTransaction) error {
		_, err := authorizeEvaluationRelease(ctx, tx, a, release)
		return err
	})
}
func validPolicyEvaluationSnapshot(v ReadinessSnapshot) bool {
	if v.PackageCount < 0 || v.PackageCount > 4096 || len(v.InvalidPackageOrProfileIDs) > v.PackageCount {
		return false
	}
	remaining := 4096 - v.PackageCount
	for _, ids := range [][]string{v.MissingCustomerStatementIDs, v.MissingNotAffectedReasonIDs, v.IncompleteExceptionIDs} {
		if len(ids) > remaining {
			return false
		}
		remaining -= len(ids)
	}
	for _, ids := range [][]string{v.MissingCustomerStatementIDs, v.MissingNotAffectedReasonIDs, v.IncompleteExceptionIDs, v.InvalidPackageOrProfileIDs} {
		for _, id := range ids {
			if !validControlText(id, 1024, true) || strings.TrimSpace(id) == "" {
				return false
			}
		}
	}
	return true
}
func (s *PolicyEvaluationCommands) EvaluateRelease(ctx context.Context, a identitydomain.Actor, release string) (riskdomain.PolicyEvaluation, error) {
	release, err := s.prepare(ctx, a, release)
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	id := s.config.IDs.NewID("pe")
	if !validControlText(id, 1024, true) {
		return riskdomain.PolicyEvaluation{}, ErrValidation
	}
	var v riskdomain.PolicyEvaluation
	err = s.config.Transactions.ExecutePolicyEvaluation(ctx, func(ctx context.Context, tx PolicyEvaluationTransaction) error {
		r, err := authorizeEvaluationRelease(ctx, tx, a, release)
		if err != nil {
			return err
		}
		// Sample expiry/signing time after acquiring current release ownership
		// and the projection fence, not before a potentially long lock wait.
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !validRiskLifecycleTime(now) {
			return ErrValidation
		}
		snapshot, err := tx.ReadPolicyEvaluationSnapshot(ctx, a.TenantID, release, now)
		if err != nil {
			return err
		}
		if snapshot.SnapshotVersion != ReadinessSnapshotVersion || snapshot.TenantID != a.TenantID || snapshot.ReleaseID != release || snapshot.ProductID != r.ProductID {
			return ErrNotFound
		}
		if !validPolicyEvaluationSnapshot(snapshot) {
			return ErrValidation
		}
		v, err = EvaluateReadinessSnapshot(snapshot, now)
		if err != nil {
			return err
		}
		v.ID = id
		if err := tx.InsertPolicyEvaluation(ctx, v); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "policy.evaluated", SubjectType: "policy_evaluation", SubjectID: id, ActorID: auditActorID(a), ActorType: auditActorType(a), OccurredAt: now}
		if !validControlText(audit.ID, 1024, true) {
			return ErrValidation
		}
		_, err = tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	return clonePolicyEvaluation(v), nil
}
