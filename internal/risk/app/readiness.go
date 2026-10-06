package app

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const ReadinessSnapshotVersion = riskdomain.ReadinessSnapshotVersion

// ReadinessSnapshot retains the focused application port name for the Risk-owned
// domain fact view. It is not a persistence or aggregate snapshot.
type ReadinessSnapshot = riskdomain.ReadinessSnapshot

func (s *Service) PreviewReleaseReadiness(ctx context.Context, actor identitydomain.Actor, releaseID string) (riskdomain.PolicyEvaluation, error) {
	snapshot, err := s.readReadinessSnapshot(ctx, actor, releaseID)
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	return EvaluateReadinessSnapshot(snapshot, s.clock.Now().UTC())
}

func (s *Service) EvaluateRelease(ctx context.Context, actor identitydomain.Actor, releaseID string) (riskdomain.PolicyEvaluation, error) {
	snapshot, err := s.readReadinessSnapshot(ctx, actor, releaseID)
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	now := s.clock.Now().UTC()
	evaluation, err := EvaluateReadinessSnapshot(snapshot, now)
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	evaluation.ID = s.ids.NewID("pe")
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{
			Scope: ScopeVerifyRead, Resources: application.ResourceReferences{ProductID: snapshot.ProductID, ReleaseID: snapshot.ReleaseID},
		}); err != nil {
			return err
		}
		if err := tx.Decisions().InsertPolicyEvaluation(ctx, evaluation); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "policy.evaluated", "policy_evaluation", evaluation.ID))
		return err
	})
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	return clonePolicyEvaluation(evaluation), nil
}

func (s *Service) readReadinessSnapshot(ctx context.Context, actor identitydomain.Actor, releaseID string) (ReadinessSnapshot, error) {
	if err := contextError(ctx); err != nil {
		return ReadinessSnapshot{}, err
	}
	if err := validateActor(actor); err != nil {
		return ReadinessSnapshot{}, err
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{}, true); err != nil {
		return ReadinessSnapshot{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return ReadinessSnapshot{}, ErrValidation
	}
	if err := s.refresh(ctx, actor.TenantID); err != nil {
		return ReadinessSnapshot{}, err
	}
	snapshot, err := s.reader.ReadReleaseReadinessSnapshot(ctx, actor.TenantID, releaseID)
	if err != nil {
		return ReadinessSnapshot{}, err
	}
	snapshot = cloneReadinessSnapshot(snapshot)
	if snapshot.SnapshotVersion != ReadinessSnapshotVersion || snapshot.TenantID != actor.TenantID || snapshot.ReleaseID != releaseID || strings.TrimSpace(snapshot.ProductID) == "" || snapshot.PackageCount < 0 {
		return ReadinessSnapshot{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{ProductID: snapshot.ProductID, ReleaseID: snapshot.ReleaseID}, false); err != nil {
		return ReadinessSnapshot{}, err
	}
	return snapshot, nil
}

// EvaluateReadinessSnapshot retains the focused application error contract;
// policy interpretation itself belongs to the Risk domain.
func EvaluateReadinessSnapshot(snapshot ReadinessSnapshot, createdAt time.Time) (riskdomain.PolicyEvaluation, error) {
	value, err := riskdomain.EvaluateReadinessSnapshot(snapshot, createdAt)
	if err != nil {
		return riskdomain.PolicyEvaluation{}, ErrValidation
	}
	return value, nil
}

func cloneReadinessSnapshot(value ReadinessSnapshot) ReadinessSnapshot {
	value.MissingCustomerStatementIDs = append([]string(nil), value.MissingCustomerStatementIDs...)
	value.MissingNotAffectedReasonIDs = append([]string(nil), value.MissingNotAffectedReasonIDs...)
	value.IncompleteExceptionIDs = append([]string(nil), value.IncompleteExceptionIDs...)
	value.InvalidPackageOrProfileIDs = append([]string(nil), value.InvalidPackageOrProfileIDs...)
	return value
}

func clonePolicyEvaluation(value riskdomain.PolicyEvaluation) riskdomain.PolicyEvaluation {
	value.Checks = append([]riskdomain.PolicyCheck(nil), value.Checks...)
	for index := range value.Checks {
		value.Checks[index].Missing = append([]string(nil), value.Checks[index].Missing...)
	}
	return value
}
