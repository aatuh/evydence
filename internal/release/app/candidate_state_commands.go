package app

import (
	"context"
	"math"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// CandidateStateRow contains the selected snapshot and its current, verified
// parent coordinate. It does not expose unrelated release/catalog metadata.
type CandidateStateRow struct {
	Candidate releasedomain.ReleaseCandidate
	ProductID string
}

type CandidateStateReader interface {
	ReadCandidateState(context.Context, string, string) (CandidateStateRow, error)
}

type CandidateStateTransaction interface {
	CandidateStateReader
	application.Authorizer
	UpdateCandidateState(context.Context, releasedomain.ReleaseCandidate, int64, string) error
	application.AuditAppender
}

type CandidateStateTransactionRunner interface {
	ExecuteCandidateState(context.Context, func(context.Context, CandidateStateTransaction) error) error
}

type CandidateStateCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions CandidateStateTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type CandidateStateCommands struct{ config CandidateStateCommandConfig }

func NewCandidateStateCommands(config CandidateStateCommandConfig) (*CandidateStateCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &CandidateStateCommands{config: config}, nil
}

// UpdateReleaseCandidateState resolves, authorizes and changes one locked row
// inside the caller's unit of work. No pool or cache preflight read is needed.
func (s *CandidateStateCommands) UpdateReleaseCandidateState(ctx context.Context, actor identitydomain.Actor, id, state, reason string, expectedRevision int64) (releasedomain.ReleaseCandidate, error) {
	if s == nil {
		return releasedomain.ReleaseCandidate{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	in, err := NormalizeCandidateTransitionInput(CandidateTransitionInput{ID: id, State: state, Reason: reason, ExpectedRevision: expectedRevision})
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	id, state = in.ID, in.State
	var updated releasedomain.ReleaseCandidate
	err = s.config.Transactions.ExecuteCandidateState(ctx, func(ctx context.Context, tx CandidateStateTransaction) error {
		row, err := tx.ReadCandidateState(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		current := row.Candidate
		if current.ID != id || current.TenantID != actor.TenantID || current.ReleaseID == "" || row.ProductID == "" {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: row.ProductID, ReleaseID: current.ReleaseID}}); err != nil {
			return err
		}
		if current.Revision != expectedRevision {
			return NewVersionConflict(current.Revision)
		}
		if current.State.String() != "open" || current.Revision == math.MaxInt64 {
			return ErrConflict
		}
		at := s.config.Clock.Now().UTC()
		updated = cloneReleaseCandidate(current)
		updated.State, _ = releasedomain.ParseReleaseCandidateState(state)
		updated.Revision++
		if state == "promoted" {
			updated.PromotedAt = &at
		} else {
			updated.RejectedAt = &at
		}
		if err := tx.UpdateCandidateState(ctx, updated, expectedRevision, "open"); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, auditEventFor(s.config.IDs, actor, at, "release_candidate."+state, "release_candidate", updated.ID, updated.SnapshotHash))
		return err
	})
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return updated, nil
}
