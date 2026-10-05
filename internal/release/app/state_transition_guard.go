package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type ReleaseTransitionScope struct{ ID, TenantID, ProductID string }
type CandidateTransitionScope struct{ ID, TenantID, ReleaseID, ProductID string }
type ReleaseTransitionGuardReader interface {
	ReadReleaseTransitionScope(context.Context, string, string) (ReleaseTransitionScope, error)
}
type CandidateTransitionGuardReader interface {
	ReadCandidateTransitionScope(context.Context, string, string) (CandidateTransitionScope, error)
}

func NormalizeTransitionID(id string) (string, error) {
	if len(id) > 1024 || !validBuildText(id) {
		return "", ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", ErrNotFound
	}
	return id, nil
}

type CandidateTransitionInput struct {
	ID, State, Reason string
	ExpectedRevision  int64
}

func NormalizeCandidateTransitionInput(in CandidateTransitionInput) (CandidateTransitionInput, error) {
	if in.ExpectedRevision < 1 || len(in.State) > 32 || !validBuildText(in.State) || len(in.Reason) > 65536 || !validBuildText(in.Reason) {
		return CandidateTransitionInput{}, ErrValidation
	}
	var err error
	in.ID, err = NormalizeTransitionID(in.ID)
	if err != nil {
		return CandidateTransitionInput{}, err
	}
	in.State = strings.TrimSpace(in.State)
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || (in.State != "promoted" && in.State != "rejected") {
		return CandidateTransitionInput{}, ErrValidation
	}
	return in, nil
}

func (s *ReleaseStateCommands) AuthorizeReleaseTransition(ctx context.Context, a identitydomain.Actor, id string) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return err
	}
	id, err := NormalizeTransitionID(id)
	if err != nil {
		return err
	}
	return s.transactions.ExecuteReleaseState(ctx, func(ctx context.Context, tx ReleaseStateTransaction) error {
		r, ok := tx.(ReleaseTransitionGuardReader)
		if !ok {
			return ErrValidation
		}
		v, err := r.ReadReleaseTransitionScope(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != a.TenantID || v.ProductID == "" {
			return ErrNotFound
		}
		if !validCandidateText(v.ProductID, 1024) {
			return ErrConflict
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: v.ProductID, ReleaseID: id}})
	})
}
func (s *CandidateStateCommands) AuthorizeCandidateTransition(ctx context.Context, a identitydomain.Actor, id string) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return err
	}
	id, err := NormalizeTransitionID(id)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteCandidateState(ctx, func(ctx context.Context, tx CandidateStateTransaction) error {
		r, ok := tx.(CandidateTransitionGuardReader)
		if !ok {
			return ErrValidation
		}
		v, err := r.ReadCandidateTransitionScope(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != a.TenantID || v.ReleaseID == "" || v.ProductID == "" {
			return ErrNotFound
		}
		if !validCandidateText(v.ReleaseID, 1024) || !validCandidateText(v.ProductID, 1024) {
			return ErrConflict
		}
		return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: v.ProductID, ReleaseID: v.ReleaseID}})
	})
}
