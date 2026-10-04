package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// This flat port locks only the current tenant-owned release and product.
// Manifest snapshots and signing-key material are not needed for replay.
type ReleaseBundleCreationScopeLocker interface {
	LockReleaseBundleCreationScope(context.Context, string, string) (string, error)
}

func NormalizeReleaseBundleID(raw string) (string, error) {
	_, id, err := NormalizeProductReleaseIDs("", raw)
	return id, err
}

func (s *ReleaseBundleCommands) AuthorizeReleaseBundleCreation(ctx context.Context, a identitydomain.Actor, raw string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateActor(a); err != nil {
		return err
	}
	id, err := NormalizeReleaseBundleID(raw)
	if err != nil || !graphID(a.TenantID) {
		return ErrValidation
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "bundle:write", ScopeOnly: true}); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteReleaseBundle(ctx, func(ctx context.Context, tx ReleaseBundleTransaction) error {
		locker, ok := tx.(ReleaseBundleCreationScopeLocker)
		if !ok {
			return ErrValidation
		}
		product, err := locker.LockReleaseBundleCreationScope(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if !graphID(product) {
			return ErrConflict
		}
		request := application.AuthorizationRequest{Scope: "bundle:write", Resources: application.ResourceReferences{ProductID: product, ReleaseID: id}}
		if err := s.config.Authorizer.Authorize(ctx, a, request); err != nil {
			return err
		}
		return tx.Authorize(ctx, a, request)
	})
}
