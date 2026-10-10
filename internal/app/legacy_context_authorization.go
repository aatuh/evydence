package app

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Transitional cached authorizers remain only for Identity and Verification
// aggregate retirement. Focused Release composition does not use them.
type ledgerContextAuthorizer struct{ ledger *Ledger }

func (a ledgerContextAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(actor, request.Scope); err != nil {
		return toApplicationAuthorizationError(err)
	}
	if request.TenantWide {
		a.ledger.mu.Lock()
		defer a.ledger.mu.Unlock()
		return toApplicationAuthorizationError(a.ledger.authorizeResourceLocked(actor, request.Scope, resourceRefs{}))
	}
	if request.ScopeOnly {
		return nil
	}
	a.ledger.mu.Lock()
	defer a.ledger.mu.Unlock()
	return toApplicationAuthorizationError(a.ledger.authorizeResourceLocked(actor, request.Scope, resourceRefs{
		ProductID:         request.Resources.ProductID,
		ProjectID:         request.Resources.ProjectID,
		ReleaseID:         request.Resources.ReleaseID,
		ArtifactID:        request.Resources.ArtifactID,
		BuildID:           request.Resources.BuildID,
		DeploymentID:      request.Resources.DeploymentID,
		EnvironmentID:     request.Resources.EnvironmentID,
		CustomerPackageID: request.Resources.CustomerPackageID,
	}))
}

func toApplicationAuthorizationError(err error) error {
	if errors.Is(err, ErrForbidden) {
		return application.ErrForbidden
	}
	return err
}

// This authorizer runs inside an aggregate transaction holding Ledger.mu.
type ledgerLockedContextAuthorizer struct{ ledger *Ledger }

func (a ledgerLockedContextAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(actor, request.Scope); err != nil {
		return toApplicationAuthorizationError(err)
	}
	if request.ScopeOnly {
		return nil
	}
	return toApplicationAuthorizationError(a.ledger.authorizeResourceLocked(actor, request.Scope, resourceRefs{
		ProductID:         request.Resources.ProductID,
		ProjectID:         request.Resources.ProjectID,
		ReleaseID:         request.Resources.ReleaseID,
		ArtifactID:        request.Resources.ArtifactID,
		BuildID:           request.Resources.BuildID,
		DeploymentID:      request.Resources.DeploymentID,
		EnvironmentID:     request.Resources.EnvironmentID,
		CustomerPackageID: request.Resources.CustomerPackageID,
	}))
}
