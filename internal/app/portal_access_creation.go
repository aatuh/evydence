package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func prepareLocalPortalAccess(ctx context.Context, a domain.Actor, in CreateCustomerPortalAccessInput) (packageapp.CreatePortalAccessInput, error) {
	if err := packagequery.NewPortalAccessWriteAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return packageapp.CreatePortalAccessInput{}, fromIdentityContextError(err)
	}
	v, err := packageapp.NormalizePortalAccessInput(packageapp.CreatePortalAccessInput{PackageID: in.PackageID, CustomerName: in.CustomerName, ReviewerName: in.ReviewerName, ReviewerEmail: in.ReviewerEmail, RequireNDA: in.RequireNDA, Watermark: in.Watermark, ExpiresAt: in.ExpiresAt})
	return v, fromPackageContextError(err)
}
func (l *Ledger) authorizePortalWriteLocked(ctx context.Context, a domain.Actor, id string) error {
	pkg, ok := l.customerPackages[id]
	if !ok || !l.currentPortalPackageLocked(a.TenantID, pkg) {
		return ErrNotFound
	}
	refs := application.ResourceReferences{ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, CustomerPackageID: pkg.ID}
	if err := packageapp.ValidatePortalPackageScope(a.TenantID, id, packageapp.PortalPackageScope{TenantID: pkg.TenantID, PackageID: pkg.ID, Resources: refs}); err != nil {
		return fromPackageContextError(err)
	}
	return fromIdentityContextError(packagequery.NewPortalAccessWriteAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: refs}))
}

// Local replay rechecks current package ownership and grants without minting.
func (l *Ledger) AuthorizeCustomerPortalAccessCreate(ctx context.Context, a domain.Actor, in CreateCustomerPortalAccessInput) error {
	if l == nil {
		return ErrValidation
	}
	v, err := prepareLocalPortalAccess(ctx, a, in)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizePortalWriteLocked(ctx, a, v.PackageID)
}
func (l *Ledger) AuthorizeCustomerPortalAccessRevoke(ctx context.Context, a domain.Actor, id string) error {
	if l == nil {
		return ErrValidation
	}
	if err := packagequery.NewPortalAccessWriteAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return fromIdentityContextError(err)
	}
	id, err := packageapp.NormalizePortalAccessID(id)
	if err != nil {
		return fromPackageContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.portalAccess[id]
	if !ok || v.TenantID != a.TenantID {
		return ErrNotFound
	}
	return l.authorizePortalWriteLocked(ctx, a, v.PackageID)
}
