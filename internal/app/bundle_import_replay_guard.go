package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func (l *Ledger) AuthorizeBundleImport(ctx context.Context, a domain.Actor, b packagedomain.EvidenceBundle) error {
	if err := packagequery.NewBundleImportAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeBundleWrite, TenantWide: true}); err != nil {
		return fromPackageContextError(err)
	}
	if a.TenantID == "" || !validPublicMembershipText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	if err := packageapp.ValidatePortableBundleInput(b); err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	return nil
}
