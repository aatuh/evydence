package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// These map guards are explicit local-memory HTTP compatibility only.
func (l *Ledger) authorizeCatalogCreation(ctx context.Context, a domain.Actor, scope, productID string) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, scope); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	if productID == "" {
		return l.authorizeResourceLocked(a, scope, resourceRefs{})
	}
	p, ok := l.products[productID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	return l.authorizeResourceLocked(a, scope, resourceRefs{ProductID: p.ID})
}
func (l *Ledger) AuthorizeProductCreation(ctx context.Context, a domain.Actor, in releaseapp.CreateProductInput) error {
	if _, err := releaseapp.NormalizeProductCreationInput(in); err != nil {
		return fromReleaseContextError(err)
	}
	return l.authorizeCatalogCreation(ctx, a, ScopeProductWrite, "")
}
func (l *Ledger) AuthorizeProjectCreation(ctx context.Context, a domain.Actor, in releaseapp.CreateProjectInput) error {
	v, err := releaseapp.NormalizeProjectCreationInput(in)
	if err != nil {
		return fromReleaseContextError(err)
	}
	return l.authorizeCatalogCreation(ctx, a, ScopeProjectWrite, v.ProductID)
}
func (l *Ledger) AuthorizeReleaseCreation(ctx context.Context, a domain.Actor, in releaseapp.CreateReleaseInput) error {
	v, err := releaseapp.NormalizeReleaseCreationInput(in)
	if err != nil {
		return fromReleaseContextError(err)
	}
	return l.authorizeCatalogCreation(ctx, a, ScopeReleaseWrite, v.ProductID)
}
