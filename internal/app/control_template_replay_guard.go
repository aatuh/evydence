package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

// This guard is local-memory only. It never reads framework versions, clocks,
// IDs or worker projections. Native HTTP uses the focused transaction port.
func (l *Ledger) AuthorizeControlTemplateInstallation(ctx context.Context, a domain.Actor, raw string) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := application.AuthorizeTenantWideScope(ctx, a, ScopeControlsAdmin); err != nil {
		return fromRiskContextError(err)
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	slug, err := riskapp.NormalizeControlTemplateSlug(raw)
	if err != nil {
		return ErrValidation
	}
	found := false
	for _, pack := range builtinTemplatePacks() {
		if pack.Slug == slug {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	return nil
}
