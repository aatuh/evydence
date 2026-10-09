package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func (l *Ledger) AuthorizeReportTemplateCreation(ctx context.Context, a domain.Actor, in packageapp.CreateReportTemplateInput) error {
	if err := packagequery.NewTemplateAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReportRead, TenantWide: true}); err != nil {
		return fromPackageContextError(err)
	}
	if !validPublicMembershipText(a.TenantID, 1024) || a.TenantID == "" || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	in, err := packageapp.NormalizeReportTemplateCreation(in)
	if err != nil || len(a.TenantID)+len(in.Name)+len(in.Version) > packageapp.MaxReportTemplateKeyBytes {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	return nil
}
func (l *Ledger) AuthorizeReportRendering(ctx context.Context, a domain.Actor, in packageapp.RenderReportInput) error {
	if err := packagequery.NewTemplateAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReportRead, TenantWide: true}); err != nil {
		return fromPackageContextError(err)
	}
	if !validPublicMembershipText(a.TenantID, 1024) || a.TenantID == "" || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	in, err := packageapp.NormalizeReportRendering(in)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	v, ok := l.reportTemplates[in.TemplateID]
	if !ok || v.TenantID != a.TenantID {
		return ErrNotFound
	}
	return nil
}
