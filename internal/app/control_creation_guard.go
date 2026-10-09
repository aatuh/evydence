package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// These guards are explicit local-memory compatibility only. Native HTTP binds
// focused Risk transaction ports, never these maps or a Ledger projection.
func (l *Ledger) AuthorizeControlFrameworkCreation(ctx context.Context, a domain.Actor, in CreateControlFrameworkInput) error {
	if err := authorizeLocalControlAdmin(ctx, a); err != nil {
		return err
	}
	if _, err := riskapp.NormalizeControlFrameworkInput(riskapp.CreateControlFrameworkInput{Name: in.Name, Slug: in.Slug, Version: in.Version, Description: in.Description}); err != nil {
		return ErrValidation
	}
	return l.authorizeLocalControlCreationScope(a, "")
}

func (l *Ledger) AuthorizeSecurityControlCreation(ctx context.Context, a domain.Actor, in CreateSecurityControlInput) error {
	if err := authorizeLocalControlAdmin(ctx, a); err != nil {
		return err
	}
	reqs := make([]riskdomain.ControlEvidenceRequirement, 0, len(in.EvidenceRequirements))
	for _, r := range in.EvidenceRequirements {
		reqs = append(reqs, riskdomain.ControlEvidenceRequirement{Type: r.Type, FreshnessDays: r.FreshnessDays, Required: r.Required})
	}
	normalized, err := riskapp.NormalizeSecurityControlInput(riskapp.CreateSecurityControlInput{FrameworkID: in.FrameworkID, Code: in.Code, Title: in.Title, Objective: in.Objective, EvidenceRequirements: reqs, Applicability: in.Applicability, Limitations: in.Limitations})
	if err != nil || len(a.TenantID)+len(normalized.FrameworkID)+len(normalized.Code) > 2048 {
		return ErrValidation
	}
	return l.authorizeLocalControlCreationScope(a, normalized.FrameworkID)
}

func authorizeLocalControlAdmin(ctx context.Context, a domain.Actor) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := application.AuthorizeTenantWideScope(ctx, a, ScopeControlsAdmin); err != nil {
		return fromRiskContextError(err)
	}
	if len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}

func (l *Ledger) authorizeLocalControlCreationScope(a domain.Actor, parent string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	if parent != "" {
		v, ok := l.frameworks[parent]
		if !ok || v.TenantID != a.TenantID {
			return ErrNotFound
		}
	}
	return nil
}
