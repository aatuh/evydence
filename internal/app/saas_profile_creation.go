package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

func saasProfileInput(in CreateSaaSEditionProfileInput) experimentalapp.SaaSProfileInput {
	return experimentalapp.SaaSProfileInput{Name: in.Name, Region: in.Region, AdminTenantID: in.AdminTenantID, IsolationModel: in.IsolationModel}
}
func SaaSProfileLegacyRecord(v experimentaldomain.SaaSEditionProfile) domain.SaaSEditionProfile {
	return domain.SaaSEditionProfile{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Region: v.Region, AdminTenantID: v.AdminTenantID, IsolationModel: v.IsolationModel, Status: v.Status, ConfigHash: v.ConfigHash, Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (l *Ledger) AuthorizeCreateSaaSEditionProfile(ctx context.Context, a domain.Actor, in CreateSaaSEditionProfileInput) error {
	if err := experimentalapp.AuthorizeSaaSProfileActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	v, err := experimentalapp.NormalizeSaaSProfileInput(saasProfileInput(in))
	if err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	if _, ok := l.tenants[v.AdminTenantID]; !ok {
		return ErrNotFound
	}
	return ctx.Err()
}
