package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

func marketplaceCollectorInput(in CreateMarketplaceCollectorInput) experimentalapp.MarketplaceCollectorInput {
	return experimentalapp.MarketplaceCollectorInput{Name: in.Name, Provider: in.Provider, Version: in.Version, Publisher: in.Publisher, ManifestHash: in.ManifestHash, SignatureID: in.SignatureID, SBOMID: in.SBOMID, ScanID: in.ScanID}
}
func MarketplaceCollectorLegacyRecord(v experimentaldomain.MarketplaceCollector) domain.MarketplaceCollector {
	return domain.MarketplaceCollector{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Provider: v.Provider, Version: v.Version, Publisher: v.Publisher, ManifestHash: v.ManifestHash, SignatureID: v.SignatureID, SBOMID: v.SBOMID, ScanID: v.ScanID, State: v.State, Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func cloneLocalMarketplaceCollector(v domain.MarketplaceCollector) domain.MarketplaceCollector {
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
func (l *Ledger) AuthorizeCreateMarketplaceCollector(ctx context.Context, a domain.Actor, in CreateMarketplaceCollectorInput) error {
	if err := experimentalapp.AuthorizeMarketplaceCollectorActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	v, err := experimentalapp.NormalizeMarketplaceCollectorInput(marketplaceCollectorInput(in))
	if err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeMarketplaceReferencesLocked(ctx, a.TenantID, v)
}
func (l *Ledger) authorizeMarketplaceReferencesLocked(ctx context.Context, tenant string, in experimentalapp.MarketplaceCollectorInput) error {
	if _, ok := l.tenants[tenant]; !ok {
		return ErrNotFound
	}
	if in.SignatureID != "" {
		v, ok := l.signatures[in.SignatureID]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
	}
	if in.SBOMID != "" {
		v, ok := l.sboms[in.SBOMID]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
	}
	if in.ScanID != "" {
		v, ok := l.scans[in.ScanID]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
	}
	return ctx.Err()
}
