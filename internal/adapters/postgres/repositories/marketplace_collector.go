package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

var _ experimentalapp.MarketplaceReferenceReader = futureExtensions{}

func (r futureExtensions) ReadMarketplaceReferences(ctx context.Context, tenant string, ids experimentalapp.MarketplaceReferenceIDs) (experimentalapp.MarketplaceReferences, error) {
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR KEY SHARE`, tenant); err != nil {
		return experimentalapp.MarketplaceReferences{}, err
	}
	// Only presence and ownership are needed for metadata registration. Share
	// locks prevent deletion/reparenting through the enclosing replay commit;
	// signature bytes, key material, components and findings are never selected.
	for _, ref := range []struct{ id, query string }{
		{ids.SignatureID, `SELECT 1 FROM signatures WHERE tenant_id=$1 AND id=$2 FOR SHARE`},
		{ids.SBOMID, `SELECT 1 FROM sboms WHERE tenant_id=$1 AND id=$2 FOR SHARE`},
		{ids.ScanID, `SELECT 1 FROM vulnerability_scans WHERE tenant_id=$1 AND id=$2 FOR SHARE`},
	} {
		if ref.id != "" {
			if err := requireRow(ctx, r.tx, ref.query, tenant, ref.id); err != nil {
				return experimentalapp.MarketplaceReferences{}, err
			}
		}
	}
	return experimentalapp.MarketplaceReferences{TenantID: tenant, SignatureID: ids.SignatureID, SBOMID: ids.SBOMID, ScanID: ids.ScanID}, nil
}
func (r futureExtensions) InsertFocusedMarketplaceCollector(ctx context.Context, v experimentaldomain.MarketplaceCollector) error {
	if _, err := r.ReadMarketplaceReferences(ctx, v.TenantID, experimentalapp.MarketplaceReferenceIDs{SignatureID: v.SignatureID, SBOMID: v.SBOMID, ScanID: v.ScanID}); err != nil {
		return err
	}
	return r.InsertMarketplaceCollector(ctx, app.MarketplaceCollectorLegacyRecord(v))
}
