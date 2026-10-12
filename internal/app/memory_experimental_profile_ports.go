package app

import (
	"context"
	"slices"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func (r memoryFutureExtensionsRepository) ReadSaaSProfileTenants(ctx context.Context, tenant, admin string) (experimentalapp.SaaSProfileTenants, error) {
	var out experimentalapp.SaaSProfileTenants
	if !memoryMembershipQueryText(admin, experimentalapp.MaxSaaSProfileIDBytes) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		if state.Tenants[tenant].ID != tenant || state.Tenants[admin].ID != admin {
			return ErrNotFound
		}
		out = experimentalapp.SaaSProfileTenants{TenantID: tenant, AdminTenantID: admin}
		return nil
	})
	return out, err
}
func (r memoryFutureExtensionsRepository) ReadMarketplaceReferences(ctx context.Context, tenant string, ids experimentalapp.MarketplaceReferenceIDs) (experimentalapp.MarketplaceReferences, error) {
	var out experimentalapp.MarketplaceReferences
	for _, id := range []string{ids.SignatureID, ids.SBOMID, ids.ScanID} {
		if id != "" && !memoryMembershipQueryText(id, experimentalapp.MaxMarketplaceIDBytes) {
			return out, ErrValidation
		}
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		for _, ref := range []struct{ requested, stored, owner string }{
			{ids.SignatureID, state.Signatures[ids.SignatureID].ID, state.Signatures[ids.SignatureID].TenantID},
			{ids.SBOMID, state.SBOMs[ids.SBOMID].ID, state.SBOMs[ids.SBOMID].TenantID},
			{ids.ScanID, state.VulnerabilityScans[ids.ScanID].ID, state.VulnerabilityScans[ids.ScanID].TenantID},
		} {
			if ref.requested != "" && (ref.stored != ref.requested || ref.owner != tenant) {
				return ErrNotFound
			}
		}
		out = experimentalapp.MarketplaceReferences{TenantID: tenant, SignatureID: ids.SignatureID, SBOMID: ids.SBOMID, ScanID: ids.ScanID}
		return nil
	})
	return out, err
}
func memoryExperimentalLimitations(values []string) bool {
	if len(values) > 128 {
		return false
	}
	total := 0
	for _, v := range values {
		if !memoryMembershipText(v, 64<<10) {
			return false
		}
		total += len(v)
	}
	return total <= packageapp.MaxGeneratedReportBytes
}
func (r memoryFutureExtensionsRepository) InsertFocusedSaaSProfile(ctx context.Context, v experimentaldomain.SaaSEditionProfile) error {
	in := experimentalapp.SaaSProfileInput{Name: v.Name, Region: v.Region, AdminTenantID: v.AdminTenantID, IsolationModel: v.IsolationModel}
	built, err := experimentalapp.BuildSaaSProfile(v.ID, v.TenantID, in, v.ConfigHash, v.CreatedAt)
	if err != nil || built.Name != v.Name || built.Region != v.Region || built.AdminTenantID != v.AdminTenantID || built.IsolationModel != v.IsolationModel || v.Status != built.Status || v.SchemaVersion != built.SchemaVersion || !memoryExperimentalLimitations(v.Limitations) {
		return ErrValidation
	}
	if _, err := r.ReadSaaSProfileTenants(ctx, v.TenantID, v.AdminTenantID); err != nil {
		return err
	}
	return r.InsertSaaSEditionProfile(ctx, SaaSProfileLegacyRecord(v))
}
func (r memoryFutureExtensionsRepository) InsertFocusedMarketplaceCollector(ctx context.Context, v experimentaldomain.MarketplaceCollector) error {
	in := experimentalapp.MarketplaceCollectorInput{Name: v.Name, Provider: v.Provider, Version: v.Version, Publisher: v.Publisher, ManifestHash: v.ManifestHash, SignatureID: v.SignatureID, SBOMID: v.SBOMID, ScanID: v.ScanID}
	built, err := experimentalapp.BuildMarketplaceCollector(v.ID, v.TenantID, in, v.CreatedAt)
	if err != nil || built.Name != v.Name || built.Provider != v.Provider || built.Version != v.Version || built.Publisher != v.Publisher || built.ManifestHash != v.ManifestHash || v.State != built.State || v.SchemaVersion != built.SchemaVersion || !memoryExperimentalLimitations(v.Limitations) {
		return ErrValidation
	}
	if _, err := r.ReadMarketplaceReferences(ctx, v.TenantID, experimentalapp.MarketplaceReferenceIDs{SignatureID: v.SignatureID, SBOMID: v.SBOMID, ScanID: v.ScanID}); err != nil {
		return err
	}
	return r.InsertMarketplaceCollector(ctx, MarketplaceCollectorLegacyRecord(v))
}
func memoryMarketplaceModel(v domain.MarketplaceCollector) experimentaldomain.MarketplaceCollector {
	return experimentaldomain.MarketplaceCollector{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Provider: v.Provider, Version: v.Version, Publisher: v.Publisher, ManifestHash: v.ManifestHash, SignatureID: v.SignatureID, SBOMID: v.SBOMID, ScanID: v.ScanID, State: v.State, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (r memoryFutureExtensionsRepository) PageMarketplaceCollectors(ctx context.Context, req experimentalquery.MarketplaceCollectorPageRequest) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	var out appquery.Result[experimentaldomain.MarketplaceCollector]
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return out, err
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, req.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		points := []domain.MarketplaceCollector{}
		for key, v := range state.MarketplaceCollectors {
			if v.TenantID == req.TenantID {
				if key != v.ID {
					return experimentalquery.ErrInvalidProjection
				}
				points = append(points, domain.MarketplaceCollector{ID: v.ID, CreatedAt: v.CreatedAt})
			}
		}
		page, err := appquery.Page(points, req.Page, req.After, func(v domain.MarketplaceCollector, sort appquery.Sort) appquery.SortKey {
			return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
		})
		if err != nil {
			return err
		}
		out = appquery.Result[experimentaldomain.MarketplaceCollector]{Items: make([]experimentaldomain.MarketplaceCollector, 0, len(page.Items)), Next: page.Next}
		for _, point := range page.Items {
			v := state.MarketplaceCollectors[point.ID]
			if !memoryExperimentalLimitations(v.Limitations) {
				return experimentalquery.ErrInvalidProjection
			}
			out.Items = append(out.Items, memoryMarketplaceModel(v))
		}
		return nil
	})
	if err != nil {
		return appquery.Result[experimentaldomain.MarketplaceCollector]{}, err
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) GetMarketplaceCollectorPoint(ctx context.Context, tenant, id string) (experimentalquery.MarketplaceCollectorPoint, error) {
	var out experimentalquery.MarketplaceCollectorPoint
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		v, ok := state.MarketplaceCollectors[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return experimentalquery.ErrNotFound
		}
		if !memoryExperimentalLimitations(v.Limitations) {
			return experimentalquery.ErrInvalidProjection
		}
		out = experimentalquery.MarketplaceCollectorPoint{Collector: memoryMarketplaceModel(v), SignatureFound: v.SignatureID != "" && state.Signatures[v.SignatureID].TenantID == tenant && state.Signatures[v.SignatureID].ID == v.SignatureID,
			SBOMFound: v.SBOMID != "" && state.SBOMs[v.SBOMID].TenantID == tenant && state.SBOMs[v.SBOMID].ID == v.SBOMID,
			ScanFound: v.ScanID != "" && state.VulnerabilityScans[v.ScanID].TenantID == tenant && state.VulnerabilityScans[v.ScanID].ID == v.ScanID}
		return nil
	})
	return out, err
}

var _ experimentalapp.SaaSProfileTenantReader = memoryFutureExtensionsRepository{}
var _ experimentalapp.MarketplaceReferenceReader = memoryFutureExtensionsRepository{}
var _ experimentalquery.MarketplaceCollectorReader = memoryFutureExtensionsRepository{}
