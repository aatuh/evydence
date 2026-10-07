package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Former local setup retains real preflight authorization and isolated writes
// through test-only focused ports. These adapters are not runtime backends or
// evidence of PostgreSQL locking, durability, or bounded SQL selection.
type peripheralFixtureCommands struct{ catalogFixtureCommands }
type marketplaceQueryFixture struct{ catalogFixtureCommands }

func graphFixtureInput(in packageapp.CreateGraphSnapshotInput) app.CreateGraphSnapshotInput {
	return app.CreateGraphSnapshotInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID}
}
func saasFixtureInput(in experimentalapp.SaaSProfileInput) app.CreateSaaSEditionProfileInput {
	return app.CreateSaaSEditionProfileInput{Name: in.Name, Region: in.Region, AdminTenantID: in.AdminTenantID, IsolationModel: in.IsolationModel}
}
func marketplaceCollectorLegacyInput(in experimentalapp.MarketplaceCollectorInput) app.CreateMarketplaceCollectorInput {
	return app.CreateMarketplaceCollectorInput{Name: in.Name, Provider: in.Provider, Version: in.Version, Publisher: in.Publisher, ManifestHash: in.ManifestHash, SignatureID: in.SignatureID, SBOMID: in.SBOMID, ScanID: in.ScanID}
}
func graphFixtureModel(v domain.EvidenceGraphSnapshot) packagedomain.EvidenceGraphSnapshot {
	nodes := make([]packagedomain.GraphNode, len(v.Nodes))
	for i, n := range v.Nodes {
		nodes[i] = packagedomain.GraphNode{ID: n.ID, Type: n.Type, Label: n.Label}
	}
	edges := make([]packagedomain.GraphEdge, len(v.Edges))
	for i, e := range v.Edges {
		edges[i] = packagedomain.GraphEdge{From: e.From, To: e.To, Relationship: e.Relationship}
	}
	return packagedomain.EvidenceGraphSnapshot{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Nodes: nodes, Edges: edges, GraphHash: v.GraphHash, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func saasFixtureModel(v domain.SaaSEditionProfile) experimentaldomain.SaaSEditionProfile {
	return experimentaldomain.SaaSEditionProfile{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Region: v.Region, AdminTenantID: v.AdminTenantID, IsolationModel: v.IsolationModel, Status: v.Status, ConfigHash: v.ConfigHash, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func marketplaceFixtureModel(v domain.MarketplaceCollector) experimentaldomain.MarketplaceCollector {
	return experimentaldomain.MarketplaceCollector{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Provider: v.Provider, Version: v.Version, Publisher: v.Publisher, ManifestHash: v.ManifestHash, SignatureID: v.SignatureID, SBOMID: v.SBOMID, ScanID: v.ScanID, State: v.State, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func marketplaceHealthFixtureModel(v domain.MarketplaceCollectorHealthReport) experimentaldomain.MarketplaceCollectorHealthReport {
	checks := make([]experimentaldomain.VerificationCheck, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = experimentaldomain.VerificationCheck{Name: c.Name, Result: c.Result, Detail: c.Detail}
	}
	return experimentaldomain.MarketplaceCollectorHealthReport{ReportType: v.ReportType, CollectorID: v.CollectorID, Name: v.Name, Provider: v.Provider, Version: v.Version, SupplyChainStatus: v.SupplyChainStatus, Checks: checks, Collector: marketplaceFixtureModel(v.Collector), Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}
}
func (f peripheralFixtureCommands) AuthorizeCreateGraphSnapshot(ctx context.Context, a domain.Actor, in packageapp.CreateGraphSnapshotInput) error {
	return f.commandLedger(ctx).AuthorizeCreateGraphSnapshot(ctx, a, graphFixtureInput(in))
}
func (f peripheralFixtureCommands) CreateGraphSnapshot(ctx context.Context, a domain.Actor, in packageapp.CreateGraphSnapshotInput) (packagedomain.EvidenceGraphSnapshot, error) {
	v, err := f.commandLedger(ctx).CreateGraphSnapshot(ctx, a, graphFixtureInput(in))
	return graphFixtureModel(v), err
}
func (f peripheralFixtureCommands) AuthorizeCreateSaaSProfile(ctx context.Context, a domain.Actor, in experimentalapp.SaaSProfileInput) error {
	return f.commandLedger(ctx).AuthorizeCreateSaaSEditionProfile(ctx, a, saasFixtureInput(in))
}
func (f peripheralFixtureCommands) CreateSaaSProfile(ctx context.Context, a domain.Actor, in experimentalapp.SaaSProfileInput) (experimentaldomain.SaaSEditionProfile, error) {
	v, err := f.commandLedger(ctx).CreateSaaSEditionProfile(ctx, a, saasFixtureInput(in))
	return saasFixtureModel(v), err
}
func (f peripheralFixtureCommands) AuthorizeCreateMarketplaceCollector(ctx context.Context, a domain.Actor, in experimentalapp.MarketplaceCollectorInput) error {
	return f.commandLedger(ctx).AuthorizeCreateMarketplaceCollector(ctx, a, marketplaceCollectorLegacyInput(in))
}
func (f peripheralFixtureCommands) CreateMarketplaceCollector(ctx context.Context, a domain.Actor, in experimentalapp.MarketplaceCollectorInput) (experimentaldomain.MarketplaceCollector, error) {
	v, err := f.commandLedger(ctx).CreateMarketplaceCollector(ctx, a, marketplaceCollectorLegacyInput(in))
	return marketplaceFixtureModel(v), err
}
func (f marketplaceQueryFixture) ListPage(ctx context.Context, a domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[experimentaldomain.MarketplaceCollector]{}, err
	}
	values, err := f.commandLedger(ctx).ListMarketplaceCollectors(ctx, a)
	if err != nil {
		return appquery.Result[experimentaldomain.MarketplaceCollector]{}, err
	}
	items := make([]experimentaldomain.MarketplaceCollector, 0, len(values))
	for _, v := range values {
		items = append(items, marketplaceFixtureModel(v))
	}
	return appquery.Page(items, request, after, func(v experimentaldomain.MarketplaceCollector, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
	})
}
func (f marketplaceQueryFixture) Health(ctx context.Context, a domain.Actor, id string) (experimentaldomain.MarketplaceCollectorHealthReport, error) {
	v, err := f.commandLedger(ctx).MarketplaceCollectorHealth(ctx, a, id)
	return marketplaceHealthFixtureModel(v), err
}
func (s *Server) bindPeripheralFixturePorts(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	commands := peripheralFixtureCommands{f}
	if _, fixture := s.graphSnapshotCommands.(peripheralFixtureCommands); s.graphSnapshotCommands == nil || fixture {
		s.graphSnapshotCommands = commands
	}
	if _, fixture := s.saasProfileCommands.(peripheralFixtureCommands); s.saasProfileCommands == nil || fixture {
		s.saasProfileCommands = commands
	}
	if _, fixture := s.marketplaceCollectorCommands.(peripheralFixtureCommands); s.marketplaceCollectorCommands == nil || fixture {
		s.marketplaceCollectorCommands = commands
	}
	if _, fixture := s.marketplaceCollectorQuery.(marketplaceQueryFixture); s.marketplaceCollectorQuery == nil || fixture {
		s.marketplaceCollectorQuery = marketplaceQueryFixture{f}
	}
}

var (
	_ GraphSnapshotCommands        = peripheralFixtureCommands{}
	_ SaaSProfileCommands          = peripheralFixtureCommands{}
	_ MarketplaceCollectorCommands = peripheralFixtureCommands{}
	_ MarketplaceCollectorQuery    = marketplaceQueryFixture{}
)
