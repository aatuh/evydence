package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Test-only fixtures run focused commands and query services on transaction
// repositories. These adapters are not runtime backends or
// evidence of PostgreSQL locking, durability, or bounded SQL selection.
type peripheralFixtureCommands struct{ catalogFixtureCommands }
type marketplaceQueryFixture struct{ catalogFixtureCommands }

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
func (f peripheralFixtureCommands) AuthorizeCreateGraphSnapshot(ctx context.Context, a domain.Actor, in packageapp.CreateGraphSnapshotInput) error {
	c, err := f.nativeGraph(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreateGraphSnapshot(ctx, a, in)
}
func (f peripheralFixtureCommands) CreateGraphSnapshot(ctx context.Context, a domain.Actor, in packageapp.CreateGraphSnapshotInput) (packagedomain.EvidenceGraphSnapshot, error) {
	c, err := f.nativeGraph(false)
	if err != nil {
		return packagedomain.EvidenceGraphSnapshot{}, err
	}
	return c.CreateGraphSnapshot(ctx, a, in)
}
func (f peripheralFixtureCommands) AuthorizeCreateSaaSProfile(ctx context.Context, a domain.Actor, in experimentalapp.SaaSProfileInput) error {
	c, err := f.nativeSaaS(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreateSaaSProfile(ctx, a, in)
}
func (f peripheralFixtureCommands) CreateSaaSProfile(ctx context.Context, a domain.Actor, in experimentalapp.SaaSProfileInput) (experimentaldomain.SaaSEditionProfile, error) {
	c, err := f.nativeSaaS(false)
	if err != nil {
		return experimentaldomain.SaaSEditionProfile{}, err
	}
	return c.CreateSaaSProfile(ctx, a, in)
}
func (f peripheralFixtureCommands) AuthorizeCreateMarketplaceCollector(ctx context.Context, a domain.Actor, in experimentalapp.MarketplaceCollectorInput) error {
	c, err := f.nativeMarketplace(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreateMarketplaceCollector(ctx, a, in)
}
func (f peripheralFixtureCommands) CreateMarketplaceCollector(ctx context.Context, a domain.Actor, in experimentalapp.MarketplaceCollectorInput) (experimentaldomain.MarketplaceCollector, error) {
	c, err := f.nativeMarketplace(false)
	if err != nil {
		return experimentaldomain.MarketplaceCollector{}, err
	}
	return c.CreateMarketplaceCollector(ctx, a, in)
}
func (f marketplaceQueryFixture) ListPage(ctx context.Context, a domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	c, err := experimentalquery.NewMarketplaceCollectors(f, peripheralFixtureQueryClock)
	if err != nil {
		return appquery.Result[experimentaldomain.MarketplaceCollector]{}, err
	}
	return c.ListPage(ctx, a, request, after)
}
func (f marketplaceQueryFixture) Health(ctx context.Context, a domain.Actor, id string) (experimentaldomain.MarketplaceCollectorHealthReport, error) {
	c, err := experimentalquery.NewMarketplaceCollectors(f, peripheralFixtureQueryClock)
	if err != nil {
		return experimentaldomain.MarketplaceCollectorHealthReport{}, err
	}
	return c.Health(ctx, a, id)
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
