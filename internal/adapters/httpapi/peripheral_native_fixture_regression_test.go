package httpapi

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestPeripheralFixtureReadsRepositoryRowsWithoutAggregatePublication(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedPeripheralFixtureScope(t, ledger, "Native")
	e := owner.evidence
	e.ID, e.Title = "repository-only-evidence", "Current graph metadata"
	collector, err := experimentalapp.BuildMarketplaceCollector("repository-only-collector", owner.actor.TenantID, experimentalapp.MarketplaceCollectorInput{Name: "New", Provider: "Example", Version: "1", Publisher: "Team", ManifestHash: "sha256:" + strings.Repeat("a", 64)}, e.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		if err := repos.Evidence.InsertEvidence(ctx, e); err != nil {
			return err
		}
		return repos.Future.InsertMarketplaceCollector(ctx, app.MarketplaceCollectorLegacyRecord(collector))
	}); err != nil {
		t.Fatal(err)
	}
	commands := peripheralFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	graph, err := commands.CreateGraphSnapshot(t.Context(), owner.actor, packageapp.CreateGraphSnapshotInput{ProductID: owner.product.ID, ReleaseID: owner.release.ID})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range graph.Nodes {
		if n.ID == e.ID && n.Label == e.Title {
			found = true
		}
	}
	if !found {
		t.Error("graph read stale aggregate evidence metadata")
	}
	query := marketplaceQueryFixture{catalogFixtureCommands{ledger: ledger}}
	page, err := query.ListPage(t.Context(), owner.actor, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0], collector) {
		t.Error("marketplace page read stale aggregate cache", page, err)
	}
	point, err := query.Health(t.Context(), owner.actor, collector.ID)
	if err != nil || !reflect.DeepEqual(point.Collector, collector) || point.SupplyChainStatus != "incomplete" {
		t.Error("health read stale aggregate collector", point, err)
	}
}
