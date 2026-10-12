package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type peripheralNativeRepository interface {
	packageapp.GraphSnapshotReader
	InsertFocusedGraphSnapshot(context.Context, packagedomain.EvidenceGraphSnapshot) error
	experimentalapp.SaaSProfileTenantReader
	InsertFocusedSaaSProfile(context.Context, experimentaldomain.SaaSEditionProfile) error
	experimentalapp.MarketplaceReferenceReader
	InsertFocusedMarketplaceCollector(context.Context, experimentaldomain.MarketplaceCollector) error
}
type peripheralNativeTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type peripheralNativeTransaction struct {
	peripheralNativeRepository
	repos    app.Repositories
	readOnly bool
}

func (f peripheralNativeTransactions) execute(ctx context.Context, tenant string, fn func(context.Context, peripheralNativeTransaction) error) error {
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(peripheralNativeRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, peripheralNativeTransaction{r, repos, f.readOnly})
	}))
}
func (f peripheralNativeTransactions) ExecuteGraphSnapshot(ctx context.Context, tenant string, fn func(context.Context, packageapp.GraphSnapshotTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx peripheralNativeTransaction) error { return fn(ctx, tx) })
}
func (f peripheralNativeTransactions) ExecuteSaaSProfile(ctx context.Context, tenant string, fn func(context.Context, experimentalapp.SaaSProfileTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx peripheralNativeTransaction) error { return fn(ctx, tx) })
}
func (f peripheralNativeTransactions) ExecuteMarketplaceCollector(ctx context.Context, tenant string, fn func(context.Context, experimentalapp.MarketplaceCollectorTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx peripheralNativeTransaction) error { return fn(ctx, tx) })
}
func (tx peripheralNativeTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewGraphSnapshotAuthorizer().Authorize(ctx, a, r)
}
func (tx peripheralNativeTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if tx.readOnly {
		panic("peripheral preflight appended an audit")
	}
	return (portalFixtureTransaction{repos: tx.repos}).AppendAudit(ctx, e)
}
func (tx peripheralNativeTransaction) ReadGraphSnapshotRoots(ctx context.Context, s packageapp.GraphSnapshotScope) ([]packagedomain.GraphNode, error) {
	if tx.readOnly {
		panic("graph preflight read labels")
	}
	v, err := tx.peripheralNativeRepository.ReadGraphSnapshotRoots(ctx, s)
	return v, portalFixtureError(err)
}
func (tx peripheralNativeTransaction) ReadGraphSnapshotEvidence(ctx context.Context, s packageapp.GraphSnapshotScope, n int) ([]packageapp.GraphSnapshotEvidence, error) {
	if tx.readOnly {
		panic("graph preflight read adjacency")
	}
	v, err := tx.peripheralNativeRepository.ReadGraphSnapshotEvidence(ctx, s, n)
	return v, portalFixtureError(err)
}
func (tx peripheralNativeTransaction) InsertGraphSnapshot(ctx context.Context, v packagedomain.EvidenceGraphSnapshot) error {
	if tx.readOnly {
		panic("graph preflight inserted a graph")
	}
	return portalFixtureError(tx.InsertFocusedGraphSnapshot(ctx, v))
}
func (tx peripheralNativeTransaction) InsertSaaSProfile(ctx context.Context, v experimentaldomain.SaaSEditionProfile) error {
	if tx.readOnly {
		panic("SaaS preflight inserted a profile")
	}
	return portalFixtureError(tx.InsertFocusedSaaSProfile(ctx, v))
}
func (tx peripheralNativeTransaction) InsertMarketplaceCollector(ctx context.Context, v experimentaldomain.MarketplaceCollector) error {
	if tx.readOnly {
		panic("marketplace preflight inserted a collector")
	}
	return portalFixtureError(tx.InsertFocusedMarketplaceCollector(ctx, v))
}

type peripheralNativeHasher struct{ readOnly bool }

func (h peripheralNativeHasher) Hash(v any) (string, error) {
	if h.readOnly {
		panic("graph preflight hashed a graph")
	}
	return application.NormalizedJSONHash(v)
}
func (f peripheralFixtureCommands) nativeGraph(readOnly bool) (*packageapp.GraphSnapshotCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return packageapp.NewGraphSnapshotCommands(packageapp.GraphSnapshotCommandConfig{Transactions: peripheralNativeTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: packagequery.NewGraphSnapshotAuthorizer(), Hasher: peripheralNativeHasher{readOnly}, Clock: clock, IDs: ids})
}
func (f peripheralFixtureCommands) nativeSaaS(readOnly bool) (*experimentalapp.SaaSProfileCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return experimentalapp.NewSaaSProfileCommands(experimentalapp.SaaSProfileConfig{Transactions: peripheralNativeTransactions{f.catalogFixtureCommands, readOnly}, Clock: clock, IDs: ids})
}
func (f peripheralFixtureCommands) nativeMarketplace(readOnly bool) (*experimentalapp.MarketplaceCollectorCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return experimentalapp.NewMarketplaceCollectorCommands(experimentalapp.MarketplaceCollectorConfig{Transactions: peripheralNativeTransactions{f.catalogFixtureCommands, readOnly}, Clock: clock, IDs: ids})
}
func peripheralFixtureQueryClock() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }
func (f marketplaceQueryFixture) PageMarketplaceCollectors(ctx context.Context, req experimentalquery.MarketplaceCollectorPageRequest) (appquery.Result[experimentaldomain.MarketplaceCollector], error) {
	var out appquery.Result[experimentaldomain.MarketplaceCollector]
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(experimentalquery.MarketplaceCollectorReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = r.PageMarketplaceCollectors(ctx, req)
		return err
	})
	return out, err
}
func (f marketplaceQueryFixture) GetMarketplaceCollectorPoint(ctx context.Context, tenant, id string) (experimentalquery.MarketplaceCollectorPoint, error) {
	var out experimentalquery.MarketplaceCollectorPoint
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(experimentalquery.MarketplaceCollectorReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = r.GetMarketplaceCollectorPoint(ctx, tenant, id)
		return err
	})
	return out, err
}
