package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

type transparencyNativeRepository interface {
	e.PublicTransparencyMetadataReader
	e.PublicTransparencyVerificationReader
	ReadPublicTransparencyFetch(context.Context, string, string) (e.PublicTransparencyFetchSource, error)
	InsertFocusedPublicTransparencyLog(context.Context, d.PublicTransparencyLog) error
	InsertFocusedPublicTransparencyEntry(context.Context, d.PublicTransparencyLogEntry) error
	UpdateFocusedPublicTransparencyVerification(context.Context, d.PublicTransparencyLogEntry, d.PublicTransparencyLogEntry) error
}
type transparencyNativeTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type transparencyNativeTransaction struct {
	transparencyNativeRepository
	repos    app.Repositories
	readOnly bool
}

func (f transparencyNativeTransactions) execute(ctx context.Context, tenant string, fn func(context.Context, transparencyNativeTransaction) error) error {
	return anomalyFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(transparencyNativeRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, transparencyNativeTransaction{r, repos, f.readOnly})
	}))
}
func (f transparencyNativeTransactions) ExecutePublicTransparencyMetadata(ctx context.Context, tenant string, fn func(context.Context, e.PublicTransparencyMetadataTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx transparencyNativeTransaction) error { return fn(ctx, tx) })
}
func (f transparencyNativeTransactions) ExecutePublicTransparencyVerification(ctx context.Context, tenant string, fn func(context.Context, e.PublicTransparencyVerificationTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx transparencyNativeTransaction) error { return fn(ctx, tx) })
}
func (f transparencyNativeTransactions) ExecutePublicTransparencyFetch(ctx context.Context, tenant string, fn func(context.Context, e.PublicTransparencyFetchTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx transparencyNativeTransaction) error { return fn(ctx, tx) })
}
func (tx transparencyNativeTransaction) InsertPublicTransparencyLog(ctx context.Context, v d.PublicTransparencyLog) error {
	if tx.readOnly {
		panic("transparency preflight wrote a log")
	}
	return tx.InsertFocusedPublicTransparencyLog(ctx, v)
}
func (tx transparencyNativeTransaction) InsertPublicTransparencyEntry(ctx context.Context, v d.PublicTransparencyLogEntry) error {
	if tx.readOnly {
		panic("transparency preflight published an entry")
	}
	return tx.InsertFocusedPublicTransparencyEntry(ctx, v)
}
func (tx transparencyNativeTransaction) UpdatePublicTransparencyVerification(ctx context.Context, v, expected d.PublicTransparencyLogEntry) error {
	if tx.readOnly {
		panic("transparency preflight wrote an assessment")
	}
	return tx.UpdateFocusedPublicTransparencyVerification(ctx, v, expected)
}
func (tx transparencyNativeTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if tx.readOnly {
		panic("transparency preflight appended audit")
	}
	return (portalFixtureTransaction{repos: tx.repos}).AppendAudit(ctx, v)
}

type transparencyNativeFetcher struct {
	client   app.TransparencyProofFetcher
	readOnly bool
}

func (f transparencyNativeFetcher) FetchTransparencyProof(ctx context.Context, r e.PublicTransparencyProofRequest) (e.PublicTransparencyFetchedProof, error) {
	if f.readOnly {
		panic("transparency preflight called provider")
	}
	v, err := f.client.FetchTransparencyProof(ctx, app.TransparencyProofRequest{TenantID: r.TenantID, LogID: r.LogID, EntryID: r.EntryID, Endpoint: r.Endpoint, ExternalID: r.ExternalID, EntryHash: r.EntryHash})
	if err != nil {
		return e.PublicTransparencyFetchedProof{}, err
	}
	return e.PublicTransparencyFetchedProof{ExternalID: v.ExternalID, Proof: e.PublicTransparencyProofInput{LeafHash: v.LeafHash, RootHash: v.RootHash, LeafIndex: v.LeafIndex, TreeSize: v.TreeSize, InclusionProof: v.InclusionProof}}, nil
}
func (f transparencyFixtureCommands) nativeMetadata(readOnly bool) (*e.PublicTransparencyMetadataCommands, error) {
	clock, ids := f.transparencyClockIDs(readOnly)
	return e.NewPublicTransparencyMetadataCommands(e.PublicTransparencyMetadataConfig{Transactions: transparencyNativeTransactions{f.catalogFixtureCommands, readOnly}, Clock: clock, IDs: ids})
}
func (f transparencyFixtureCommands) nativeProof(readOnly bool) (*e.PublicTransparencyVerificationCommands, error) {
	clock, ids := f.transparencyClockIDs(readOnly)
	return e.NewPublicTransparencyVerificationCommands(e.PublicTransparencyVerificationConfig{Transactions: transparencyNativeTransactions{f.catalogFixtureCommands, readOnly}, Clock: clock, IDs: ids})
}
func (f transparencyFixtureCommands) nativeFetch(readOnly bool) (*e.PublicTransparencyFetchCommands, error) {
	clock, ids := f.transparencyClockIDs(readOnly)
	var fetcher e.PublicTransparencyProofFetcher
	if f.fetcher != nil {
		fetcher = transparencyNativeFetcher{f.fetcher, readOnly}
	}
	return e.NewPublicTransparencyFetchCommands(e.PublicTransparencyFetchConfig{Transactions: transparencyNativeTransactions{f.catalogFixtureCommands, readOnly}, Fetcher: fetcher, Clock: clock, IDs: ids})
}

// Explicit fake I/O stays in existing test-only ports, not Server/Ledger
// fields or a global registry. Non-fixture command implementations are kept.
func transparencyFixtureClock() application.Clock {
	return application.ClockFunc(peripheralFixtureQueryClock)
}
func (f transparencyFixtureCommands) transparencyClockIDs(readOnly bool) (application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return clock, ids
}
func (s *Server) bindTransparencyFixtureResources(fetcher app.TransparencyProofFetcher, clock application.Clock) {
	if f, ok := s.publicTransparencyMetadata.(transparencyFixtureCommands); ok {
		f.fetcher = fetcher
		f.clock = clock
		s.publicTransparencyMetadata = f
	}
	if f, ok := s.publicTransparencyProofs.(transparencyFixtureCommands); ok {
		f.fetcher = fetcher
		f.clock = clock
		s.publicTransparencyProofs = f
	}
	if f, ok := s.publicTransparencyFetch.(transparencyFixtureCommands); ok {
		f.fetcher = fetcher
		f.clock = clock
		s.publicTransparencyFetch = f
	}
}
