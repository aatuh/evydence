package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	e "github.com/aatuh/evydence/internal/experimental/app"
)

func BuildPublicTransparencyFetchCommands(factory app.UnitOfWorkFactory, client app.TransparencyProofFetcher) (*e.PublicTransparencyFetchCommands, error) {
	if factory == nil {
		return nil, errors.New("public transparency fetch transactions are required")
	}
	var fetcher e.PublicTransparencyProofFetcher
	if client != nil {
		fetcher = publicTransparencyProofFetcher{client}
	}
	return e.NewPublicTransparencyFetchCommands(e.PublicTransparencyFetchConfig{Transactions: publicTransparencyFetchTransactions{factory}, Fetcher: fetcher, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type publicTransparencyProofFetcher struct{ client app.TransparencyProofFetcher }

func (f publicTransparencyProofFetcher) FetchTransparencyProof(ctx context.Context, r e.PublicTransparencyProofRequest) (e.PublicTransparencyFetchedProof, error) {
	v, err := f.client.FetchTransparencyProof(ctx, app.TransparencyProofRequest{TenantID: r.TenantID, LogID: r.LogID, EntryID: r.EntryID, Endpoint: r.Endpoint, ExternalID: r.ExternalID, EntryHash: r.EntryHash})
	if err != nil {
		return e.PublicTransparencyFetchedProof{}, err
	}
	return e.PublicTransparencyFetchedProof{ExternalID: v.ExternalID, Proof: e.PublicTransparencyProofInput{LeafHash: v.LeafHash, RootHash: v.RootHash, LeafIndex: v.LeafIndex, TreeSize: v.TreeSize, InclusionProof: v.InclusionProof}}, nil
}

type publicTransparencyFetchRepository interface {
	publicTransparencyVerificationRepository
	ReadPublicTransparencyFetch(context.Context, string, string) (e.PublicTransparencyFetchSource, error)
}
type publicTransparencyFetchTransactions struct{ factory app.UnitOfWorkFactory }

func (t publicTransparencyFetchTransactions) ExecutePublicTransparencyFetch(ctx context.Context, tenant string, fn func(context.Context, e.PublicTransparencyFetchTransaction) error) error {
	return mapAnomalyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(publicTransparencyFetchRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, publicTransparencyFetchTransaction{publicTransparencyVerificationTransaction{r, repos.Audit}, r})
	}))
}

type publicTransparencyFetchTransaction struct {
	publicTransparencyVerificationTransaction
	reader publicTransparencyFetchRepository
}

func (t publicTransparencyFetchTransaction) ReadPublicTransparencyFetch(ctx context.Context, tenant, id string) (e.PublicTransparencyFetchSource, error) {
	v, err := t.reader.ReadPublicTransparencyFetch(ctx, tenant, id)
	return v, mapAnomalyWriteError(err)
}
