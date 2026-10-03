package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildCandidateStateCommands needs only the caller's transaction factory;
// neither a pool reader nor a Ledger snapshot participates in transitions.
func BuildCandidateStateCommands(factory app.UnitOfWorkFactory) (*releaseapp.CandidateStateCommands, error) {
	if factory == nil {
		return nil, errors.New("candidate state transactions are required")
	}
	return releaseapp.NewCandidateStateCommands(releaseapp.CandidateStateCommandConfig{
		Authorizer: releasequery.NewCatalogAuthorizer(), Transactions: candidateStateTransactions{factory: factory},
		Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type candidateStateTransactions struct{ factory app.UnitOfWorkFactory }

func (t candidateStateTransactions) ExecuteCandidateState(ctx context.Context, fn func(context.Context, releaseapp.CandidateStateTransaction) error) error {
	return mapReleaseStateWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(releaseapp.CandidateStateReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, candidateStateTransaction{reader: reader, writer: repos.ReleaseCatalog, audit: repos.Audit})
	}))
}

type candidateStateTransaction struct {
	reader releaseapp.CandidateStateReader
	writer interface {
		UpdateReleaseCandidateState(context.Context, domain.ReleaseCandidate, string) error
	}
	audit app.AuditRepository
}

func (t candidateStateTransaction) ReadCandidateState(ctx context.Context, tenant, id string) (releaseapp.CandidateStateRow, error) {
	v, err := t.reader.ReadCandidateState(ctx, tenant, id)
	return v, mapReleaseStateWriteError(err)
}
func (t candidateStateTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, req application.AuthorizationRequest) error {
	return releasequery.NewCatalogAuthorizer().Authorize(ctx, actor, req)
}
func (t candidateStateTransaction) UpdateCandidateState(ctx context.Context, v releasedomain.ReleaseCandidate, revision int64, state string) error {
	if v.Revision != revision+1 {
		return releaseapp.ErrConflict
	}
	return mapReleaseStateWriteError(t.writer.UpdateReleaseCandidateState(ctx, domain.ReleaseCandidate{
		ID: v.ID, TenantID: v.TenantID, ReleaseID: v.ReleaseID, Name: v.Name, Revision: v.Revision, State: v.State.String(),
		BuildIDs: v.BuildIDs, ArtifactIDs: v.ArtifactIDs, SBOMIDs: v.SBOMIDs, ScanIDs: v.ScanIDs, VEXIDs: v.VEXIDs, ContractIDs: v.ContractIDs, BundleIDs: v.BundleIDs,
		SnapshotHash: v.SnapshotHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt, PromotedAt: v.PromotedAt, RejectedAt: v.RejectedAt,
	}, state))
}
func (t candidateStateTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}
