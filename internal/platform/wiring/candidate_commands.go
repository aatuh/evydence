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

// BuildCandidateCommands validates current parents and foreign references
// entirely through the active unit of work, without a pool or Ledger reader.
func BuildCandidateCommands(factory app.UnitOfWorkFactory) (*releaseapp.CandidateCommands, error) {
	if factory == nil {
		return nil, errors.New("candidate creation transactions are required")
	}
	return releaseapp.NewCandidateCommands(releaseapp.CandidateCommandConfig{Authorizer: releasequery.NewCatalogAuthorizer(), Transactions: candidateCreationTransactions{factory}, Canonicalizer: candidateCanonicalizer{}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type candidateCreationStorageReader interface {
	releaseapp.CandidateReleaseReader
	releaseapp.ReleaseCandidateReferenceValidator
	artifactGrantReader
}
type candidateCreationTransactions struct{ factory app.UnitOfWorkFactory }

func (t candidateCreationTransactions) ExecuteCandidateCreation(ctx context.Context, fn func(context.Context, releaseapp.CandidateCreationTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(candidateCreationStorageReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		auth, err := releasequery.NewCandidateAuthorizer(buildArtifactGrants{source: reader})
		if err != nil {
			return err
		}
		return fn(ctx, candidateCreationTransaction{reader: reader, writer: repos.ReleaseCatalog, audit: repos.Audit, authorizer: auth})
	}))
}

type candidateCreationTransaction struct {
	reader candidateCreationStorageReader
	writer interface {
		InsertReleaseCandidate(context.Context, domain.ReleaseCandidate) error
	}
	audit      app.AuditRepository
	authorizer application.Authorizer
}

func (t candidateCreationTransaction) ReadCandidateRelease(ctx context.Context, tenant, id string) (releaseapp.CandidateReleaseCoordinates, error) {
	v, err := t.reader.ReadCandidateRelease(ctx, tenant, id)
	return v, mapProductWriteError(err)
}
func (t candidateCreationTransaction) ValidateReleaseCandidateReferences(ctx context.Context, tenant, release string, refs releaseapp.ReleaseCandidateReferences) error {
	return mapProductWriteError(t.reader.ValidateReleaseCandidateReferences(ctx, tenant, release, refs))
}
func (t candidateCreationTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	err := t.authorizer.Authorize(ctx, actor, request)
	if errors.Is(err, releasequery.ErrValidation) {
		return releaseapp.ErrValidation
	}
	if errors.Is(err, releasequery.ErrNotFound) {
		return releaseapp.ErrNotFound
	}
	return err
}
func (t candidateCreationTransaction) InsertCandidate(ctx context.Context, v releasedomain.ReleaseCandidate) error {
	return mapProductWriteError(t.writer.InsertReleaseCandidate(ctx, candidateRecord(v)))
}
func (t candidateCreationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}

type candidateCanonicalizer struct{}

func (candidateCanonicalizer) HashReleaseCandidate(ctx context.Context, v releasedomain.ReleaseCandidate) (string, error) {
	if ctx == nil {
		return "", releaseapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(candidateRecord(v))
}

// Preserve the existing versioned normalized-JSON snapshot fields and tags.
func candidateRecord(v releasedomain.ReleaseCandidate) domain.ReleaseCandidate {
	return domain.ReleaseCandidate{ID: v.ID, TenantID: v.TenantID, ReleaseID: v.ReleaseID, Name: v.Name, Revision: v.Revision, State: v.State.String(), BuildIDs: v.BuildIDs, ArtifactIDs: v.ArtifactIDs, SBOMIDs: v.SBOMIDs, ScanIDs: v.ScanIDs, VEXIDs: v.VEXIDs, ContractIDs: v.ContractIDs, BundleIDs: v.BundleIDs, SnapshotHash: v.SnapshotHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt, PromotedAt: v.PromotedAt, RejectedAt: v.RejectedAt}
}
