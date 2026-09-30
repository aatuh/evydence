package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildArtifactCommands composes digest-unique registration and current
// duplicate-grant checks without loading the Ledger's artifact maps.
func BuildArtifactCommands(reader releasequery.ArtifactPointReader, factory app.UnitOfWorkFactory) (*releaseapp.ArtifactCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("artifact grant reader and transactions are required")
	}
	authorizer, err := releasequery.NewArtifactWriteAuthorizer(reader)
	if err != nil {
		return nil, err
	}
	return releaseapp.NewArtifactCommands(releaseapp.ArtifactCommandConfig{
		Authorizer:   authorizer,
		Transactions: artifactTransactions{factory: factory, authorizer: authorizer},
		Clock:        application.ClockFunc(time.Now),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type artifactTransactions struct {
	factory    app.UnitOfWorkFactory
	authorizer application.Authorizer
}

func (t artifactTransactions) ExecuteArtifact(ctx context.Context, command func(context.Context, releaseapp.ArtifactTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.ReleaseCatalog == nil || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, artifactTransaction{
			catalog: repositories.ReleaseCatalog, audit: repositories.Audit, authorizer: t.authorizer,
		})
	}))
}

type artifactTransaction struct {
	catalog    app.ReleaseCatalogRepository
	audit      app.AuditRepository
	authorizer application.Authorizer
}

func (t artifactTransaction) ArtifactByDigest(ctx context.Context, tenantID, digest string) (releasedomain.Artifact, bool, error) {
	artifact, found, err := t.catalog.ArtifactByDigest(ctx, tenantID, digest)
	if err != nil {
		return releasedomain.Artifact{}, false, mapProductWriteError(err)
	}
	if !found {
		return releasedomain.Artifact{}, false, nil
	}
	return releasedomain.Artifact{
		ID: artifact.ID, TenantID: artifact.TenantID, Name: artifact.Name,
		MediaType: artifact.MediaType, Size: artifact.Size, Digest: artifact.Digest, CreatedAt: artifact.CreatedAt,
	}, true, nil
}

func (t artifactTransaction) InsertArtifact(ctx context.Context, artifact releasedomain.Artifact) error {
	return mapProductWriteError(t.catalog.InsertArtifact(ctx, domain.Artifact{
		ID: artifact.ID, TenantID: artifact.TenantID, Name: artifact.Name,
		MediaType: artifact.MediaType, Size: artifact.Size, Digest: artifact.Digest, CreatedAt: artifact.CreatedAt,
	}))
}

func (t artifactTransaction) AuthorizeExisting(ctx context.Context, actor identitydomain.Actor, id string) error {
	return t.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: releaseapp.ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: id},
	})
}

func (t artifactTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{catalog: t.catalog, audit: t.audit}.AppendAudit(ctx, event)
}
