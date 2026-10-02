package wiring

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

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
func BuildArtifactCommands(factory app.UnitOfWorkFactory) (*releaseapp.ArtifactCommands, error) {
	if factory == nil {
		return nil, errors.New("artifact transactions are required")
	}
	authorizer, err := releasequery.NewArtifactWriteAuthorizer(buildArtifactGrants{buildCreationReads{factory}})
	if err != nil {
		return nil, err
	}
	return releaseapp.NewArtifactCommands(releaseapp.ArtifactCommandConfig{
		Authorizer:   authorizer,
		Transactions: artifactTransactions{factory: factory},
		Clock:        application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type artifactTransactions struct{ factory app.UnitOfWorkFactory }

func (t artifactTransactions) ExecuteArtifact(ctx context.Context, command func(context.Context, releaseapp.ArtifactTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		grants, ok := repositories.ReleaseCatalog.(artifactGrantReader)
		reader, valid := repositories.ReleaseCatalog.(releaseapp.ArtifactRegistrationReader)
		if !ok || !valid || repositories.Audit == nil {
			return app.ErrValidation
		}
		authorizer, err := releasequery.NewArtifactWriteAuthorizer(buildArtifactGrants{grants})
		if err != nil {
			return err
		}
		return command(ctx, artifactTransaction{
			catalog: repositories.ReleaseCatalog, reader: reader, audit: repositories.Audit, authorizer: authorizer,
		})
	}))
}

type artifactTransaction struct {
	catalog interface {
		InsertArtifact(context.Context, domain.Artifact) error
	}
	reader     releaseapp.ArtifactRegistrationReader
	audit      app.AuditRepository
	authorizer application.Authorizer
}

func (t artifactTransaction) ArtifactIdentityByDigest(ctx context.Context, tenantID, digest string) (releaseapp.ArtifactRegistrationIdentity, bool, error) {
	v, found, err := t.reader.ArtifactIdentityByDigest(ctx, tenantID, digest)
	return v, found, mapProductWriteError(err)
}

func (t artifactTransaction) ReadArtifactMetadata(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	v, err := t.reader.ReadArtifactMetadata(ctx, tenantID, id)
	return v, mapProductWriteError(err)
}

func (t artifactTransaction) InsertArtifact(ctx context.Context, artifact releasedomain.Artifact) error {
	// New records must fit the bounded metadata projection used on reuse.
	for _, field := range []struct {
		text  string
		limit int
	}{{artifact.ID, 1024}, {artifact.TenantID, 1024}, {artifact.Name, 65536}, {artifact.MediaType, 65536}, {artifact.Digest, 71}} {
		if len(field.text) > field.limit || !utf8.ValidString(field.text) || strings.ContainsRune(field.text, 0) {
			return releaseapp.ErrValidation
		}
	}
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
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}
