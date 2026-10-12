package wiring

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func BuildContainerImageCommands(factory app.UnitOfWorkFactory) (*releaseapp.ContainerImageCommands, error) {
	if factory == nil {
		return nil, errors.New("container image transactions are required")
	}
	reads := buildCreationReads{factory}
	auth, err := releasequery.NewArtifactWriteAuthorizer(buildArtifactGrants{reads})
	if err != nil {
		return nil, err
	}
	return releaseapp.NewContainerImageCommands(releaseapp.ContainerImageCommandConfig{
		Reader: buildParentReader{reads}, Authorizer: auth, Transactions: containerImageTransactions{factory},
		Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type containerImageTransactions struct{ factory app.UnitOfWorkFactory }

func (t containerImageTransactions) ExecuteContainerImage(ctx context.Context, fn func(context.Context, releaseapp.ContainerImageTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		artifacts, ok := repos.ReleaseCatalog.(BuildStorageReader)
		images, valid := repos.SupplyChain.(releaseapp.ContainerImageIdentityReader)
		if !ok || !valid || repos.Audit == nil {
			return app.ErrValidation
		}
		auth, err := releasequery.NewArtifactWriteAuthorizer(buildArtifactGrants{artifacts})
		if err != nil {
			return err
		}
		return fn(ctx, containerImageTransaction{buildParentReader{artifacts}, images, repos.SupplyChain, repos.Audit, auth})
	}))
}

type containerImageTransaction struct {
	buildParentReader
	images     releaseapp.ContainerImageIdentityReader
	supply     app.SupplyChainRepository
	audit      app.AuditRepository
	authorizer application.Authorizer
}

func (t containerImageTransaction) ContainerImageRegistrationIdentityByKey(ctx context.Context, tenant, repository, digest string) (releaseapp.ContainerImageRegistrationIdentity, bool, error) {
	r, ok := t.images.(interface {
		ContainerImageRegistrationIdentityByKey(context.Context, string, string, string) (releaseapp.ContainerImageRegistrationIdentity, bool, error)
	})
	if !ok {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, releaseapp.ErrValidation
	}
	v, found, err := r.ContainerImageRegistrationIdentityByKey(ctx, tenant, repository, digest)
	return v, found, mapProductWriteError(err)
}
func (t containerImageTransaction) ReadContainerImageRegistrationArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	r, ok := t.source.(releaseapp.BuildCreationGuardReader)
	if !ok {
		return releasedomain.Artifact{}, releaseapp.ErrValidation
	}
	v, err := r.ReadBuildCreationArtifact(ctx, tenant, id)
	return v, mapProductWriteError(err)
}

func (t containerImageTransaction) ContainerImageByRepositoryDigest(ctx context.Context, tenant, repository, digest string) (releasedomain.ContainerImage, bool, error) {
	v, found, err := t.images.ContainerImageByRepositoryDigest(ctx, tenant, repository, digest)
	return v, found, mapProductWriteError(err)
}
func (t containerImageTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	return t.authorizer.Authorize(ctx, actor, r)
}
func (t containerImageTransaction) InsertContainerImage(ctx context.Context, v releasedomain.ContainerImage) error {
	// Match the bounded read projection: newly written records must remain
	// readable, and unsupported storage text must fail as client validation.
	for _, field := range []struct {
		text  string
		limit int
	}{{v.ID, 1024}, {v.TenantID, 1024}, {v.ArtifactID, 1024}, {v.Repository, 65536}, {v.Tag, 65536}, {v.Digest, 71}, {v.Platform, 65536}, {v.SchemaVersion, 1024}} {
		if len(field.text) > field.limit || !utf8.ValidString(field.text) || strings.ContainsRune(field.text, 0) {
			return releaseapp.ErrValidation
		}
	}
	return mapProductWriteError(t.supply.InsertContainerImage(ctx, domain.ContainerImage{ID: v.ID, TenantID: v.TenantID, ArtifactID: v.ArtifactID, Repository: v.Repository, Tag: v.Tag, Digest: v.Digest, Platform: v.Platform, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t containerImageTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}
