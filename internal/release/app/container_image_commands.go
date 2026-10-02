package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type ContainerImageArtifactReader interface {
	GetArtifact(context.Context, string, string) (releasedomain.Artifact, error)
}

// ContainerImageTransaction exposes only immutable artifact coordinates,
// current authorization, repository/digest identity, image writes and audit.
type ContainerImageTransaction interface {
	ContainerImageArtifactReader
	application.Authorizer
	application.AuditAppender
	ContainerImageByRepositoryDigest(context.Context, string, string, string) (releasedomain.ContainerImage, bool, error)
	InsertContainerImage(context.Context, releasedomain.ContainerImage) error
}

type ContainerImageTransactionRunner interface {
	ExecuteContainerImage(context.Context, func(context.Context, ContainerImageTransaction) error) error
}

type ContainerImageCommandConfig struct {
	Reader       ContainerImageArtifactReader
	Authorizer   application.Authorizer
	Transactions ContainerImageTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type ContainerImageCommands struct {
	reader       ContainerImageArtifactReader
	authorizer   application.Authorizer
	transactions ContainerImageTransactionRunner
	clock        application.Clock
	ids          application.IDGenerator
}

func NewContainerImageCommands(c ContainerImageCommandConfig) (*ContainerImageCommands, error) {
	if c.Reader == nil || c.Authorizer == nil || c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &ContainerImageCommands{c.Reader, c.Authorizer, c.Transactions, c.Clock, c.IDs}, nil
}

func (s *ContainerImageCommands) RegisterContainerImage(ctx context.Context, actor identitydomain.Actor, input RegisterContainerImageInput) (releasedomain.ContainerImage, error) {
	if s == nil {
		return releasedomain.ContainerImage{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.ContainerImage{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return releasedomain.ContainerImage{}, err
	}
	input.ArtifactID = strings.TrimSpace(input.ArtifactID)
	input.Repository = strings.TrimSpace(input.Repository)
	input.Tag = strings.TrimSpace(input.Tag)
	input.Digest = strings.TrimSpace(input.Digest)
	input.Platform = strings.TrimSpace(input.Platform)
	if input.Repository == "" || !validDigest(input.Digest) {
		return releasedomain.ContainerImage{}, ErrValidation
	}
	var artifact releasedomain.Artifact
	if input.ArtifactID != "" {
		var err error
		artifact, err = s.reader.GetArtifact(ctx, actor.TenantID, input.ArtifactID)
		if err != nil {
			return releasedomain.ContainerImage{}, err
		}
		if !artifactBelongsToTenant(artifact, actor.TenantID, input.ArtifactID) || artifact.Digest != input.Digest {
			return releasedomain.ContainerImage{}, ErrNotFound
		}
		if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: artifact.ID}}); err != nil {
			return releasedomain.ContainerImage{}, err
		}
	}
	var image releasedomain.ContainerImage
	err := s.transactions.ExecuteContainerImage(ctx, func(ctx context.Context, tx ContainerImageTransaction) error {
		if input.ArtifactID != "" {
			current, err := tx.GetArtifact(ctx, actor.TenantID, artifact.ID)
			if err != nil {
				return err
			}
			if !artifactBelongsToTenant(current, actor.TenantID, artifact.ID) {
				return ErrNotFound
			}
			if !sameArtifactCoordinates(current, artifact) {
				return ErrConflict
			}
			if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: current.ID}}); err != nil {
				return err
			}
		}
		existing, exists, err := tx.ContainerImageByRepositoryDigest(ctx, actor.TenantID, input.Repository, input.Digest)
		if err != nil {
			return err
		}
		if exists {
			if existing.TenantID != actor.TenantID || strings.TrimSpace(existing.ID) == "" {
				return ErrNotFound
			}
			if existing.Repository != input.Repository || existing.Digest != input.Digest {
				return ErrConflict
			}
			if existing.ArtifactID != "" {
				current, err := tx.GetArtifact(ctx, actor.TenantID, existing.ArtifactID)
				if err != nil {
					return err
				}
				if !artifactBelongsToTenant(current, actor.TenantID, existing.ArtifactID) {
					return ErrNotFound
				}
				if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: current.ID}}); err != nil {
					return err
				}
				if current.Digest != existing.Digest {
					return ErrConflict
				}
			}
			if input.ArtifactID != "" && existing.ArtifactID != input.ArtifactID {
				return ErrConflict
			}
			image = existing
			return nil
		}
		commandAt := s.clock.Now().UTC()
		image = releasedomain.ContainerImage{
			ID: s.ids.NewID("img"), TenantID: actor.TenantID, ArtifactID: input.ArtifactID,
			Repository: input.Repository, Tag: input.Tag, Digest: input.Digest, Platform: input.Platform,
			SchemaVersion: releasedomain.ContainerImageSchemaVersion, CreatedAt: commandAt,
		}
		if err := tx.InsertContainerImage(ctx, image); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, auditEventFor(s.ids, actor, commandAt, "container_image.created", "container_image", image.ID, image.Digest))
		return err
	})
	if err != nil {
		return releasedomain.ContainerImage{}, err
	}
	return image, nil
}

// Legacy/local bridge only; durable composition supplies the flat capability.
type releaseContainerImageTransactions struct{ runner TransactionRunner }

func (r releaseContainerImageTransactions) ExecuteContainerImage(ctx context.Context, fn func(context.Context, ContainerImageTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, releaseContainerImageTransaction{tx})
	})
}

type releaseContainerImageTransaction struct{ tx Transaction }

func (t releaseContainerImageTransaction) GetArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	return t.tx.Catalog().GetArtifact(ctx, tenant, id)
}
func (t releaseContainerImageTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	return t.tx.Authorization().Authorize(ctx, actor, r)
}
func (t releaseContainerImageTransaction) ContainerImageByRepositoryDigest(ctx context.Context, tenant, repository, digest string) (releasedomain.ContainerImage, bool, error) {
	return t.tx.SupplyChain().ContainerImageByRepositoryDigest(ctx, tenant, repository, digest)
}
func (t releaseContainerImageTransaction) InsertContainerImage(ctx context.Context, image releasedomain.ContainerImage) error {
	return t.tx.SupplyChain().InsertContainerImage(ctx, image)
}
func (t releaseContainerImageTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
