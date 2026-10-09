package app

import (
	"context"
	"errors"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type ArtifactRegistrationIdentity struct {
	ID       string
	TenantID string
	Digest   string
}

type ArtifactRegistrationReader interface {
	ArtifactIdentityByDigest(context.Context, string, string) (ArtifactRegistrationIdentity, bool, error)
	ReadArtifactMetadata(context.Context, string, string) (releasedomain.Artifact, error)
}

// ArtifactTransaction separates identity/grant checks from private metadata
// reads and keeps all effects inside the caller's commit boundary.
type ArtifactTransaction interface {
	ArtifactRegistrationReader
	InsertArtifact(context.Context, releasedomain.Artifact) error
	AuthorizeExisting(context.Context, identitydomain.Actor, string) error
	AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error)
}

type ArtifactTransactionRunner interface {
	ExecuteArtifact(context.Context, func(context.Context, ArtifactTransaction) error) error
}

type ArtifactCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ArtifactTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type ArtifactCommands struct {
	authorizer   application.Authorizer
	transactions ArtifactTransactionRunner
	clock        application.Clock
	ids          application.IDGenerator
}

func NewArtifactCommands(config ArtifactCommandConfig) (*ArtifactCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ArtifactCommands{
		authorizer: config.Authorizer, transactions: config.Transactions,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

func (s *ArtifactCommands) RegisterArtifact(ctx context.Context, actor identitydomain.Actor, input RegisterArtifactInput) (releasedomain.Artifact, error) {
	if s == nil {
		return releasedomain.Artifact{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.Artifact{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return releasedomain.Artifact{}, err
	}
	var err error
	input, err = NormalizeArtifactRegistrationInput(input)
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	artifact := releasedomain.Artifact{
		ID: s.ids.NewID("art"), TenantID: actor.TenantID, Name: input.Name,
		MediaType: input.MediaType, Size: input.Size, Digest: input.Digest, CreatedAt: s.clock.Now().UTC(),
	}
	err = s.transactions.ExecuteArtifact(ctx, func(ctx context.Context, tx ArtifactTransaction) error {
		if existing, exists, err := tx.ArtifactIdentityByDigest(ctx, actor.TenantID, input.Digest); err != nil {
			return err
		} else if exists {
			var err error
			artifact, err = readAuthorizedArtifact(ctx, tx, actor, existing, input.Digest)
			return err
		}
		if err := tx.InsertArtifact(ctx, artifact); err != nil {
			if errors.Is(err, ErrConflict) {
				existing, exists, lookupErr := tx.ArtifactIdentityByDigest(ctx, actor.TenantID, input.Digest)
				if lookupErr != nil {
					return lookupErr
				}
				if exists {
					var err error
					artifact, err = readAuthorizedArtifact(ctx, tx, actor, existing, input.Digest)
					return err
				}
			}
			return err
		}
		_, err := tx.AppendAudit(ctx, auditEventFor(s.ids, actor, artifact.CreatedAt, "artifact.created", "artifact", artifact.ID, artifact.Digest))
		return err
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return artifact, nil
}

func readAuthorizedArtifact(ctx context.Context, tx ArtifactTransaction, actor identitydomain.Actor, existing ArtifactRegistrationIdentity, digest string) (releasedomain.Artifact, error) {
	if existing.TenantID != actor.TenantID || strings.TrimSpace(existing.ID) == "" {
		return releasedomain.Artifact{}, ErrNotFound
	}
	if existing.Digest != digest {
		return releasedomain.Artifact{}, ErrConflict
	}
	if err := tx.AuthorizeExisting(ctx, actor, existing.ID); err != nil {
		return releasedomain.Artifact{}, err
	}
	artifact, err := tx.ReadArtifactMetadata(ctx, actor.TenantID, existing.ID)
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	if !artifactBelongsToTenant(artifact, actor.TenantID, existing.ID) {
		return releasedomain.Artifact{}, ErrNotFound
	}
	if artifact.Digest != existing.Digest {
		return releasedomain.Artifact{}, ErrConflict
	}
	return artifact, nil
}

type releaseArtifactTransactions struct{ runner TransactionRunner }

func (r releaseArtifactTransactions) ExecuteArtifact(ctx context.Context, command func(context.Context, ArtifactTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, releaseArtifactTransaction{tx: tx})
	})
}

type releaseArtifactTransaction struct{ tx Transaction }

func (t releaseArtifactTransaction) ArtifactIdentityByDigest(ctx context.Context, tenantID, digest string) (ArtifactRegistrationIdentity, bool, error) {
	v, found, err := t.tx.Catalog().ArtifactByDigest(ctx, tenantID, digest)
	return ArtifactRegistrationIdentity{ID: v.ID, TenantID: v.TenantID, Digest: v.Digest}, found, err
}

func (t releaseArtifactTransaction) ReadArtifactMetadata(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	return t.tx.Catalog().GetArtifact(ctx, tenantID, id)
}

func (t releaseArtifactTransaction) InsertArtifact(ctx context.Context, artifact releasedomain.Artifact) error {
	return t.tx.Catalog().InsertArtifact(ctx, artifact)
}

func (t releaseArtifactTransaction) AuthorizeExisting(ctx context.Context, actor identitydomain.Actor, id string) error {
	return t.tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: id},
	})
}

func (t releaseArtifactTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
