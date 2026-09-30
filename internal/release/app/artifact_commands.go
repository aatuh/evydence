package app

import (
	"context"
	"errors"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ArtifactTransaction keeps digest lookup, duplicate authorization, insertion,
// and audit inside the caller's commit boundary.
type ArtifactTransaction interface {
	ArtifactByDigest(context.Context, string, string) (releasedomain.Artifact, bool, error)
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
	input.Name = strings.TrimSpace(input.Name)
	input.MediaType = strings.TrimSpace(input.MediaType)
	input.Digest = strings.TrimSpace(input.Digest)
	if input.Name == "" || input.MediaType == "" || !validDigest(input.Digest) || input.Size < 0 {
		return releasedomain.Artifact{}, ErrValidation
	}
	artifact := releasedomain.Artifact{
		ID: s.ids.NewID("art"), TenantID: actor.TenantID, Name: input.Name,
		MediaType: input.MediaType, Size: input.Size, Digest: input.Digest, CreatedAt: s.clock.Now().UTC(),
	}
	err := s.transactions.ExecuteArtifact(ctx, func(ctx context.Context, tx ArtifactTransaction) error {
		if existing, exists, err := tx.ArtifactByDigest(ctx, actor.TenantID, input.Digest); err != nil {
			return err
		} else if exists {
			if err := authorizeExistingArtifact(ctx, tx, actor, existing, input.Digest); err != nil {
				return err
			}
			artifact = existing
			return nil
		}
		if err := tx.InsertArtifact(ctx, artifact); err != nil {
			if errors.Is(err, ErrConflict) {
				existing, exists, lookupErr := tx.ArtifactByDigest(ctx, actor.TenantID, input.Digest)
				if lookupErr != nil {
					return lookupErr
				}
				if exists {
					if err := authorizeExistingArtifact(ctx, tx, actor, existing, input.Digest); err != nil {
						return err
					}
					artifact = existing
					return nil
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

func authorizeExistingArtifact(ctx context.Context, tx ArtifactTransaction, actor identitydomain.Actor, existing releasedomain.Artifact, digest string) error {
	if existing.TenantID != actor.TenantID || strings.TrimSpace(existing.ID) == "" {
		return ErrNotFound
	}
	if existing.Digest != digest {
		return ErrConflict
	}
	return tx.AuthorizeExisting(ctx, actor, existing.ID)
}

type releaseArtifactTransactions struct{ runner TransactionRunner }

func (r releaseArtifactTransactions) ExecuteArtifact(ctx context.Context, command func(context.Context, ArtifactTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, releaseArtifactTransaction{tx: tx})
	})
}

type releaseArtifactTransaction struct{ tx Transaction }

func (t releaseArtifactTransaction) ArtifactByDigest(ctx context.Context, tenantID, digest string) (releasedomain.Artifact, bool, error) {
	return t.tx.Catalog().ArtifactByDigest(ctx, tenantID, digest)
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
