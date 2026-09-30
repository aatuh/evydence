package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ReleaseReader supplies a tenant-scoped product point read before the write.
// The transaction rechecks the parent and version uniqueness under one commit.
type ReleaseReader interface {
	GetProduct(context.Context, string, string) (releasedomain.Product, error)
}

type ReleaseCreationTransaction interface {
	GetProduct(context.Context, string, string) (releasedomain.Product, error)
	ReleaseByVersion(context.Context, string, string, string) (releasedomain.Release, bool, error)
	InsertRelease(context.Context, releasedomain.Release) error
	AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error)
}

type ReleaseCreationTransactionRunner interface {
	ExecuteReleaseCreation(context.Context, func(context.Context, ReleaseCreationTransaction) error) error
}

type ReleaseCommandConfig struct {
	Reader       ReleaseReader
	Authorizer   application.Authorizer
	Transactions ReleaseCreationTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type ReleaseCommands struct {
	reader       ReleaseReader
	authorizer   application.Authorizer
	transactions ReleaseCreationTransactionRunner
	clock        application.Clock
	ids          application.IDGenerator
}

func NewReleaseCommands(config ReleaseCommandConfig) (*ReleaseCommands, error) {
	if config.Reader == nil || config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ReleaseCommands{
		reader: config.Reader, authorizer: config.Authorizer, transactions: config.Transactions,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

func (s *ReleaseCommands) CreateRelease(ctx context.Context, actor identitydomain.Actor, input CreateReleaseInput) (releasedomain.Release, error) {
	if s == nil {
		return releasedomain.Release{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.Release{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return releasedomain.Release{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.Version = strings.TrimSpace(input.Version)
	if input.ProductID == "" || input.Version == "" {
		return releasedomain.Release{}, ErrValidation
	}
	product, err := s.reader.GetProduct(ctx, actor.TenantID, input.ProductID)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if !productBelongsToTenant(product, actor.TenantID, input.ProductID) {
		return releasedomain.Release{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: product.ID},
	}); err != nil {
		return releasedomain.Release{}, err
	}
	release, err := releasedomain.NewRelease(s.ids.NewID("rel"), actor.TenantID, product.ID, input.Version, s.clock.Now())
	if err != nil {
		return releasedomain.Release{}, ErrValidation
	}
	err = s.transactions.ExecuteReleaseCreation(ctx, func(ctx context.Context, tx ReleaseCreationTransaction) error {
		current, err := tx.GetProduct(ctx, actor.TenantID, product.ID)
		if err != nil {
			return err
		}
		if !productBelongsToTenant(current, actor.TenantID, product.ID) {
			return ErrNotFound
		}
		if !sameProductCoordinates(current, product) {
			return ErrConflict
		}
		if existing, exists, err := tx.ReleaseByVersion(ctx, actor.TenantID, product.ID, input.Version); err != nil {
			return err
		} else if exists {
			if existing.TenantID != actor.TenantID || strings.TrimSpace(existing.ID) == "" {
				return ErrNotFound
			}
			return ErrConflict
		}
		if err := tx.InsertRelease(ctx, release); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, auditEventFor(s.ids, actor, release.CreatedAt, "release.created", "release", release.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return release, nil
}

type releaseCreationTransactions struct{ runner TransactionRunner }

func (r releaseCreationTransactions) ExecuteReleaseCreation(ctx context.Context, command func(context.Context, ReleaseCreationTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, releaseCreationTransaction{tx: tx})
	})
}

type releaseCreationTransaction struct{ tx Transaction }

func (t releaseCreationTransaction) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	return t.tx.Catalog().GetProduct(ctx, tenantID, id)
}

func (t releaseCreationTransaction) ReleaseByVersion(ctx context.Context, tenantID, productID, version string) (releasedomain.Release, bool, error) {
	return t.tx.Catalog().ReleaseByVersion(ctx, tenantID, productID, version)
}

func (t releaseCreationTransaction) InsertRelease(ctx context.Context, release releasedomain.Release) error {
	return t.tx.Catalog().InsertRelease(ctx, release)
}

func (t releaseCreationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
