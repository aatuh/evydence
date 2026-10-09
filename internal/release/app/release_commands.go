package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type ReleaseVersionReader interface {
	ReleaseVersionExists(context.Context, string, string, string) (bool, error)
}

type ReleaseCreationTransaction interface {
	ProductCoordinateReader
	ReleaseVersionReader
	InsertRelease(context.Context, releasedomain.Release) error
	AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error)
}

type ReleaseCreationTransactionRunner interface {
	ExecuteReleaseCreation(context.Context, func(context.Context, ReleaseCreationTransaction) error) error
}

type ReleaseCommandConfig struct {
	Reader       ProductCoordinateReader
	Authorizer   application.Authorizer
	Transactions ReleaseCreationTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type ReleaseCommands struct {
	reader       ProductCoordinateReader
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
	var err error
	input, err = NormalizeReleaseCreationInput(input)
	if err != nil {
		return releasedomain.Release{}, err
	}
	product, err := s.reader.ReadProductCoordinates(ctx, actor.TenantID, input.ProductID)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if product.TenantID != actor.TenantID || product.ID != input.ProductID {
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
		if guard, ok := tx.(catalogCreationGuardTransaction); ok {
			if err := authorizeCatalogCreationScope(ctx, guard, actor, ScopeReleaseWrite, input.ProductID); err != nil {
				return err
			}
		}
		current, err := tx.ReadProductCoordinates(ctx, actor.TenantID, product.ID)
		if err != nil {
			return err
		}
		if current.TenantID != actor.TenantID || current.ID != product.ID {
			return ErrNotFound
		}
		if current != product {
			return ErrConflict
		}
		if exists, err := tx.ReleaseVersionExists(ctx, actor.TenantID, product.ID, input.Version); err != nil {
			return err
		} else if exists {
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

func (t releaseCreationTransaction) ReadProductCoordinates(ctx context.Context, tenantID, id string) (ProductCoordinates, error) {
	return legacyProductCoordinates{source: t.tx.Catalog()}.ReadProductCoordinates(ctx, tenantID, id)
}

func (t releaseCreationTransaction) ReleaseVersionExists(ctx context.Context, tenantID, productID, version string) (bool, error) {
	v, found, err := t.tx.Catalog().ReleaseByVersion(ctx, tenantID, productID, version)
	if err != nil {
		return false, err
	}
	if found && (v.TenantID != tenantID || strings.TrimSpace(v.ID) == "") {
		return false, ErrNotFound
	}
	return found, nil
}

func (t releaseCreationTransaction) InsertRelease(ctx context.Context, release releasedomain.Release) error {
	return t.tx.Catalog().InsertRelease(ctx, release)
}

func (t releaseCreationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
