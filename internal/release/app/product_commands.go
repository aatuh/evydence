package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ProductTransaction exposes only the product and audit writes required by
// product creation. A caller owns the transaction and its commit boundary.
type ProductTransaction interface {
	ProductBySlug(context.Context, string, string) (releasedomain.Product, bool, error)
	InsertProduct(context.Context, releasedomain.Product) error
	AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error)
}

type ProductTransactionRunner interface {
	ExecuteProduct(context.Context, func(context.Context, ProductTransaction) error) error
}

type ProductCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ProductTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type ProductCommands struct {
	authorizer   application.Authorizer
	transactions ProductTransactionRunner
	clock        application.Clock
	ids          application.IDGenerator
}

func NewProductCommands(config ProductCommandConfig) (*ProductCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ProductCommands{authorizer: config.Authorizer, transactions: config.Transactions, clock: config.Clock, ids: config.IDs}, nil
}

func (s *ProductCommands) CreateProduct(ctx context.Context, actor identitydomain.Actor, input CreateProductInput) (releasedomain.Product, error) {
	if s == nil {
		return releasedomain.Product{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.Product{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeProductWrite, TenantWide: true}); err != nil {
		return releasedomain.Product{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)
	if input.Name == "" || input.Slug == "" || len(input.Slug) > 1024 {
		return releasedomain.Product{}, ErrValidation
	}
	product := releasedomain.Product{ID: s.ids.NewID("prod"), TenantID: actor.TenantID, Name: input.Name, Slug: input.Slug, CreatedAt: s.clock.Now().UTC()}
	err := s.transactions.ExecuteProduct(ctx, func(ctx context.Context, tx ProductTransaction) error {
		if _, exists, err := tx.ProductBySlug(ctx, actor.TenantID, input.Slug); err != nil {
			return err
		} else if exists {
			return ErrConflict
		}
		if err := tx.InsertProduct(ctx, product); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, auditEventFor(s.ids, actor, product.CreatedAt, "product.created", "product", product.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Product{}, err
	}
	return product, nil
}

// releaseProductTransactions adapts the pre-existing full release service to
// the same focused product command without duplicating its business rules.
type releaseProductTransactions struct{ runner TransactionRunner }

func (r releaseProductTransactions) ExecuteProduct(ctx context.Context, command func(context.Context, ProductTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, releaseProductTransaction{tx: tx})
	})
}

type releaseProductTransaction struct{ tx Transaction }

func (t releaseProductTransaction) ProductBySlug(ctx context.Context, tenantID, slug string) (releasedomain.Product, bool, error) {
	return t.tx.Catalog().ProductBySlug(ctx, tenantID, slug)
}

func (t releaseProductTransaction) InsertProduct(ctx context.Context, product releasedomain.Product) error {
	return t.tx.Catalog().InsertProduct(ctx, product)
}

func (t releaseProductTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
