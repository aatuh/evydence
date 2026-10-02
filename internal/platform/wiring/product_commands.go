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

// BuildProductCommands composes the release-owned product command directly on
// transaction-scoped repositories. It never constructs or loads a Ledger.
func BuildProductCommands(factory app.UnitOfWorkFactory) (*releaseapp.ProductCommands, error) {
	if factory == nil {
		return nil, errors.New("product transactions are required")
	}
	return releaseapp.NewProductCommands(releaseapp.ProductCommandConfig{
		Authorizer:   releasequery.NewCatalogAuthorizer(),
		Transactions: productTransactions{factory: factory},
		Clock:        application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}

type productTransactions struct{ factory app.UnitOfWorkFactory }

func (t productTransactions) ExecuteProduct(ctx context.Context, command func(context.Context, releaseapp.ProductTransaction) error) error {
	return mapProductWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		slugs, ok := repositories.ReleaseCatalog.(releaseapp.ProductSlugReader)
		if !ok || repositories.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, productTransaction{slugs: slugs, writer: repositories.ReleaseCatalog, audit: repositories.Audit})
	}))
}

type productTransaction struct {
	slugs  releaseapp.ProductSlugReader
	writer interface {
		InsertProduct(context.Context, domain.Product) error
	}
	audit app.AuditRepository
}

func (t productTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return releasequery.NewCatalogAuthorizer().Authorize(ctx, actor, request)
}

func (t productTransaction) ProductSlugExists(ctx context.Context, tenantID, slug string) (bool, error) {
	exists, err := t.slugs.ProductSlugExists(ctx, tenantID, slug)
	return exists, mapProductWriteError(err)
}

func (t productTransaction) InsertProduct(ctx context.Context, product releasedomain.Product) error {
	for _, field := range []struct {
		text  string
		limit int
	}{{product.ID, 1024}, {product.TenantID, 1024}, {product.Name, 65536}, {product.Slug, 1024}} {
		if field.text == "" || len(field.text) > field.limit || !utf8.ValidString(field.text) || strings.ContainsRune(field.text, 0) {
			return releaseapp.ErrValidation
		}
	}
	return mapProductWriteError(t.writer.InsertProduct(ctx, domain.Product{ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt}))
}

func (t productTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return catalogTransaction{audit: t.audit}.AppendAudit(ctx, event)
}

// Shared audit translation holds no catalog reader or writer capability.
type catalogTransaction struct {
	audit app.AuditRepository
}

func (t catalogTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry, err := t.audit.Append(ctx, domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType,
		SubjectType: event.SubjectType, SubjectID: event.SubjectID,
		ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef,
		SchemaVersion: domain.AuditChainEntrySchemaVersion,
	})
	if err != nil {
		return application.AuditReceipt{}, mapProductWriteError(err)
	}
	return application.AuditReceipt{ID: entry.ID}, nil
}

func mapProductWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return releaseapp.ErrValidation
	case errors.Is(err, app.ErrConflict):
		return releaseapp.ErrConflict
	case errors.Is(err, app.ErrNotFound):
		return releaseapp.ErrNotFound
	default:
		return err
	}
}
