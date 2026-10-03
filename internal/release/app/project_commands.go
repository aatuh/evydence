package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type ProjectTransaction interface {
	ProductCoordinateReader
	InsertProject(context.Context, releasedomain.Project) error
	AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error)
}

type ProjectTransactionRunner interface {
	ExecuteProject(context.Context, func(context.Context, ProjectTransaction) error) error
}

type ProjectCommandConfig struct {
	Reader       ProductCoordinateReader
	Authorizer   application.Authorizer
	Transactions ProjectTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type ProjectCommands struct {
	reader       ProductCoordinateReader
	authorizer   application.Authorizer
	transactions ProjectTransactionRunner
	clock        application.Clock
	ids          application.IDGenerator
}

func NewProjectCommands(config ProjectCommandConfig) (*ProjectCommands, error) {
	if config.Reader == nil || config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ProjectCommands{
		reader: config.Reader, authorizer: config.Authorizer, transactions: config.Transactions,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

func (s *ProjectCommands) CreateProject(ctx context.Context, actor identitydomain.Actor, input CreateProjectInput) (releasedomain.Project, error) {
	if s == nil {
		return releasedomain.Project{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.Project{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeProjectWrite, ScopeOnly: true}); err != nil {
		return releasedomain.Project{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.Name = strings.TrimSpace(input.Name)
	if input.ProductID == "" || input.Name == "" {
		return releasedomain.Project{}, ErrValidation
	}
	product, err := s.reader.ReadProductCoordinates(ctx, actor.TenantID, input.ProductID)
	if err != nil {
		return releasedomain.Project{}, err
	}
	if product.TenantID != actor.TenantID || product.ID != input.ProductID {
		return releasedomain.Project{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: ScopeProjectWrite, Resources: application.ResourceReferences{ProductID: product.ID},
	}); err != nil {
		return releasedomain.Project{}, err
	}
	project := releasedomain.Project{ID: s.ids.NewID("proj"), TenantID: actor.TenantID, ProductID: product.ID, Name: input.Name, CreatedAt: s.clock.Now().UTC()}
	err = s.transactions.ExecuteProject(ctx, func(ctx context.Context, tx ProjectTransaction) error {
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
		if err := tx.InsertProject(ctx, project); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, auditEventFor(s.ids, actor, project.CreatedAt, "project.created", "project", project.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Project{}, err
	}
	return project, nil
}

type releaseProjectTransactions struct{ runner TransactionRunner }

func (r releaseProjectTransactions) ExecuteProject(ctx context.Context, command func(context.Context, ProjectTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, releaseProjectTransaction{tx: tx})
	})
}

type releaseProjectTransaction struct{ tx Transaction }

func (t releaseProjectTransaction) ReadProductCoordinates(ctx context.Context, tenantID, id string) (ProductCoordinates, error) {
	return legacyProductCoordinates{source: t.tx.Catalog()}.ReadProductCoordinates(ctx, tenantID, id)
}

func (t releaseProjectTransaction) InsertProject(ctx context.Context, project releasedomain.Project) error {
	return t.tx.Catalog().InsertProject(ctx, project)
}

func (t releaseProjectTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
