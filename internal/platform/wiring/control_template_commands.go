package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func BuildControlTemplateCommands(factory app.UnitOfWorkFactory) (*riskapp.ControlTemplateCommands, error) {
	if factory == nil {
		return nil, errors.New("control template transactions are required")
	}
	return riskapp.NewControlTemplateCommands(riskapp.ControlTemplateCommandConfig{Authorizer: riskapp.NewControlAdminAuthorizer(), Transactions: controlTemplateTransactions{factory}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type controlTemplateTransactions struct{ factory app.UnitOfWorkFactory }

func (t controlTemplateTransactions) ExecuteControlTemplate(ctx context.Context, command func(context.Context, riskapp.ControlTemplateTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		versions, ok := repos.Controls.(riskapp.FrameworkVersionReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, controlTemplateTransaction{versions: versions, writer: repos.Controls, audit: repos.Audit})
	}))
}

type controlTemplateTransaction struct {
	versions riskapp.FrameworkVersionReader
	writer   app.ControlRepository
	audit    app.AuditRepository
}

func (t controlTemplateTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return riskapp.NewControlAdminAuthorizer().Authorize(ctx, actor, request)
}
func (t controlTemplateTransaction) FrameworkVersionExists(ctx context.Context, tenant, slug, version string) (bool, error) {
	v, err := t.versions.FrameworkVersionExists(ctx, tenant, slug, version)
	return v, mapControlWriteError(err)
}
func (t controlTemplateTransaction) InsertControlFramework(ctx context.Context, v riskdomain.ControlFramework) error {
	return (controlTransaction{writer: t.writer}).InsertControlFramework(ctx, v)
}
func (t controlTemplateTransaction) InsertSecurityControl(ctx context.Context, v riskdomain.SecurityControl) error {
	return (controlTransaction{writer: t.writer}).InsertSecurityControl(ctx, v)
}
func (t controlTemplateTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return (controlTransaction{audit: t.audit}).AppendAudit(ctx, v)
}
