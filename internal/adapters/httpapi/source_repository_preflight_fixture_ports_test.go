package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type sourceRepositoryPreflightFixture struct {
	catalogFixtureCommands
	readOnly bool
}
type sourceRepositoryPreflightTransaction struct {
	reader   integrationapp.SourceRepositoryCreationReader
	repos    app.Repositories
	readOnly bool
}

func (f sourceRepositoryPreflightFixture) ExecuteSourceRepository(ctx context.Context, run func(context.Context, integrationapp.SourceRepositoryCreationTransaction) error) error {
	if ctx == nil || run == nil {
		return integrationapp.ErrValidation
	}
	return collectorReleaseFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Source.(integrationapp.SourceRepositoryCreationReader)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, sourceRepositoryPreflightTransaction{reader, r, f.readOnly})
	}))
}
func (t sourceRepositoryPreflightTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (t sourceRepositoryPreflightTransaction) LockRepositoryCreation(ctx context.Context, tenant string) error {
	return collectorReleaseFixtureCoreError(t.reader.LockRepositoryCreation(ctx, tenant))
}
func (t sourceRepositoryPreflightTransaction) LockRepositoryProject(ctx context.Context, tenant, id string) (integrationapp.SourceProjectIdentity, error) {
	v, err := t.reader.LockRepositoryProject(ctx, tenant, id)
	return v, collectorReleaseFixtureCoreError(err)
}
func (t sourceRepositoryPreflightTransaction) RepositoryIdentityByName(ctx context.Context, tenant, provider, name string) (integrationapp.SourceRepositoryIdentity, bool, error) {
	v, found, err := t.reader.RepositoryIdentityByName(ctx, tenant, provider, name)
	return v, found, collectorReleaseFixtureCoreError(err)
}
func (t sourceRepositoryPreflightTransaction) ReadSourceRepository(ctx context.Context, tenant, id string) (integrationdomain.SourceRepository, error) {
	if t.readOnly {
		panic("repository preflight read descriptive metadata")
	}
	v, err := t.reader.ReadSourceRepository(ctx, tenant, id)
	return v, collectorReleaseFixtureCoreError(err)
}
func (t sourceRepositoryPreflightTransaction) InsertSourceRepository(ctx context.Context, v integrationdomain.SourceRepository) error {
	if t.readOnly {
		panic("repository preflight inserted repository")
	}
	return collectorReleaseFixtureCoreError(t.repos.Source.InsertSourceRepository(ctx, domain.SourceRepository(v)))
}
func (t sourceRepositoryPreflightTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("repository preflight appended audit")
	}
	v, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
	return v, collectorReleaseFixtureCoreError(err)
}

func (f integrationFixtureCommands) nativeSourceRepository(readOnly bool) (*integrationapp.SourceRepositoryCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return integrationapp.NewSourceRepositoryCommands(integrationapp.SourceRepositoryCreationConfig{Transactions: sourceRepositoryPreflightFixture{f.catalogFixtureCommands, readOnly}, Authorizer: integrationquery.NewSourceWriteAuthorizer(), Clock: clock, IDs: ids})
}

var _ integrationapp.SourceRepositoryCreationTransaction = sourceRepositoryPreflightTransaction{}
