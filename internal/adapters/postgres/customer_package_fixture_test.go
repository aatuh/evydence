package postgres

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type postgresCustomerFixture struct{ store *Store }
type postgresCustomerFixtureGuard interface {
	LockCustomerPackageCreationScope(context.Context, string, string, string) error
	GetCustomerPackageRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
}
type postgresCustomerFixtureTransaction struct {
	packages app.PackageRepository
	guard    postgresCustomerFixtureGuard
	audit    app.AuditRepository
}
type postgresCustomerFixtureHasher struct{}

func (postgresCustomerFixtureHasher) Hash(v any) (string, error) {
	return application.NormalizedJSONHash(v)
}
func (postgresCustomerFixtureHasher) HashPackageManifest(ctx context.Context, v map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(v)
}

func newCustomerPackageFixture(store *Store) (*packageapp.CustomerPackageCommands, error) {
	reader, err := NewCustomerPackageCreationSnapshotReader(store, postgresCustomerFixtureHasher{}, localed25519.PayloadVerifier{})
	if err != nil {
		return nil, err
	}
	return packageapp.NewCustomerPackageCommands(packageapp.CustomerPackageCommandConfig{Reader: reader, Transactions: postgresCustomerFixture{store}, Authorizer: packagequery.NewCustomerPackageCreationAuthorizer(), Hasher: postgresCustomerFixtureHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}
func (f postgresCustomerFixture) ExecuteCustomerPackageCreation(ctx context.Context, run func(context.Context, packageapp.CustomerPackageCreationTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		guard, ok := r.Packages.(postgresCustomerFixtureGuard)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, postgresCustomerFixtureTransaction{r.Packages, guard, r.Audit})
	})
}
func (t postgresCustomerFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	if err := packagequery.NewCustomerPackageCreationAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return t.guard.LockCustomerPackageCreationScope(ctx, a.TenantID, r.Resources.ProductID, r.Resources.ReleaseID)
}
func (t postgresCustomerFixtureTransaction) GetRedactionProfile(ctx context.Context, tenant, id string) (packagedomain.RedactionProfile, error) {
	return t.guard.GetCustomerPackageRedactionProfile(ctx, tenant, id)
}
func (t postgresCustomerFixtureTransaction) InsertCustomerSecurityPackage(ctx context.Context, v packagedomain.CustomerSecurityPackage) error {
	return t.packages.InsertCustomerSecurityPackage(ctx, domain.CustomerSecurityPackage(v))
}
func (t postgresCustomerFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := t.audit.Append(ctx, domain.AuditChainEntry{ID: e.ID, TenantID: e.TenantID, EntryType: e.EntryType, SubjectType: e.SubjectType, SubjectID: e.SubjectID, ActorType: e.ActorType, ActorID: e.ActorID, OccurredAt: e.OccurredAt, PayloadHash: e.PayloadHash, SignatureRef: e.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	if err != nil {
		return application.AuditReceipt{}, err
	}
	return application.AuditReceipt{ID: v.ID}, nil
}
