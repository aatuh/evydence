package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

// Run the actual native collector preflight, using owned fixture lookups only.
// LockCollectorWrites checks the bootstrapped fixture tenant, not SQL locking.
// No credential, clock, ID, uniqueness-write or audit capability may run here.
type collectorFixtureGuard struct{ catalogFixtureCommands }

func (f collectorFixtureGuard) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return integrationapp.NewCollectorWriteAuthorizer().Authorize(ctx, a, r)
}
func (f collectorFixtureGuard) LockCollectorWrites(ctx context.Context, tenant string) error {
	// Historical fixture tenants are created by BootstrapTenant, which creates
	// at least one key. The inventory includes revoked keys; this does not grant
	// the caller access to their metadata or to another tenant.
	keys, err := f.commandLedger(ctx).ListAPIKeys(ctx, domain.Actor{TenantID: tenant, KeyID: "fixture-owner-reader", Scopes: []string{"*"}})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return integrationapp.ErrNotFound
	}
	return nil
}
func (f collectorFixtureGuard) ReadCollectorReleaseReference(ctx context.Context, tenant, kind, id string) (integrationapp.CollectorReference, error) {
	reader := domain.Actor{TenantID: tenant, KeyID: "fixture-owner-reader", Scopes: []string{"*"}}
	ledger := f.commandLedger(ctx)
	result := integrationapp.CollectorReference{ID: id, TenantID: tenant, Type: kind}
	switch kind {
	case "collector":
		values, err := ledger.ListCollectors(ctx, reader)
		if err != nil {
			return result, err
		}
		for _, value := range values {
			if value.ID == id && value.TenantID == tenant {
				return result, nil
			}
		}
		return result, integrationapp.ErrNotFound
	case "signature":
		value, err := ledger.GetArtifactSignature(ctx, reader, id)
		result.ID, result.TenantID, result.Digest = value.ID, value.TenantID, value.SubjectDigest
		return result, err
	case "sbom":
		value, err := ledger.GetSBOM(ctx, reader, id)
		result.ID, result.TenantID = value.ID, value.TenantID
		return result, err
	case "scan":
		value, err := ledger.GetVulnerabilityScan(ctx, reader, id)
		result.ID, result.TenantID = value.ID, value.TenantID
		return result, err
	default:
		return result, integrationapp.ErrValidation
	}
}
func (collectorFixtureGuard) CollectorNameExists(context.Context, string, string) (bool, error) {
	panic("collector replay guard queried creation uniqueness")
}
func (collectorFixtureGuard) CommercialCollectorIdentityExists(context.Context, string, string, string, string) (bool, error) {
	panic("collector replay guard queried commercial uniqueness")
}
func (collectorFixtureGuard) InsertCollectorAPIKey(context.Context, identitydomain.APIKey) error {
	panic("collector replay guard inserted key")
}
func (collectorFixtureGuard) InsertCollector(context.Context, integrationdomain.Collector) error {
	panic("collector replay guard inserted collector")
}
func (collectorFixtureGuard) InsertCollectorRelease(context.Context, integrationdomain.CollectorRelease) error {
	panic("collector replay guard inserted release")
}
func (collectorFixtureGuard) InsertCommercialCollectorDefinition(context.Context, integrationdomain.CommercialCollectorDefinition) error {
	panic("collector replay guard inserted definition")
}
func (collectorFixtureGuard) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("collector replay guard appended audit")
}
func (collectorFixtureGuard) GenerateCollectorCredential(context.Context) (integrationapp.CollectorCredential, error) {
	panic("collector replay guard generated credentials")
}
func (f collectorFixtureGuard) ExecuteCollector(ctx context.Context, run func(context.Context, integrationapp.CollectorTransaction) error) error {
	return run(ctx, f)
}
func (f integrationFixtureCommands) collectorGuard() (*integrationapp.CollectorCommands, error) {
	guard := collectorFixtureGuard(f)
	return integrationapp.NewCollectorCommands(integrationapp.CollectorCommandConfig{Authorizer: integrationapp.NewCollectorWriteAuthorizer(), Transactions: guard, Credentials: guard, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
}
func (f integrationFixtureCommands) AuthorizeCreateCollector(ctx context.Context, a domain.Actor, in integrationapp.CreateCollectorInput) error {
	guard, err := f.collectorGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateCollector(ctx, a, in)
}
func (f integrationFixtureCommands) AuthorizeRecordCollectorRelease(ctx context.Context, a domain.Actor, in integrationapp.RecordCollectorReleaseInput) error {
	guard, err := f.collectorGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeRecordCollectorRelease(ctx, a, in)
}
func (f integrationFixtureCommands) AuthorizeCreateCommercialCollectorDefinition(ctx context.Context, a domain.Actor, in integrationapp.CreateCommercialCollectorInput) error {
	guard, err := f.collectorGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateCommercialCollectorDefinition(ctx, a, in)
}

var _ integrationapp.CollectorTransaction = collectorFixtureGuard{}
var _ integrationapp.CollectorTransactions = collectorFixtureGuard{}
var _ integrationapp.CollectorCredentials = collectorFixtureGuard{}
