package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type ingestionDiffFixture struct{ catalogFixtureCommands }
type ingestionDiffFixtureRunner struct{ ingestionFixtureAuthority }
type ingestionDiffFixtureGuard struct {
	ingestionFixtureGuardTransaction
}

func (f ingestionFixtureAuthority) diffSource(ctx context.Context, tenant, id, kind, product, release string) (application.ResourceReferences, error) {
	value, err := (evidenceReadFixture{catalogFixtureCommands{ledger: f.commandLedger(ctx)}}).GetEvidence(ctx, fixtureOwnerReader(tenant), id)
	if err != nil {
		return application.ResourceReferences{}, err
	}
	if value.Type != kind || value.TenantID != tenant || value.ProductID != "" && product != "" && value.ProductID != product || value.ReleaseID != "" && release != "" && value.ReleaseID != release {
		return application.ResourceReferences{}, app.ErrNotFound
	}
	if product == "" {
		product = value.ProductID
	}
	if release == "" {
		release = value.ReleaseID
	}
	return f.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{ProductID: product, ProjectID: value.ProjectID, ReleaseID: release})
}

func (f ingestionDiffFixtureGuard) ReadSBOMDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.SBOMDiffSubject, error) {
	value, err := (evidenceReadFixture{catalogFixtureCommands{ledger: f.commandLedger(ctx)}}).GetSBOM(ctx, fixtureOwnerReader(tenant), id)
	if err != nil {
		return evidenceapp.SBOMDiffSubject{}, err
	}
	refs, err := f.diffSource(ctx, tenant, value.EvidenceID, "sbom", "", value.ReleaseID)
	if err != nil {
		return evidenceapp.SBOMDiffSubject{}, err
	}
	if value.ArtifactID != "" {
		if err := f.ValidateArtifactReference(ctx, tenant, value.ArtifactID, ""); err != nil {
			return evidenceapp.SBOMDiffSubject{}, err
		}
		refs.ArtifactID = value.ArtifactID
	}
	return evidenceapp.SBOMDiffSubject{ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, Resources: refs}, nil
}
func (f ingestionDiffFixtureGuard) ReadSBOMDiffComponents(ctx context.Context, tenant, id string) ([]evidencedomain.SBOMComponent, error) {
	value, err := (evidenceReadFixture{catalogFixtureCommands{ledger: f.commandLedger(ctx)}}).GetSBOM(ctx, fixtureOwnerReader(tenant), id)
	return value.Components, err
}
func (f ingestionDiffFixtureGuard) ReadContractDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffSubject, error) {
	value, err := (evidenceReadFixture{catalogFixtureCommands{ledger: f.commandLedger(ctx)}}).GetOpenAPIContract(ctx, fixtureOwnerReader(tenant), id)
	if err != nil {
		return evidenceapp.ContractDiffSubject{}, err
	}
	refs, err := f.diffSource(ctx, tenant, value.EvidenceID, "openapi_contract", value.ProductID, value.ReleaseID)
	if err != nil {
		return evidenceapp.ContractDiffSubject{}, err
	}
	return evidenceapp.ContractDiffSubject{ID: value.ID, TenantID: value.TenantID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, EvidenceID: value.EvidenceID}, nil
}
func (f ingestionDiffFixtureGuard) ReadContractDiffRelease(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffRelease, error) {
	refs, err := f.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{ReleaseID: id})
	return evidenceapp.ContractDiffRelease{ID: refs.ReleaseID, TenantID: tenant, ProductID: refs.ProductID}, err
}
func (f ingestionDiffFixtureGuard) ReadContractDiffProjection(ctx context.Context, tenant, id string) (evidencedomain.OpenAPIContract, error) {
	return (evidenceReadFixture{catalogFixtureCommands{ledger: f.commandLedger(ctx)}}).GetOpenAPIContract(ctx, fixtureOwnerReader(tenant), id)
}

func (f ingestionDiffFixtureRunner) transaction() (ingestionDiffFixtureGuard, error) {
	artifacts, err := releasequery.NewArtifactReadAuthorizer(f.ingestionFixtureAuthority)
	if err != nil {
		return ingestionDiffFixtureGuard{}, err
	}
	auth, err := evidencequery.NewDiffAuthorizer(artifacts)
	return ingestionDiffFixtureGuard{ingestionFixtureGuardTransaction{ingestionFixtureAuthority: f.ingestionFixtureAuthority, Authorizer: auth}}, err
}
func (f ingestionDiffFixtureRunner) ExecuteSBOMDiff(ctx context.Context, run func(context.Context, evidenceapp.SBOMDiffTransaction) error) error {
	tx, err := f.transaction()
	if err != nil {
		return err
	}
	return run(ctx, tx)
}
func (f ingestionDiffFixtureRunner) ExecuteContractDiff(ctx context.Context, run func(context.Context, evidenceapp.ContractDiffTransaction) error) error {
	tx, err := f.transaction()
	if err != nil {
		return err
	}
	return run(ctx, tx)
}
func (f ingestionDiffFixture) AuthorizeCreateSBOMDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateSBOMDiffInput) error {
	runner := ingestionDiffFixtureRunner{ingestionFixtureAuthority(f)}
	tx, err := runner.transaction()
	if err != nil {
		return err
	}
	guard, err := evidenceapp.NewSBOMDiffCommands(evidenceapp.SBOMDiffCommandConfig{Authorizer: tx.Authorizer, Transactions: runner, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeCreateSBOMDiff(ctx, a, in))
}
func (f ingestionDiffFixture) AuthorizeCreateContractDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateContractDiffInput) error {
	runner := ingestionDiffFixtureRunner{ingestionFixtureAuthority(f)}
	tx, err := runner.transaction()
	if err != nil {
		return err
	}
	guard, err := evidenceapp.NewContractDiffCommands(evidenceapp.ContractDiffCommandConfig{Authorizer: tx.Authorizer, Transactions: runner, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeCreateContractDiff(ctx, a, in))
}

func fixtureSBOMDiff(value domain.SBOMDiff) evidencedomain.SBOMDiff {
	components := func(values []domain.SBOMComponent) []evidencedomain.SBOMComponent {
		out := make([]evidencedomain.SBOMComponent, 0, len(values))
		for _, v := range values {
			out = append(out, evidencedomain.SBOMComponent(v))
		}
		return out
	}
	changes := make([]evidencedomain.DependencyChange, 0, len(value.DependencyChanges))
	for _, v := range value.DependencyChanges {
		changes = append(changes, evidencedomain.DependencyChange{ID: v.ID, TenantID: v.TenantID, SBOMDiffID: v.SBOMDiffID, ChangeType: v.ChangeType, Component: evidencedomain.SBOMComponent(v.Component), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
	}
	return evidencedomain.SBOMDiff{ID: value.ID, TenantID: value.TenantID, BaseSBOMID: value.BaseSBOMID, TargetSBOMID: value.TargetSBOMID, ReleaseID: value.ReleaseID, AddedComponents: components(value.AddedComponents), RemovedComponents: components(value.RemovedComponents), UnchangedCount: value.UnchangedCount, DependencyChanges: changes, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
func (f ingestionDiffFixture) CreateSBOMDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateSBOMDiffInput) (evidencedomain.SBOMDiff, error) {
	value, err := f.commandLedger(ctx).CreateSBOMDiff(ctx, a, app.CreateSBOMDiffInput(in))
	return fixtureSBOMDiff(value), err
}
func (f ingestionDiffFixture) CreateContractDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateContractDiffInput) (evidencedomain.ContractDiff, error) {
	value, err := f.commandLedger(ctx).CreateContractDiff(ctx, a, app.CreateContractDiffInput(in))
	model := evidencedomain.ContractDiff(value)
	model.BreakingChanges, model.NonBreakingChanges = slices.Clone(value.BreakingChanges), slices.Clone(value.NonBreakingChanges)
	return model, err
}
func (s *Server) bindDiffFixturePorts(ledger *app.Ledger) {
	commands := ingestionDiffFixture{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.sbomDiffCommands.(ingestionDiffFixture); s.sbomDiffCommands == nil || fixture {
		s.sbomDiffCommands = commands
	}
	if _, fixture := s.contractDiffCommands.(ingestionDiffFixture); s.contractDiffCommands == nil || fixture {
		s.contractDiffCommands = commands
	}
}

var (
	_ SBOMDiffCommands     = ingestionDiffFixture{}
	_ ContractDiffCommands = ingestionDiffFixture{}
)
