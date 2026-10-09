package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type ingestionDiffFixture struct {
	catalogFixtureCommands
	clock application.Clock
}

// Actual focused diff services over current repository capabilities, not a
// Ledger command facade. Read-only preflight cannot transfer parsed documents.
type diffNativeFixture struct {
	evidenceCreationNativeFixture
}

func (f diffNativeFixture) authorizer() (application.Authorizer, error) {
	artifacts, err := releasequery.NewArtifactReadAuthorizer(f)
	if err != nil {
		return nil, err
	}
	return evidencequery.NewDiffAuthorizer(artifacts)
}
func (f diffNativeFixture) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	auth, err := f.authorizer()
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, a, r)
}
func (f diffNativeFixture) ExecuteSBOMDiff(ctx context.Context, run func(context.Context, evidenceapp.SBOMDiffTransaction) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	return fixtureIngestionError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if _, ok := r.Evidence.(evidenceapp.SBOMDiffReader); !ok || r.Risk == nil || r.Audit == nil {
			return app.ErrValidation
		}
		if _, ok := r.ReleaseCatalog.(repositoryIngestionFixtureArtifactReader); !ok {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	}))
}
func (f diffNativeFixture) ExecuteContractDiff(ctx context.Context, run func(context.Context, evidenceapp.ContractDiffTransaction) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	return fixtureIngestionError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if _, ok := r.Evidence.(evidenceapp.ContractDiffReader); !ok || r.Risk == nil || r.Audit == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	}))
}
func (f diffNativeFixture) ReadSBOMDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.SBOMDiffSubject, error) {
	var out evidenceapp.SBOMDiffSubject
	err := f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidenceapp.SBOMDiffReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadSBOMDiffSubject(ctx, tenant, id)
		return err
	})
	if err != nil {
		return evidenceapp.SBOMDiffSubject{}, fixtureIngestionError(err)
	}
	return out, nil
}
func (f diffNativeFixture) ReadSBOMDiffComponents(ctx context.Context, tenant, id string) ([]evidencedomain.SBOMComponent, error) {
	if f.readOnly {
		panic("diff preflight read SBOM components")
	}
	var out []evidencedomain.SBOMComponent
	err := f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidenceapp.SBOMDiffReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadSBOMDiffComponents(ctx, tenant, id)
		return err
	})
	if err != nil {
		return nil, fixtureIngestionError(err)
	}
	return out, nil
}
func (f diffNativeFixture) ReadContractDiffSubject(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffSubject, error) {
	var out evidenceapp.ContractDiffSubject
	err := f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidenceapp.ContractDiffReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadContractDiffSubject(ctx, tenant, id)
		return err
	})
	if err != nil {
		return evidenceapp.ContractDiffSubject{}, fixtureIngestionError(err)
	}
	return out, nil
}
func (f diffNativeFixture) ReadContractDiffRelease(ctx context.Context, tenant, id string) (evidenceapp.ContractDiffRelease, error) {
	var out evidenceapp.ContractDiffRelease
	err := f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidenceapp.ContractDiffReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadContractDiffRelease(ctx, tenant, id)
		return err
	})
	if err != nil {
		return evidenceapp.ContractDiffRelease{}, fixtureIngestionError(err)
	}
	return out, nil
}
func (f diffNativeFixture) ReadContractDiffProjection(ctx context.Context, tenant, id string) (evidencedomain.OpenAPIContract, error) {
	if f.readOnly {
		panic("diff preflight read contract operations")
	}
	var out evidencedomain.OpenAPIContract
	err := f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidenceapp.ContractDiffReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadContractDiffProjection(ctx, tenant, id)
		return err
	})
	if err != nil {
		return evidencedomain.OpenAPIContract{}, fixtureIngestionError(err)
	}
	return out, nil
}
func (f diffNativeFixture) InsertSBOMDiff(ctx context.Context, v evidencedomain.SBOMDiff) error {
	if f.readOnly || f.repositories == nil {
		panic("diff preflight/unbound SBOM insert")
	}
	return fixtureIngestionError(f.repositories.Risk.InsertSBOMDiff(ctx, domain.SBOMDiffFromContext(v)))
}
func (f diffNativeFixture) InsertContractDiff(ctx context.Context, v evidencedomain.ContractDiff) error {
	if f.readOnly || f.repositories == nil {
		panic("diff preflight/unbound contract insert")
	}
	return fixtureIngestionError(f.repositories.Risk.InsertContractDiff(ctx, domain.ContractDiffFromContext(v)))
}
func (f ingestionDiffFixture) ports(readOnly bool) (diffNativeFixture, application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return diffNativeFixture{evidenceCreationNativeFixture{catalogFixtureCommands: f.catalogFixtureCommands, readOnly: readOnly}}, clock, ids
}
func (f ingestionDiffFixture) nativeSBOM(readOnly bool) (*evidenceapp.SBOMDiffCommands, error) {
	ports, clock, ids := f.ports(readOnly)
	auth, err := ports.authorizer()
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewSBOMDiffCommands(evidenceapp.SBOMDiffCommandConfig{Authorizer: auth, Transactions: ports, Clock: clock, IDs: ids})
}
func (f ingestionDiffFixture) nativeContract(readOnly bool) (*evidenceapp.ContractDiffCommands, error) {
	ports, clock, ids := f.ports(readOnly)
	auth, err := ports.authorizer()
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewContractDiffCommands(evidenceapp.ContractDiffCommandConfig{Authorizer: auth, Transactions: ports, Clock: clock, IDs: ids})
}
func (f ingestionDiffFixture) AuthorizeCreateSBOMDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateSBOMDiffInput) error {
	c, err := f.nativeSBOM(true)
	if err != nil {
		return err
	}
	return fixtureIngestionError(c.AuthorizeCreateSBOMDiff(ctx, a, in))
}
func (f ingestionDiffFixture) AuthorizeCreateContractDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateContractDiffInput) error {
	c, err := f.nativeContract(true)
	if err != nil {
		return err
	}
	return fixtureIngestionError(c.AuthorizeCreateContractDiff(ctx, a, in))
}
func (f ingestionDiffFixture) CreateSBOMDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateSBOMDiffInput) (evidencedomain.SBOMDiff, error) {
	c, err := f.nativeSBOM(false)
	if err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	v, err := c.CreateSBOMDiff(ctx, a, in)
	return v, mapEvidenceCreationCommandError(fixtureIngestionError(err))
}
func (f ingestionDiffFixture) CreateContractDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateContractDiffInput) (evidencedomain.ContractDiff, error) {
	c, err := f.nativeContract(false)
	if err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	v, err := c.CreateContractDiff(ctx, a, in)
	return v, mapEvidenceCreationCommandError(fixtureIngestionError(err))
}
func (s *Server) bindDiffFixturePorts(ledger *app.Ledger) {
	commands := ingestionDiffFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, ok := s.sbomDiffCommands.(ingestionDiffFixture); ok {
		old.ledger = ledger
		s.sbomDiffCommands = old
	} else if s.sbomDiffCommands == nil {
		s.sbomDiffCommands = commands
	}
	if old, ok := s.contractDiffCommands.(ingestionDiffFixture); ok {
		old.ledger = ledger
		s.contractDiffCommands = old
	} else if s.contractDiffCommands == nil {
		s.contractDiffCommands = commands
	}
}

var (
	_ SBOMDiffCommands     = ingestionDiffFixture{}
	_ ContractDiffCommands = ingestionDiffFixture{}
)
