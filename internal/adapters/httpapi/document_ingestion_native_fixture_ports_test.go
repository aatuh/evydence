package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

// Typed test composition uses real focused services, parsers and repository
// ports. It never recovers object storage, clocks or parser policy from Ledger.
type documentIngestionNativeFixture struct {
	evidenceCreationNativeFixture
	objects app.ObjectStore
	clock   application.Clock
}

func (f documentIngestionNativeFixture) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	if digest == "" {
		return f.ValidateArtifactIdentity(ctx, tenant, id)
	}
	return f.evidenceCreationNativeFixture.ValidateArtifactReference(ctx, tenant, id, digest)
}
func (f documentIngestionNativeFixture) ExecuteSBOMIngestion(ctx context.Context, run func(context.Context, evidenceapp.SBOMIngestionTransaction) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	return fixtureIngestionError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.Evidence == nil || r.Audit == nil || r.Outbox == nil || r.Payloads == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	}))
}
func (f documentIngestionNativeFixture) ExecuteOpenAPIIngestion(ctx context.Context, run func(context.Context, evidenceapp.OpenAPIIngestionTransaction) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	return fixtureIngestionError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.Evidence == nil || r.Audit == nil || r.Outbox == nil || r.Payloads == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	}))
}
func (f documentIngestionNativeFixture) InsertSBOM(ctx context.Context, v evidencedomain.SBOM) error {
	if f.readOnly || f.repositories == nil {
		panic("document preflight/unbound SBOM insert")
	}
	return fixtureIngestionError(f.repositories.Evidence.InsertSBOM(ctx, domain.SBOMFromContext(v)))
}
func (f documentIngestionNativeFixture) InsertOpenAPIContract(ctx context.Context, v evidencedomain.OpenAPIContract) error {
	if f.readOnly || f.repositories == nil {
		panic("document preflight/unbound OpenAPI insert")
	}
	return fixtureIngestionError(f.repositories.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContractFromContext(v)))
}
func (f documentIngestionNativeFixture) ParseSBOM(ctx context.Context, format string, source evidenceapp.PayloadSource) (evidenceapp.ParsedSBOM, error) {
	if f.readOnly {
		panic("document preflight parsed SBOM")
	}
	return (app.SBOMPayloadParser{}).ParseSBOM(ctx, format, source)
}
func (f documentIngestionNativeFixture) ParseOpenAPIContract(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedOpenAPIContract, error) {
	if f.readOnly {
		panic("document preflight parsed OpenAPI")
	}
	return (app.OpenAPIContractPayloadParser{}).ParseOpenAPIContract(ctx, source)
}

func (f documentIngestionNativeFixture) ExecuteVulnerabilityScanIngestion(ctx context.Context, run func(context.Context, evidenceapp.VulnerabilityScanIngestionTransaction) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	return fixtureIngestionError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.Evidence == nil || r.Audit == nil || r.Outbox == nil || r.Payloads == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	}))
}
func (f documentIngestionNativeFixture) InsertVulnerabilityScan(ctx context.Context, v evidencedomain.VulnerabilityScan) error {
	if f.readOnly || f.repositories == nil {
		panic("document preflight/unbound scan insert")
	}
	return fixtureIngestionError(f.repositories.Evidence.InsertVulnerabilityScan(ctx, domain.VulnerabilityScanFromContext(v)))
}
func (f documentIngestionNativeFixture) ProbeVulnerabilityScanScope(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.VulnerabilityScanScope, error) {
	// This bounded coordinate-only parser is allowed during transport probing;
	// full normalization remains behind current ownership and grant checks.
	return (app.VulnerabilityScanPayloadParser{}).ProbeVulnerabilityScanScope(ctx, source)
}
func (f documentIngestionNativeFixture) ParseVulnerabilityScan(ctx context.Context, source evidenceapp.PayloadSource) (evidenceapp.ParsedVulnerabilityScan, error) {
	if f.readOnly {
		panic("document preflight parsed scan findings")
	}
	return (app.VulnerabilityScanPayloadParser{}).ParseVulnerabilityScan(ctx, source)
}
func (f documentIngestionNativeFixture) StagePayloadSource(ctx context.Context, tenant, media string, source evidenceapp.PayloadSource) (evidenceapp.StagedPayload, error) {
	if f.readOnly {
		panic("document preflight staged source")
	}
	if ctx == nil {
		return evidenceapp.StagedPayload{}, evidenceapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidenceapp.StagedPayload{}, err
	}
	if f.objects == nil {
		return evidenceapp.StagedPayload{}, nil
	}
	objects, ok := f.objects.(app.PayloadObjectStore)
	if !ok {
		return evidenceapp.StagedPayload{}, evidenceapp.ErrConflict
	}
	p, err := app.StageObjectPayload(ctx, objects, tenant, media, fixtureLegacySource(source), f.clock.Now())
	if err != nil {
		return evidenceapp.StagedPayload{}, fixtureIngestionError(err)
	}
	return evidenceapp.StagedPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: string(p.Status), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}, nil
}
func (f ingestionFixtureCommands) documentPorts(readOnly bool) (documentIngestionNativeFixture, application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly {
		clock = application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
		if f.clock != nil {
			clock = f.clock
		}
	}
	return documentIngestionNativeFixture{evidenceCreationNativeFixture: evidenceCreationNativeFixture{catalogFixtureCommands: f.catalogFixtureCommands, readOnly: readOnly}, objects: f.objects, clock: clock}, clock, ids
}
func (f ingestionFixtureCommands) nativeSBOMIngestion(readOnly bool) (*evidenceapp.SBOMIngestionCommands, error) {
	ports, clock, ids := f.documentPorts(readOnly)
	auth, err := ports.authorizer()
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewSBOMIngestionCommands(evidenceapp.SBOMIngestionCommandConfig{Authorizer: auth, Transactions: ports, Parser: ports, Objects: ports, Payloads: ports, Canonicalizer: ports, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: ids, WorkerOwnedParsers: f.workerOwnedParsers})
}
func (f ingestionFixtureCommands) nativeOpenAPIIngestion(readOnly bool) (*evidenceapp.OpenAPIIngestionCommands, error) {
	ports, clock, ids := f.documentPorts(readOnly)
	auth, err := ports.authorizer()
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewOpenAPIIngestionCommands(evidenceapp.OpenAPIIngestionCommandConfig{Authorizer: auth, Transactions: ports, Parser: ports, Objects: ports, Payloads: ports, Canonicalizer: ports, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: ids, WorkerOwnedParsers: f.workerOwnedParsers})
}

func (f ingestionFixtureCommands) nativeScanIngestion(readOnly bool) (*evidenceapp.VulnerabilityScanIngestionCommands, error) {
	ports, clock, ids := f.documentPorts(readOnly)
	auth, err := ports.authorizer()
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewVulnerabilityScanIngestionCommands(evidenceapp.VulnerabilityScanIngestionCommandConfig{Authorizer: auth, Transactions: ports, Parser: ports, Objects: ports, Payloads: ports, Canonicalizer: ports, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: ids, WorkerOwnedParsers: f.workerOwnedParsers})
}

func uploadVulnerabilityScanFixture(ctx context.Context, ledger *app.Ledger, a domain.Actor, raw []byte) (domain.VulnerabilityScan, error) {
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	source := evidenceapp.BytesPayloadSource(raw)
	in, err := f.ProbeVulnerabilityScanScope(ctx, a, source)
	if err != nil {
		return domain.VulnerabilityScan{}, mapEvidenceCreationCommandError(err)
	}
	v, err := f.UploadVulnerabilityScanPayload(ctx, a, in, source)
	return domain.VulnerabilityScanFromContext(v), err
}

func uploadSBOMFixture(ctx context.Context, ledger *app.Ledger, a domain.Actor, release, artifact string, raw []byte) (domain.SBOM, error) {
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	v, err := f.UploadSBOMPayload(ctx, a, evidenceapp.SBOMIngestionInput{ReleaseID: release, ArtifactID: artifact, Format: "cyclonedx"}, evidenceapp.BytesPayloadSource(raw))
	return domain.SBOMFromContext(v), err
}
func uploadOpenAPIContractFixture(ctx context.Context, ledger *app.Ledger, a domain.Actor, product, release, version string, raw []byte) (domain.OpenAPIContract, error) {
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	v, err := f.UploadOpenAPIContractPayload(ctx, a, evidenceapp.OpenAPIIngestionInput{ProductID: product, ReleaseID: release, Version: version}, evidenceapp.BytesPayloadSource(raw))
	return domain.OpenAPIContractFromContext(v), err
}
func (s *Server) bindDocumentIngestionFixtureResources(objects app.ObjectStore, clock application.Clock, workerOwned bool) {
	if f, ok := s.sbomIngestionCommands.(ingestionFixtureCommands); ok {
		f.objects, f.clock, f.workerOwnedParsers = objects, clock, workerOwned
		s.sbomIngestionCommands = f
	}
	if f, ok := s.openAPIIngestionCommands.(ingestionFixtureCommands); ok {
		f.objects, f.clock, f.workerOwnedParsers = objects, clock, workerOwned
		s.openAPIIngestionCommands = f
	}
	if f, ok := s.scanIngestionCommands.(ingestionFixtureCommands); ok {
		f.objects, f.clock, f.workerOwnedParsers = objects, clock, workerOwned
		s.scanIngestionCommands = f
	}
}
