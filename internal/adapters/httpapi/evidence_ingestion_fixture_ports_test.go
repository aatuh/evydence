package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

// Only test binaries use these command adapters. Native guards run the actual
// algorithms and authorizers on current fixture parents. SBOM/SPDX, OpenAPI and
// security documents and scanner writes use focused native services; VEX writes
// still depend on historical parser commands and the isolated replay transaction.
type ingestionFixtureCommands struct {
	catalogFixtureCommands
	repositoryScope    bool
	objects            app.ObjectStore
	clock              application.Clock
	workerOwnedParsers bool
}

func (f ingestionFixtureCommands) authority() ingestionFixtureReadAuthority {
	legacy := ingestionFixtureAuthority{f.catalogFixtureCommands}
	if f.repositoryScope {
		return repositoryIngestionFixtureAuthority{ingestionFixtureAuthority: legacy}
	}
	return legacy
}

func (f ingestionFixtureCommands) sbomGuard() (*evidenceapp.SBOMIngestionCommands, error) {
	return f.nativeSBOMIngestion(true)
}
func (f ingestionFixtureCommands) vexGuard() (*evidenceapp.VEXIngestionCommands, error) {
	auth, err := f.authority().authorizer(false)
	if err != nil {
		return nil, err
	}
	noEffects := ingestionFixtureGuardEffects{}
	return evidenceapp.NewVEXIngestionCommands(evidenceapp.VEXIngestionCommandConfig{Authorizer: auth, Transactions: ingestionFixtureGuardRunner{f.authority(), false}, Parser: app.VEXPayloadParser{}, Objects: noEffects, Payloads: noEffects, Canonicalizer: noEffects, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
}
func (f ingestionFixtureCommands) openAPIGuard() (*evidenceapp.OpenAPIIngestionCommands, error) {
	return f.nativeOpenAPIIngestion(true)
}
func (f ingestionFixtureCommands) scanGuard() (*evidenceapp.VulnerabilityScanIngestionCommands, error) {
	return f.nativeScanIngestion(true)
}
func (f ingestionFixtureCommands) securityGuard() (*evidenceapp.SecurityDocumentCommands, error) {
	return f.nativeSecurityDocuments(true)
}

func (f ingestionFixtureCommands) AuthorizeUploadSBOM(ctx context.Context, a domain.Actor, in evidenceapp.SBOMIngestionInput) error {
	guard, err := f.sbomGuard()
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeUploadSBOM(ctx, a, in))
}
func (f ingestionFixtureCommands) AuthorizeUploadVEX(ctx context.Context, a domain.Actor, in evidenceapp.VEXIngestionInput) error {
	guard, err := f.vexGuard()
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeUploadVEX(ctx, a, in))
}
func (f ingestionFixtureCommands) AuthorizeUploadOpenAPIContract(ctx context.Context, a domain.Actor, in evidenceapp.OpenAPIIngestionInput) error {
	guard, err := f.openAPIGuard()
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeUploadOpenAPIContract(ctx, a, in))
}
func (f ingestionFixtureCommands) ProbeVulnerabilityScanScope(ctx context.Context, a domain.Actor, source evidenceapp.PayloadSource) (evidenceapp.VulnerabilityScanScope, error) {
	guard, err := f.scanGuard()
	if err != nil {
		return evidenceapp.VulnerabilityScanScope{}, err
	}
	in, err := guard.ProbeVulnerabilityScanScope(ctx, a, source)
	return in, fixtureIngestionError(err)
}
func (f ingestionFixtureCommands) AuthorizeUploadVulnerabilityScan(ctx context.Context, a domain.Actor, in evidenceapp.VulnerabilityScanScope) error {
	guard, err := f.scanGuard()
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeUploadVulnerabilityScan(ctx, a, in))
}
func (f ingestionFixtureCommands) AuthorizeUploadSecurityScan(ctx context.Context, a domain.Actor, in evidenceapp.UploadSecurityScanInput) error {
	guard, err := f.securityGuard()
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeUploadSecurityScan(ctx, a, in))
}
func (f ingestionFixtureCommands) AuthorizeUploadManualSecurityDocument(ctx context.Context, a domain.Actor, in evidenceapp.UploadManualSecurityDocumentInput) error {
	guard, err := f.securityGuard()
	if err != nil {
		return err
	}
	return fixtureIngestionError(guard.AuthorizeUploadManualSecurityDocument(ctx, a, in))
}

func fixtureLegacySource(source evidenceapp.PayloadSource) app.PayloadSource {
	return app.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open}
}
func (f ingestionFixtureCommands) UploadSBOMPayload(ctx context.Context, a domain.Actor, in evidenceapp.SBOMIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.SBOM, error) {
	c, err := f.nativeSBOMIngestion(false)
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	v, err := c.UploadSBOMPayload(ctx, a, in, source)
	return v, mapEvidenceCreationCommandError(fixtureIngestionError(err))
}
func readFixtureSource(ctx context.Context, source evidenceapp.PayloadSource) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source.Open == nil || !app.ValidPayloadSize(source.Size, app.EvidenceDocumentLimit) {
		return nil, app.ErrValidation
	}
	reader, err := source.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, app.EvidenceDocumentLimit+1))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if int64(len(raw)) != source.Size || "sha256:"+hex.EncodeToString(digest[:]) != source.Digest {
		return nil, app.ErrValidation
	}
	return raw, nil
}
func (f ingestionFixtureCommands) UploadVEXPayload(ctx context.Context, a domain.Actor, in evidenceapp.VEXIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.VEXDocument, error) {
	var value domain.VEXDocument
	var err error
	switch in.Format {
	case "openvex":
		value, err = f.commandLedger(ctx).UploadVEXPayload(ctx, a, in.ReleaseID, in.ArtifactID, fixtureLegacySource(source))
	case "cyclonedx":
		raw, readErr := readFixtureSource(ctx, source)
		if readErr != nil {
			return evidencedomain.VEXDocument{}, readErr
		}
		value, err = f.commandLedger(ctx).UploadCycloneDXVEX(ctx, a, in.ReleaseID, in.ArtifactID, raw)
	default:
		return evidencedomain.VEXDocument{}, app.ErrValidation
	}
	return fixtureVEXDocument(value), err
}
func (f ingestionFixtureCommands) UploadOpenAPIContractPayload(ctx context.Context, a domain.Actor, in evidenceapp.OpenAPIIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.OpenAPIContract, error) {
	c, err := f.nativeOpenAPIIngestion(false)
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	v, err := c.UploadOpenAPIContractPayload(ctx, a, in, source)
	return v, mapEvidenceCreationCommandError(fixtureIngestionError(err))
}
func (f ingestionFixtureCommands) UploadVulnerabilityScanPayload(ctx context.Context, a domain.Actor, in evidenceapp.VulnerabilityScanScope, source evidenceapp.PayloadSource) (evidencedomain.VulnerabilityScan, error) {
	c, err := f.nativeScanIngestion(false)
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	v, err := c.UploadVulnerabilityScanPayload(ctx, a, in, source)
	return v, mapEvidenceCreationCommandError(fixtureIngestionError(err))
}
func (f ingestionFixtureCommands) UploadSecurityScan(ctx context.Context, a domain.Actor, in evidenceapp.UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	c, err := f.nativeSecurityDocuments(false)
	if err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	v, err := c.UploadSecurityScan(ctx, a, in)
	return v, mapEvidenceCreationCommandError(fixtureIngestionError(err))
}
func (f ingestionFixtureCommands) UploadManualSecurityDocument(ctx context.Context, a domain.Actor, in evidenceapp.UploadManualSecurityDocumentInput) (evidencedomain.ManualSecurityDocument, error) {
	c, err := f.nativeSecurityDocuments(false)
	if err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	v, err := c.UploadManualSecurityDocument(ctx, a, in)
	return v, mapEvidenceCreationCommandError(fixtureIngestionError(err))
}

func (s *Server) bindIngestionFixturePorts(ledger *app.Ledger) {
	commands := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.sbomIngestionCommands.(ingestionFixtureCommands); fixture {
		old.ledger = ledger
		s.sbomIngestionCommands = old
	} else if s.sbomIngestionCommands == nil {
		s.sbomIngestionCommands = commands
	}
	if old, fixture := s.vexIngestionCommands.(ingestionFixtureCommands); fixture {
		old.ledger = ledger
		s.vexIngestionCommands = old
	} else if s.vexIngestionCommands == nil {
		s.vexIngestionCommands = commands
	}
	if old, fixture := s.scanIngestionCommands.(ingestionFixtureCommands); fixture {
		old.ledger = ledger
		s.scanIngestionCommands = old
	} else if s.scanIngestionCommands == nil {
		s.scanIngestionCommands = commands
	}
	if old, fixture := s.openAPIIngestionCommands.(ingestionFixtureCommands); fixture {
		old.ledger = ledger
		s.openAPIIngestionCommands = old
	} else if s.openAPIIngestionCommands == nil {
		s.openAPIIngestionCommands = commands
	}
	if old, fixture := s.securityDocumentCommands.(ingestionFixtureCommands); fixture {
		old.ledger = ledger
		s.securityDocumentCommands = old
	} else if s.securityDocumentCommands == nil {
		s.securityDocumentCommands = commands
	}
	if _, fixture := s.durableStreamedCommandExecutor.(catalogFixtureReplayExecutor); s.durableStreamedCommandExecutor == nil || fixture {
		s.durableStreamedCommandExecutor = catalogFixtureReplayExecutor{ledger: ledger}
	}
}

var (
	_ SBOMIngestionCommands              = ingestionFixtureCommands{}
	_ VEXIngestionCommands               = ingestionFixtureCommands{}
	_ OpenAPIIngestionCommands           = ingestionFixtureCommands{}
	_ VulnerabilityScanIngestionCommands = ingestionFixtureCommands{}
	_ SecurityDocumentCommands           = ingestionFixtureCommands{}
)
