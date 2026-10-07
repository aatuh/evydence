package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"maps"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

// Only test binaries use these command adapters. Native guards run the actual
// algorithms and authorizers on current fixture parents. Fresh writes retain
// the real legacy parser/stager and isolated replay transaction, not guard stubs.
type ingestionFixtureCommands struct{ catalogFixtureCommands }

func (f ingestionFixtureCommands) authority() ingestionFixtureAuthority {
	return ingestionFixtureAuthority(f)
}

func (f ingestionFixtureCommands) sbomGuard() (*evidenceapp.SBOMIngestionCommands, error) {
	auth, err := f.authority().authorizer(false)
	if err != nil {
		return nil, err
	}
	noEffects := ingestionFixtureGuardEffects{}
	return evidenceapp.NewSBOMIngestionCommands(evidenceapp.SBOMIngestionCommandConfig{Authorizer: auth, Transactions: ingestionFixtureGuardRunner{f.authority(), false}, Parser: app.SBOMPayloadParser{}, Objects: noEffects, Payloads: noEffects, Canonicalizer: noEffects, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
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
	auth, err := f.authority().authorizer(false)
	if err != nil {
		return nil, err
	}
	noEffects := ingestionFixtureGuardEffects{}
	return evidenceapp.NewOpenAPIIngestionCommands(evidenceapp.OpenAPIIngestionCommandConfig{Authorizer: auth, Transactions: ingestionFixtureGuardRunner{f.authority(), false}, Parser: app.OpenAPIContractPayloadParser{}, Objects: noEffects, Payloads: noEffects, Canonicalizer: noEffects, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
}
func (f ingestionFixtureCommands) scanGuard() (*evidenceapp.VulnerabilityScanIngestionCommands, error) {
	auth, err := f.authority().authorizer(false)
	if err != nil {
		return nil, err
	}
	noEffects := ingestionFixtureGuardEffects{}
	return evidenceapp.NewVulnerabilityScanIngestionCommands(evidenceapp.VulnerabilityScanIngestionCommandConfig{Authorizer: auth, Transactions: ingestionFixtureGuardRunner{f.authority(), false}, Parser: app.VulnerabilityScanPayloadParser{}, Objects: noEffects, Payloads: noEffects, Canonicalizer: noEffects, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
}
func (f ingestionFixtureCommands) securityGuard() (*evidenceapp.SecurityDocumentCommands, error) {
	auth, err := f.authority().authorizer(true)
	if err != nil {
		return nil, err
	}
	noEffects := ingestionFixtureGuardEffects{}
	return evidenceapp.NewSecurityDocumentCommands(evidenceapp.SecurityDocumentCommandConfig{Authorizer: auth, Transactions: ingestionFixtureGuardRunner{f.authority(), true}, Objects: noEffects, Canonicalizer: noEffects, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: application.ClockFunc(ingestionFixtureGuardClock), IDs: application.IDGeneratorFunc(ingestionFixtureGuardID)})
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
	var value domain.SBOM
	var err error
	switch in.Format {
	case "cyclonedx":
		value, err = f.commandLedger(ctx).UploadSBOMPayload(ctx, a, in.ReleaseID, in.ArtifactID, fixtureLegacySource(source))
	case "spdx":
		value, err = f.commandLedger(ctx).UploadSPDXSBOMPayload(ctx, a, in.ReleaseID, in.ArtifactID, fixtureLegacySource(source))
	default:
		return evidencedomain.SBOM{}, app.ErrValidation
	}
	return fixtureSBOM(value), err
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
	value, err := f.commandLedger(ctx).UploadOpenAPIContractPayload(ctx, a, in.ProductID, in.ReleaseID, in.Version, fixtureLegacySource(source))
	return fixtureOpenAPIContract(value), err
}
func (f ingestionFixtureCommands) UploadVulnerabilityScanPayload(ctx context.Context, a domain.Actor, in evidenceapp.VulnerabilityScanScope, source evidenceapp.PayloadSource) (evidencedomain.VulnerabilityScan, error) {
	probed, err := f.ProbeVulnerabilityScanScope(ctx, a, source)
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	if probed.ReleaseID != in.ReleaseID {
		return evidencedomain.VulnerabilityScan{}, app.ErrValidation
	}
	value, err := f.commandLedger(ctx).UploadVulnerabilityScanPayload(ctx, a, fixtureLegacySource(source))
	return fixtureVulnerabilityScan(value), err
}
func (f ingestionFixtureCommands) UploadSecurityScan(ctx context.Context, a domain.Actor, in evidenceapp.UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	value, err := f.commandLedger(ctx).UploadSecurityScan(ctx, a, app.UploadSecurityScanInput(in))
	model := evidencedomain.SecurityScan(value)
	model.Summary = maps.Clone(value.Summary)
	return model, err
}
func (f ingestionFixtureCommands) UploadManualSecurityDocument(ctx context.Context, a domain.Actor, in evidenceapp.UploadManualSecurityDocumentInput) (evidencedomain.ManualSecurityDocument, error) {
	value, err := f.commandLedger(ctx).UploadManualSecurityDocument(ctx, a, app.UploadManualSecurityDocumentInput(in))
	return evidencedomain.ManualSecurityDocument(value), err
}

func (s *Server) bindIngestionFixturePorts(ledger *app.Ledger) {
	commands := ingestionFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.sbomIngestionCommands.(ingestionFixtureCommands); s.sbomIngestionCommands == nil || fixture {
		s.sbomIngestionCommands = commands
	}
	if _, fixture := s.vexIngestionCommands.(ingestionFixtureCommands); s.vexIngestionCommands == nil || fixture {
		s.vexIngestionCommands = commands
	}
	if _, fixture := s.scanIngestionCommands.(ingestionFixtureCommands); s.scanIngestionCommands == nil || fixture {
		s.scanIngestionCommands = commands
	}
	if _, fixture := s.openAPIIngestionCommands.(ingestionFixtureCommands); s.openAPIIngestionCommands == nil || fixture {
		s.openAPIIngestionCommands = commands
	}
	if _, fixture := s.securityDocumentCommands.(ingestionFixtureCommands); s.securityDocumentCommands == nil || fixture {
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
