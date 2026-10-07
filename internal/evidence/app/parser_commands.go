package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const (
	CycloneDXMediaType        = "application/vnd.cyclonedx+json"
	OpenVEXMediaType          = "application/vnd.openvex+json"
	SPDXMediaType             = "application/spdx+json"
	ScannerMediaType          = "application/json"
	OpenAPIMediaType          = "application/vnd.oai.openapi+json"
	OpenVEXParserVersion      = "openvex-json.v2.0.0"
	CycloneDXVEXParserVersion = "cyclonedx-vex-json.v2.0.0"
)

// PayloadSource provides repeatable access to one bounded, digest-bound
// document without requiring the evidence application service to know whether
// the bytes came from memory, a request spool, or another adapter.
type PayloadSource struct {
	Digest string
	Size   int64
	Open   func() (io.ReadCloser, error)
}

func BytesPayloadSource(raw []byte) PayloadSource {
	owned := append([]byte(nil), raw...)
	digest := sha256.Sum256(owned)
	return PayloadSource{
		Digest: "sha256:" + hex.EncodeToString(digest[:]),
		Size:   int64(len(owned)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(owned)), nil
		},
	}
}

type ParsedSBOM struct {
	Format        string
	SpecVersion   string
	ParserVersion string
	Components    []evidencedomain.SBOMComponent
	Metadata      map[string]any
	Limitations   []string
}

type ParsedVulnerabilityScan struct {
	ReleaseID      string
	Scanner        string
	Adapter        string
	AdapterVersion string
	SourceSchema   string
	TargetRef      string
	Summary        map[string]int
	Findings       []evidencedomain.VulnerabilityFinding
	Metadata       map[string]any
	Limitations    []string
}

type VulnerabilityScanScope struct {
	ReleaseID string
}

// VulnerabilityScanScopeProber extracts only the authorization scope from a
// bounded payload. Full scanner normalization must remain behind the resulting
// tenant and resource authorization checks.
type VulnerabilityScanScopeProber interface {
	ProbeVulnerabilityScanScope(context.Context, PayloadSource) (VulnerabilityScanScope, error)
}

type ParsedOpenAPIContract struct {
	ParserVersion string
	SourceSchema  string
	PathCount     int
	Operations    []evidencedomain.OpenAPIOperation
	Metadata      map[string]any
	Limitations   []string
}

// VEXDecisionStatement is the bounded normalized statement persisted in the
// versioned decision request for post-commit worker processing. The immutable
// raw document remains the evidence source of truth.
type VEXDecisionStatement struct {
	StatementIndex  int
	Vulnerability   string
	Products        []string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
}

// ParsedVEX is the evidence context's intentionally narrow normalized view of
// an uploaded VEX document. Statements are retained for the durable post-commit
// decision request; a stored immutable raw payload is also replayed by the
// worker when one is available.
type ParsedVEX struct {
	Format              string
	Author              string
	Version             string
	ParserVersion       string
	StatementCount      int
	ValidStatementCount int
	StatusSummary       map[string]int
	Statements          []VEXDecisionStatement
	Warnings            []string
	InvalidStatements   []evidencedomain.VEXImportIssue
	Metadata            map[string]any
	Limitations         []string
}

type PayloadParser interface {
	ParseSBOM(context.Context, string, PayloadSource) (ParsedSBOM, error)
	ParseVulnerabilityScan(context.Context, PayloadSource) (ParsedVulnerabilityScan, error)
	ParseOpenAPIContract(context.Context, PayloadSource) (ParsedOpenAPIContract, error)
	ParseVEX(context.Context, string, PayloadSource) (ParsedVEX, error)
}

func (s *Service) UploadSBOM(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID string, raw []byte) (evidencedomain.SBOM, error) {
	return s.UploadSBOMPayload(ctx, actor, releaseID, artifactID, BytesPayloadSource(raw))
}

func (s *Service) UploadSBOMPayload(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID string, source PayloadSource) (evidencedomain.SBOM, error) {
	return s.uploadSBOMPayload(ctx, actor, releaseID, artifactID, "cyclonedx", "CycloneDX SBOM", CycloneDXMediaType, source)
}

func (s *Service) UploadSPDXSBOM(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID string, raw []byte) (evidencedomain.SBOM, error) {
	return s.UploadSPDXSBOMPayload(ctx, actor, releaseID, artifactID, BytesPayloadSource(raw))
}

func (s *Service) UploadSPDXSBOMPayload(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID string, source PayloadSource) (evidencedomain.SBOM, error) {
	return s.uploadSBOMPayload(ctx, actor, releaseID, artifactID, "spdx", "SPDX SBOM", SPDXMediaType, source)
}

func (s *Service) uploadSBOMPayload(ctx context.Context, actor identitydomain.Actor, releaseID, artifactID, format, title, mediaType string, source PayloadSource) (evidencedomain.SBOM, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.SBOM{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.SBOM{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	artifactID = strings.TrimSpace(artifactID)
	if err := validatePayloadSource(source); err != nil {
		return evidencedomain.SBOM{}, err
	}
	scope := EvidenceScope{ReleaseID: releaseID}
	if err := s.reader.ValidateScope(ctx, actor.TenantID, scope); err != nil {
		return evidencedomain.SBOM{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, resourceReferences(scope), false); err != nil {
		return evidencedomain.SBOM{}, err
	}
	if err := s.validateAndAuthorizeArtifactReference(ctx, actor, ScopeEvidenceWrite, artifactID, ""); err != nil {
		return evidencedomain.SBOM{}, err
	}

	parsed, err := s.parser.ParseSBOM(ctx, format, source)
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	parsed.Format = strings.ToLower(strings.TrimSpace(parsed.Format))
	parsed.SpecVersion = strings.TrimSpace(parsed.SpecVersion)
	parsed.ParserVersion = strings.TrimSpace(parsed.ParserVersion)
	if parsed.Format != format || parsed.SpecVersion == "" || parsed.ParserVersion == "" {
		return evidencedomain.SBOM{}, ErrValidation
	}
	staged, err := s.sourceObjects.StagePayloadSource(ctx, actor.TenantID, mediaType, source)
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	now := s.clock.Now().UTC()
	prepared, err := s.prepareEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID: releaseID, Type: "sbom", Subtype: format, Title: title, SourceSystem: "api", ObservedAt: now,
		PayloadRef: staged.Reference(), PayloadHash: source.Digest, PayloadMediaType: mediaType, PayloadSize: source.Size,
		StagedPayload: staged, SubjectRefs: subjectForArtifact(artifactID), Metadata: cloneMap(parsed.Metadata),
		Limitations: append([]string(nil), parsed.Limitations...),
	})
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	sbom := evidencedomain.SBOM{
		ID: s.ids.NewID("sbom"), TenantID: actor.TenantID, EvidenceID: prepared.item.ID,
		ReleaseID: releaseID, ArtifactID: artifactID, Format: format, SpecVersion: parsed.SpecVersion,
		ComponentCount: len(parsed.Components), Components: append([]evidencedomain.SBOMComponent(nil), parsed.Components...), CreatedAt: now,
	}
	persisted, action := parserOwnedSBOM(sbom, s.workerOwnedParsers && staged.Present() && staged.Reference() != "")
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := s.persistPreparedEvidence(ctx, tx, actor, &prepared); err != nil {
			return err
		}
		if err := tx.Ingestion().InsertSBOM(ctx, persisted); err != nil {
			return err
		}
		if _, err := tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, now, action, "sbom", sbom.ID, source.Digest)); err != nil {
			return err
		}
		return tx.Outbox().EnqueueOutbox(ctx, s.parserJob(actor.TenantID, "parse_sbom", "sbom", sbom.ID, source, staged, parsed.ParserVersion, now))
	})
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	return cloneSBOM(sbom), nil
}

func (s *Service) UploadVulnerabilityScan(ctx context.Context, actor identitydomain.Actor, raw []byte) (evidencedomain.VulnerabilityScan, error) {
	return s.UploadVulnerabilityScanPayload(ctx, actor, BytesPayloadSource(raw))
}

func (s *Service) UploadVulnerabilityScanPayload(ctx context.Context, actor identitydomain.Actor, source PayloadSource) (evidencedomain.VulnerabilityScan, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	if err := validatePayloadSource(source); err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	probed, err := s.vulnerabilityScanScopeProber.ProbeVulnerabilityScanScope(ctx, source)
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	probed.ReleaseID = strings.TrimSpace(probed.ReleaseID)
	if probed.ReleaseID == "" {
		return evidencedomain.VulnerabilityScan{}, ErrValidation
	}
	scope := EvidenceScope{ReleaseID: probed.ReleaseID}
	if err := s.reader.ValidateScope(ctx, actor.TenantID, scope); err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, resourceReferences(scope), false); err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	parsed, err := s.parser.ParseVulnerabilityScan(ctx, source)
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	parsed.ReleaseID = strings.TrimSpace(parsed.ReleaseID)
	parsed.Scanner = strings.TrimSpace(parsed.Scanner)
	parsed.Adapter = strings.TrimSpace(parsed.Adapter)
	parsed.AdapterVersion = strings.TrimSpace(parsed.AdapterVersion)
	parsed.SourceSchema = strings.TrimSpace(parsed.SourceSchema)
	parsed.TargetRef = strings.TrimSpace(parsed.TargetRef)
	if parsed.ReleaseID == "" || parsed.ReleaseID != probed.ReleaseID || parsed.Scanner == "" || parsed.Adapter == "" || parsed.AdapterVersion == "" || parsed.SourceSchema == "" || parsed.TargetRef == "" {
		return evidencedomain.VulnerabilityScan{}, ErrValidation
	}
	staged, err := s.sourceObjects.StagePayloadSource(ctx, actor.TenantID, ScannerMediaType, source)
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	now := s.clock.Now().UTC()
	prepared, err := s.prepareEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID: parsed.ReleaseID, Type: "vulnerability_scan", Subtype: parsed.Adapter, Title: "Vulnerability scan",
		SourceSystem: parsed.Scanner, ObservedAt: now, PayloadRef: staged.Reference(), PayloadHash: source.Digest,
		PayloadMediaType: ScannerMediaType, PayloadSize: source.Size, StagedPayload: staged,
		Metadata: cloneMap(parsed.Metadata), Limitations: append([]string(nil), parsed.Limitations...),
	})
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	scanID := s.ids.NewID("scan")
	findings := make([]evidencedomain.VulnerabilityFinding, len(parsed.Findings))
	copy(findings, parsed.Findings)
	for index := range findings {
		findings[index].ID = scanID + ":finding:" + decimal(index+1)
	}
	scan := evidencedomain.VulnerabilityScan{
		ID: scanID, TenantID: actor.TenantID, EvidenceID: prepared.item.ID, ReleaseID: parsed.ReleaseID,
		Scanner: parsed.Scanner, Adapter: parsed.Adapter, AdapterVersion: parsed.AdapterVersion, SourceSchema: parsed.SourceSchema,
		TargetRef: parsed.TargetRef, Summary: cloneIntMap(parsed.Summary), Findings: findings, CreatedAt: now,
	}
	persisted, action := parserOwnedVulnerabilityScan(scan, s.workerOwnedParsers && staged.Present() && staged.Reference() != "")
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := s.persistPreparedEvidence(ctx, tx, actor, &prepared); err != nil {
			return err
		}
		if err := tx.Ingestion().InsertVulnerabilityScan(ctx, persisted); err != nil {
			return err
		}
		if _, err := tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, now, action, "vulnerability_scan", scan.ID, source.Digest)); err != nil {
			return err
		}
		return tx.Outbox().EnqueueOutbox(ctx, s.parserJob(actor.TenantID, "parse_vulnerability_scan", "vulnerability_scan", scan.ID, source, staged, parsed.AdapterVersion, now))
	})
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	return cloneVulnerabilityScan(scan), nil
}

func (s *Service) UploadOpenAPIContract(ctx context.Context, actor identitydomain.Actor, productID, releaseID, version string, raw []byte) (evidencedomain.OpenAPIContract, error) {
	return s.UploadOpenAPIContractPayload(ctx, actor, productID, releaseID, version, BytesPayloadSource(raw))
}

func (s *Service) UploadOpenAPIContractPayload(ctx context.Context, actor identitydomain.Actor, productID, releaseID, version string, source PayloadSource) (evidencedomain.OpenAPIContract, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	productID = strings.TrimSpace(productID)
	releaseID = strings.TrimSpace(releaseID)
	version = strings.TrimSpace(version)
	if productID == "" || version == "" {
		return evidencedomain.OpenAPIContract{}, ErrValidation
	}
	if err := validatePayloadSource(source); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	scope := EvidenceScope{ProductID: productID, ReleaseID: releaseID}
	if err := s.reader.ValidateScope(ctx, actor.TenantID, scope); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, resourceReferences(scope), false); err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	parsed, err := s.parser.ParseOpenAPIContract(ctx, source)
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	parsed.ParserVersion = strings.TrimSpace(parsed.ParserVersion)
	parsed.SourceSchema = strings.TrimSpace(parsed.SourceSchema)
	if parsed.ParserVersion == "" || parsed.SourceSchema == "" || parsed.PathCount < 0 {
		return evidencedomain.OpenAPIContract{}, ErrValidation
	}
	staged, err := s.sourceObjects.StagePayloadSource(ctx, actor.TenantID, OpenAPIMediaType, source)
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	now := s.clock.Now().UTC()
	prepared, err := s.prepareEvidence(ctx, actor, CreateEvidenceInput{
		ProductID: productID, ReleaseID: releaseID, Type: "openapi_contract", Subtype: "openapi", Title: "OpenAPI contract",
		SourceSystem: "api", ObservedAt: now, PayloadRef: staged.Reference(), PayloadHash: source.Digest,
		PayloadMediaType: OpenAPIMediaType, PayloadSize: source.Size, StagedPayload: staged,
		Metadata: cloneMap(parsed.Metadata), Limitations: append([]string(nil), parsed.Limitations...),
	})
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	contract := evidencedomain.OpenAPIContract{
		ID: s.ids.NewID("oas"), TenantID: actor.TenantID, ProductID: productID, ReleaseID: releaseID,
		Version: version, Hash: source.Digest, PathCount: parsed.PathCount,
		Operations: cloneOpenAPIOperations(parsed.Operations), EvidenceID: prepared.item.ID, CreatedAt: now,
	}
	persisted, action := parserOwnedOpenAPIContract(contract, s.workerOwnedParsers && staged.Present() && staged.Reference() != "")
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := s.persistPreparedEvidence(ctx, tx, actor, &prepared); err != nil {
			return err
		}
		if err := tx.Ingestion().InsertOpenAPIContract(ctx, persisted); err != nil {
			return err
		}
		if _, err := tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, now, action, "openapi_contract", contract.ID, source.Digest)); err != nil {
			return err
		}
		return tx.Outbox().EnqueueOutbox(ctx, s.parserJob(actor.TenantID, "parse_openapi_contract", "openapi_contract", contract.ID, source, staged, parsed.ParserVersion, now))
	})
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	return cloneOpenAPIContract(contract), nil
}

func validatePayloadSource(source PayloadSource) error {
	if !validPayloadSize(source.Size, EvidenceDocumentLimit) || !validDigest(strings.TrimSpace(source.Digest)) || source.Open == nil {
		return ErrValidation
	}
	return nil
}

func subjectForArtifact(artifactID string) []evidencedomain.SubjectRef {
	if artifactID = strings.TrimSpace(artifactID); artifactID != "" {
		return []evidencedomain.SubjectRef{{Type: "artifact", ID: artifactID}}
	}
	return nil
}

func (s *Service) parserJob(tenantID, kind, subjectType, subjectID string, source PayloadSource, staged StagedPayload, parserVersion string, now time.Time) application.OutboxEvent {
	return newParserJob(s.ids, tenantID, kind, subjectType, subjectID, source, staged, parserVersion, now)
}

func newParserJob(ids application.IDGenerator, tenantID, kind, subjectType, subjectID string, source PayloadSource, staged StagedPayload, parserVersion string, now time.Time) application.OutboxEvent {
	payload := map[string]any{
		"payload_ref": staged.Reference(), "payload_hash": source.Digest, "parser_version": parserVersion,
	}
	if staged.Status == PayloadStatusStaged {
		payload["payload_lifecycle"] = PayloadLifecycleVersion
		payload["payload_digest"] = staged.Digest
	}
	return application.OutboxEvent{
		ID: ids.NewID("job"), TenantID: tenantID, Kind: kind, SubjectType: subjectType,
		SubjectID: subjectID, Payload: payload, CreatedAt: now,
	}
}

func parserOwnedSBOM(value evidencedomain.SBOM, workerOwned bool) (evidencedomain.SBOM, string) {
	if !workerOwned {
		return value, "sbom.parsed"
	}
	persisted := value
	persisted.SpecVersion = ""
	persisted.ComponentCount = 0
	persisted.Components = nil
	return persisted, "sbom.accepted"
}

func parserOwnedVulnerabilityScan(value evidencedomain.VulnerabilityScan, workerOwned bool) (evidencedomain.VulnerabilityScan, string) {
	if !workerOwned {
		return value, "vulnerability_scan.parsed"
	}
	persisted := value
	persisted.Scanner = ""
	persisted.Adapter = ""
	persisted.AdapterVersion = ""
	persisted.SourceSchema = ""
	persisted.TargetRef = ""
	persisted.Summary = nil
	persisted.Findings = nil
	return persisted, "vulnerability_scan.accepted"
}

func parserOwnedOpenAPIContract(value evidencedomain.OpenAPIContract, workerOwned bool) (evidencedomain.OpenAPIContract, string) {
	if !workerOwned {
		return value, "openapi_contract.parsed"
	}
	persisted := value
	persisted.PathCount = 0
	persisted.Operations = nil
	return persisted, "openapi_contract.accepted"
}

func cloneVulnerabilityScan(value evidencedomain.VulnerabilityScan) evidencedomain.VulnerabilityScan {
	value.Summary = cloneIntMap(value.Summary)
	if value.Findings != nil {
		value.Findings = append([]evidencedomain.VulnerabilityFinding{}, value.Findings...)
	}
	return value
}

func cloneOpenAPIOperations(values []evidencedomain.OpenAPIOperation) []evidencedomain.OpenAPIOperation {
	result := append([]evidencedomain.OpenAPIOperation(nil), values...)
	for index := range result {
		result[index].RequiredRequestFields = append([]string(nil), result[index].RequiredRequestFields...)
		result[index].ResponseStatuses = append([]string(nil), result[index].ResponseStatuses...)
	}
	return result
}

func decimal(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
