package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"reflect"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

const (
	BuildAttestationMediaType        = "application/vnd.dsse.envelope+json"
	BuildAttestationParserVersion    = "dsse-in-toto-json.v1.0.0"
	BuildAttestationPayloadLimit     = int64(20 << 20)
	buildAttestationPayloadLimit     = BuildAttestationPayloadLimit
	buildAttestationPayloadLifecycle = "object-payload.v1"
)

// BuildAttestationPayloadSource provides repeatable access to caller-supplied
// bytes. Digest and size are transport observations which the parser and
// stager must independently verify before the command trusts the payload.
type BuildAttestationPayloadSource struct {
	Digest string
	Size   int64
	Open   func() (io.ReadCloser, error)
}

func BytesBuildAttestationPayloadSource(raw []byte) BuildAttestationPayloadSource {
	digest := sha256.Sum256(raw)
	return BuildAttestationPayloadSource{
		Digest: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(raw)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil },
	}
}

type ParsedBuildAttestation struct {
	PayloadHash    string
	PayloadSize    int64
	ParserVersion  string
	PayloadType    string
	PredicateType  string
	SubjectDigests []string
	BuilderID      string
	BuildType      string
	MaterialsCount int
	SignatureCount int
}

type BuildAttestationParser interface {
	ParseBuildAttestation(context.Context, BuildAttestationPayloadSource) (ParsedBuildAttestation, error)
}

// StagedBuildAttestationPayload is the release command's storage-neutral view
// of a payload staged by the compatibility layer. Empty values represent the
// supported inline/no-object-store mode.
type StagedBuildAttestationPayload struct {
	TenantID    string
	Digest      string
	Size        int64
	MediaType   string
	Reference   string
	StagingKey  string
	FinalKey    string
	Status      string
	FailureCode string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	FinalizedAt *time.Time
	FailedAt    *time.Time
	OrphanedAt  *time.Time
}

func (p StagedBuildAttestationPayload) present() bool {
	return p.TenantID != "" || p.Digest != "" || p.Size != 0 || p.MediaType != "" || p.Reference != "" || p.StagingKey != "" || p.FinalKey != "" || p.Status != ""
}

func (p StagedBuildAttestationPayload) managed() bool {
	return p.Status == "staged" && p.TenantID != "" && p.Digest != "" && p.StagingKey != "" && p.FinalKey != ""
}

func (p StagedBuildAttestationPayload) replayable() bool {
	return p.present() && (p.Status == "staged" || p.Status == "finalized") &&
		strings.TrimSpace(p.FinalKey) != "" && p.Reference == "object://"+p.FinalKey
}

type BuildAttestationPayloadStager interface {
	StageBuildAttestationPayload(context.Context, string, BuildAttestationPayloadSource) (StagedBuildAttestationPayload, error)
}

type BuildAttestationEvidenceSubject struct {
	Type   string
	ID     string
	Digest string
}

// BuildAttestationEvidenceInput is the only evidence-owned mutation requested
// by this release command. It intentionally excludes the broad evidence
// repository surface.
type BuildAttestationEvidenceInput struct {
	ProductID        string
	ProjectID        string
	ReleaseID        string
	BuildID          string
	SourceSystem     string
	SourceIdentity   map[string]any
	CollectorID      string
	ObservedAt       time.Time
	PayloadRef       string
	PayloadHash      string
	PayloadMediaType string
	PayloadSize      int64
	StagedPayload    StagedBuildAttestationPayload
	Subjects         []BuildAttestationEvidenceSubject
	ParserVersion    string
	PayloadType      string
	PredicateType    string
	SignatureCount   int
}

type BuildAttestationEvidenceReceipt struct{ EvidenceID string }

// BuildAttestationEvidenceWriter is the method-specific EVY-903 compatibility
// bridge documented by ADR 0003. Implementations construct and insert the
// immutable evidence item and its audit in this transaction. EVY-906 retires
// this capability in favor of the documented ingestion saga.
type BuildAttestationEvidenceWriter interface {
	WriteBuildAttestationEvidence(context.Context, identitydomain.Actor, BuildAttestationEvidenceInput) (BuildAttestationEvidenceReceipt, error)
}

func (s *Service) UploadBuildAttestation(ctx context.Context, actor identitydomain.Actor, buildID string, raw []byte) (releasedomain.BuildAttestation, error) {
	return s.buildAttestationCommands.UploadBuildAttestation(ctx, actor, buildID, raw)
}

func (s *Service) UploadBuildAttestationPayload(ctx context.Context, actor identitydomain.Actor, buildID string, source BuildAttestationPayloadSource) (releasedomain.BuildAttestation, error) {
	return s.buildAttestationCommands.UploadBuildAttestationPayload(ctx, actor, buildID, source)
}

func (s *BuildAttestationCommands) UploadBuildAttestation(ctx context.Context, actor identitydomain.Actor, buildID string, raw []byte) (releasedomain.BuildAttestation, error) {
	return s.UploadBuildAttestationPayload(ctx, actor, buildID, BytesBuildAttestationPayloadSource(raw))
}

func (s *BuildAttestationCommands) UploadBuildAttestationPayload(ctx context.Context, actor identitydomain.Actor, buildID string, source BuildAttestationPayloadSource) (releasedomain.BuildAttestation, error) {
	if s == nil {
		return releasedomain.BuildAttestation{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeBuildWrite, ScopeOnly: true}); err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	var err error
	buildID, err = NormalizeBuildAttestationBuildID(buildID)
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	if !validBuildAttestationPayloadSource(source) {
		return releasedomain.BuildAttestation{}, ErrValidation
	}

	build, err := s.reader.GetBuildRun(ctx, actor.TenantID, buildID)
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	if build.TenantID != actor.TenantID || build.ID != buildID {
		return releasedomain.BuildAttestation{}, ErrNotFound
	}
	project, err := s.reader.GetProject(ctx, actor.TenantID, build.ProjectID)
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, build.ReleaseID)
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	if !projectBelongsToTenant(project, actor.TenantID, build.ProjectID) || !releaseBelongsToTenant(release, actor.TenantID, build.ReleaseID) || project.ProductID != release.ProductID {
		return releasedomain.BuildAttestation{}, ErrNotFound
	}
	resources := application.ResourceReferences{ProductID: project.ProductID, ProjectID: project.ID, ReleaseID: release.ID, BuildID: build.ID}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: resources}); err != nil {
		return releasedomain.BuildAttestation{}, err
	}

	artifacts := make(map[string]releasedomain.Artifact)
	for _, output := range build.Outputs {
		if !validDigest(strings.TrimSpace(output.Digest)) {
			return releasedomain.BuildAttestation{}, ErrValidation
		}
		if strings.TrimSpace(output.ArtifactID) == "" {
			continue
		}
		artifact, err := s.reader.GetArtifact(ctx, actor.TenantID, strings.TrimSpace(output.ArtifactID))
		if err != nil {
			return releasedomain.BuildAttestation{}, err
		}
		if !artifactBelongsToTenant(artifact, actor.TenantID, output.ArtifactID) {
			return releasedomain.BuildAttestation{}, ErrNotFound
		}
		if artifact.Digest != output.Digest {
			return releasedomain.BuildAttestation{}, ErrValidation
		}
		if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeBuildWrite, Resources: application.ResourceReferences{ArtifactID: artifact.ID}}); err != nil {
			return releasedomain.BuildAttestation{}, err
		}
		artifacts[artifact.ID] = artifact
	}

	parsed, err := s.attestationParser.ParseBuildAttestation(ctx, source)
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	if !validParsedBuildAttestation(source, parsed) || !attestationSubjectsMatchBuildOutputs(parsed.SubjectDigests, build.Outputs) {
		return releasedomain.BuildAttestation{}, ErrValidation
	}
	staged, err := s.payloadStager.StageBuildAttestationPayload(ctx, actor.TenantID, source)
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	if !validStagedBuildAttestationPayload(actor.TenantID, source, staged) {
		return releasedomain.BuildAttestation{}, ErrValidation
	}

	commandAt := s.clock.Now().UTC()
	attestation := releasedomain.BuildAttestation{
		ID: s.ids.NewID("att"), TenantID: actor.TenantID, BuildID: build.ID,
		PayloadRef: staged.Reference, PayloadHash: source.Digest, PayloadSize: source.Size,
		PayloadType: parsed.PayloadType, PredicateType: parsed.PredicateType,
		SubjectDigests: append([]string(nil), parsed.SubjectDigests...), BuilderID: parsed.BuilderID,
		BuildType: parsed.BuildType, MaterialsCount: parsed.MaterialsCount, SignatureCount: parsed.SignatureCount,
		VerificationStatus: "structurally_valid", SchemaVersion: releasedomain.BuildAttestationSchemaVersion,
		CreatedAt: commandAt,
	}
	persisted := attestation
	auditAction := "build_attestation.created"
	if s.workerOwnedParsers && staged.replayable() {
		persisted.PayloadType = ""
		persisted.PredicateType = ""
		persisted.SubjectDigests = nil
		persisted.BuilderID = ""
		persisted.BuildType = ""
		persisted.MaterialsCount = 0
		persisted.SignatureCount = 0
		persisted.VerificationStatus = "accepted"
		auditAction = "build_attestation.accepted"
	}
	evidenceInput := BuildAttestationEvidenceInput{
		ProductID: project.ProductID, ProjectID: project.ID, ReleaseID: release.ID, BuildID: build.ID,
		SourceSystem: build.Provider, SourceIdentity: cloneAnyMap(build.SourceIdentity), CollectorID: actor.CollectorID,
		ObservedAt: commandAt, PayloadRef: staged.Reference, PayloadHash: source.Digest,
		PayloadMediaType: BuildAttestationMediaType, PayloadSize: source.Size, StagedPayload: staged,
		Subjects: buildAttestationEvidenceSubjects(build.Outputs), ParserVersion: parsed.ParserVersion,
		PayloadType: parsed.PayloadType, PredicateType: parsed.PredicateType, SignatureCount: parsed.SignatureCount,
	}

	err = s.transactions.ExecuteBuildAttestation(ctx, func(ctx context.Context, tx BuildAttestationTransaction) error {
		if err := revalidateBuildAttestationScope(ctx, tx, actor.TenantID, project, release, build, artifacts); err != nil {
			return err
		}
		receipt, err := tx.WriteBuildAttestationEvidence(ctx, actor, evidenceInput)
		if err != nil {
			return err
		}
		if strings.TrimSpace(receipt.EvidenceID) == "" {
			return ErrConflict
		}
		attestation.EvidenceID = receipt.EvidenceID
		persisted.EvidenceID = receipt.EvidenceID
		if err := tx.InsertBuildAttestation(ctx, persisted); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, auditEventFor(s.ids, actor, commandAt, auditAction, "build_attestation", attestation.ID, source.Digest)); err != nil {
			return err
		}
		payload := map[string]any{"payload_ref": staged.Reference, "payload_hash": source.Digest, "parser_version": parsed.ParserVersion}
		if staged.managed() {
			payload["payload_lifecycle"] = buildAttestationPayloadLifecycle
			payload["payload_digest"] = staged.Digest
		}
		return tx.EnqueueOutbox(ctx, application.OutboxEvent{
			ID: s.ids.NewID("job"), TenantID: actor.TenantID, Kind: "verify_attestation",
			SubjectType: "build_attestation", SubjectID: attestation.ID, Payload: payload, CreatedAt: commandAt,
		})
	})
	if err != nil {
		return releasedomain.BuildAttestation{}, err
	}
	return attestation, nil
}

func validBuildAttestationPayloadSource(source BuildAttestationPayloadSource) bool {
	return source.Open != nil && source.Size > 0 && source.Size <= buildAttestationPayloadLimit && validDigest(strings.TrimSpace(source.Digest))
}

func validParsedBuildAttestation(source BuildAttestationPayloadSource, parsed ParsedBuildAttestation) bool {
	return parsed.PayloadHash == source.Digest && parsed.PayloadSize == source.Size &&
		parsed.ParserVersion == BuildAttestationParserVersion && strings.TrimSpace(parsed.PayloadType) != "" &&
		strings.TrimSpace(parsed.PredicateType) != "" && parsed.MaterialsCount >= 0 && parsed.SignatureCount >= 0
}

func validStagedBuildAttestationPayload(tenantID string, source BuildAttestationPayloadSource, staged StagedBuildAttestationPayload) bool {
	if !staged.present() {
		return true
	}
	if staged.TenantID != tenantID || staged.Digest != source.Digest || staged.Size != source.Size ||
		staged.MediaType != BuildAttestationMediaType || staged.Reference != "object://"+staged.FinalKey || strings.TrimSpace(staged.FinalKey) == "" {
		return false
	}
	switch staged.Status {
	case "staged":
		return strings.TrimSpace(staged.StagingKey) != ""
	case "finalized":
		return true
	default:
		return false
	}
}

func attestationSubjectsMatchBuildOutputs(subjectDigests []string, outputs []releasedomain.BuildOutput) bool {
	outputSet := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if digest := strings.TrimSpace(output.Digest); digest != "" {
			outputSet[digest] = struct{}{}
		}
	}
	for _, digest := range subjectDigests {
		if _, ok := outputSet[strings.TrimSpace(digest)]; ok {
			return true
		}
	}
	return false
}

func buildAttestationEvidenceSubjects(outputs []releasedomain.BuildOutput) []BuildAttestationEvidenceSubject {
	result := make([]BuildAttestationEvidenceSubject, 0, len(outputs))
	for _, output := range outputs {
		result = append(result, BuildAttestationEvidenceSubject{Type: "artifact", ID: output.ArtifactID, Digest: output.Digest})
	}
	return result
}

func revalidateBuildAttestationScope(ctx context.Context, tx BuildAttestationTransaction, tenantID string, project releasedomain.Project, release releasedomain.Release, build releasedomain.BuildRun, artifacts map[string]releasedomain.Artifact) error {
	currentProject, err := tx.GetProject(ctx, tenantID, project.ID)
	if err != nil {
		return err
	}
	if !projectBelongsToTenant(currentProject, tenantID, project.ID) {
		return ErrNotFound
	}
	currentRelease, err := tx.GetRelease(ctx, tenantID, release.ID)
	if err != nil {
		return err
	}
	if !releaseBelongsToTenant(currentRelease, tenantID, release.ID) {
		return ErrNotFound
	}
	if !sameProjectCoordinates(currentProject, project) || !sameReleaseCoordinates(currentRelease, release) || currentProject.ProductID != currentRelease.ProductID {
		return ErrConflict
	}
	currentBuild, err := tx.GetBuildRun(ctx, tenantID, build.ID)
	if err != nil {
		return err
	}
	if currentBuild.TenantID != tenantID || currentBuild.ID != build.ID {
		return ErrNotFound
	}
	if !reflect.DeepEqual(currentBuild, build) || currentBuild.ProjectID != currentProject.ID || currentBuild.ReleaseID != currentRelease.ID {
		return ErrConflict
	}
	for id, artifact := range artifacts {
		current, err := tx.GetArtifact(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if !artifactBelongsToTenant(current, tenantID, id) {
			return ErrNotFound
		}
		if !sameArtifactCoordinates(current, artifact) {
			return ErrConflict
		}
	}
	return nil
}
