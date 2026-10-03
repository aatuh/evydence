package app

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const buildAttestationEvidenceMediaType = "application/vnd.dsse.envelope+json"

type BuildAttestationEvidenceInput struct {
	ProductID, ProjectID, ReleaseID, BuildID  string
	SourceSystem                              string
	SourceIdentity                            map[string]any
	ObservedAt, CreatedAt                     time.Time
	PayloadRef, PayloadHash                   string
	PayloadSize                               int64
	StagedPayload                             StagedPayload
	Subjects                                  []evidencedomain.SubjectRef
	ParserVersion, PayloadType, PredicateType string
	SignatureCount                            int
}

type BuildAttestationEvidenceRepository interface {
	ValidateScope(context.Context, string, EvidenceScope) error
	ValidateArtifactReference(context.Context, string, string, string) error
	InsertEvidence(context.Context, evidencedomain.EvidenceItem) error
}

// Validation checks the storage-neutral lifecycle identity and canonical keys;
// it must not stage bytes, finalize objects, or perform an independent write.
type BuildAttestationEvidencePayloads interface {
	PayloadRecorder
	ValidateStagedPayload(context.Context, StagedPayload) error
}

type BuildAttestationEvidenceConfig struct {
	Repository    BuildAttestationEvidenceRepository
	Audit         application.AuditAppender
	Payloads      BuildAttestationEvidencePayloads
	Outbox        application.OutboxEnqueuer
	Canonicalizer Canonicalizer
	Authorizer    application.Authorizer
	IDs           application.IDGenerator
}

// BuildAttestationEvidenceWriter is the fixed-shape ADR 0003 capability owned
// by Evidence. Every port must be bound to the caller's active transaction;
// the writer opens no transaction and publishes no compatibility cache state.
type BuildAttestationEvidenceWriter struct {
	config BuildAttestationEvidenceConfig
}

func NewBuildAttestationEvidenceWriter(c BuildAttestationEvidenceConfig) (*BuildAttestationEvidenceWriter, error) {
	if c.Repository == nil || c.Audit == nil || c.Payloads == nil || c.Outbox == nil || c.Canonicalizer == nil || c.Authorizer == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &BuildAttestationEvidenceWriter{c}, nil
}

func (w *BuildAttestationEvidenceWriter) WriteBuildAttestationEvidence(ctx context.Context, a identitydomain.Actor, in BuildAttestationEvidenceInput) (string, error) {
	if w == nil {
		return "", ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return "", err
	}
	for _, id := range []string{a.TenantID, in.ProductID, in.ProjectID, in.ReleaseID, in.BuildID} {
		if !validDeploymentEvidenceID(id) {
			return "", ErrValidation
		}
	}
	if in.ObservedAt.IsZero() || in.CreatedAt.IsZero() || !validDigest(in.PayloadHash) || in.PayloadSize <= 0 || in.PayloadSize > 20<<20 || in.ParserVersion != "dsse-in-toto-json.v1.0.0" || strings.TrimSpace(in.PayloadType) == "" || strings.TrimSpace(in.PredicateType) == "" || in.SignatureCount < 0 {
		return "", ErrValidation
	}
	if err := validateAttestationEvidencePayload(a.TenantID, in); err != nil {
		return "", err
	}
	refs, err := normalizeSubjectRefs(in.Subjects)
	if err != nil {
		return "", err
	}
	for _, ref := range refs {
		if ref.Type != "artifact" || !validDigest(ref.Digest) || ref.ID != "" && !validDeploymentEvidenceID(ref.ID) {
			return "", ErrValidation
		}
	}
	encoded, err := json.Marshal(in.SourceIdentity)
	if err != nil || len(encoded) > 1<<20 {
		return "", ErrValidation
	}
	var sourceIdentity map[string]any
	if err := json.Unmarshal(encoded, &sourceIdentity); err != nil {
		return "", ErrValidation
	}
	if len(sourceIdentity) == 0 {
		sourceIdentity = nil
	}
	scope := EvidenceScope{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID}
	if err := w.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "build:write", Resources: resourceReferences(scope)}); err != nil {
		return "", err
	}
	if in.StagedPayload.Present() {
		if err := w.config.Payloads.ValidateStagedPayload(ctx, in.StagedPayload); err != nil {
			return "", err
		}
	}
	if err := w.config.Repository.ValidateScope(ctx, a.TenantID, scope); err != nil {
		return "", err
	}
	for _, ref := range refs {
		if ref.ID != "" {
			if err := w.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "build:write", Resources: application.ResourceReferences{ArtifactID: ref.ID}}); err != nil {
				return "", err
			}
			if err := w.config.Repository.ValidateArtifactReference(ctx, a.TenantID, ref.ID, ref.Digest); err != nil {
				return "", err
			}
		}
	}
	// Commit exactly the precision PostgreSQL persists, without changing the
	// versioned canonicalization policy or rehashing historical evidence.
	in.ObservedAt = in.ObservedAt.UTC().Truncate(time.Microsecond)
	in.CreatedAt = in.CreatedAt.UTC().Truncate(time.Microsecond)
	item := evidencedomain.EvidenceItem{
		ID: w.config.IDs.NewID("ev"), TenantID: a.TenantID, ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID,
		Type: "build_attestation", Subtype: "dsse_in_toto", Title: "DSSE in-toto build attestation", SourceSystem: nonEmpty(in.SourceSystem, "api"), SourceIdentity: sourceIdentity,
		CollectorID: a.CollectorID, UploadedBy: a.KeyID, ObservedAt: in.ObservedAt, EvidenceVersion: 1, SchemaVersion: evidencedomain.EvidenceItemSchemaVersion,
		PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash, PayloadMediaType: buildAttestationEvidenceMediaType, PayloadSize: in.PayloadSize,
		Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion, SubjectRefs: withEvidenceOriginRefs(refs, scope), TrustLevel: "L2", VerificationStatus: "pending", Tags: []string{},
		Metadata:    map[string]any{"payload_type": in.PayloadType, "predicate_type": in.PredicateType, "signature_count": in.SignatureCount, "parser": map[string]any{"name": "dsse-in-toto", "version": in.ParserVersion, "source_schema": "in-toto-statement.v1", "normalized_schema": "evydence-build-attestation.v1", "warnings": []string(nil), "replay_status": "original"}},
		Limitations: []string{"Structural DSSE/in-toto parsing does not assign trust. A separately recorded offline verification receipt is required for release readiness."}, CreatedAt: in.CreatedAt,
	}
	item.CanonicalHash, err = w.config.Canonicalizer.HashEvidence(ctx, item)
	if err != nil {
		return "", err
	}
	if !validDigest(item.CanonicalHash) {
		return "", ErrValidation
	}
	if in.StagedPayload.Status == PayloadStatusStaged {
		if err := w.config.Payloads.RecordStagedPayload(ctx, in.StagedPayload); err != nil {
			return "", err
		}
		if err := w.config.Outbox.EnqueueOutbox(ctx, application.OutboxEvent{ID: w.config.IDs.NewID("job"), TenantID: a.TenantID, Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: in.PayloadHash, Payload: map[string]any{"payload_digest": in.PayloadHash, "payload_lifecycle": PayloadLifecycleVersion}, CreatedAt: in.CreatedAt}); err != nil {
			return "", err
		}
	}
	receipt, err := w.config.Audit.AppendAudit(ctx, application.AuditEvent{ID: w.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: item.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: item.CreatedAt, PayloadHash: item.PayloadHash})
	if err != nil {
		return "", err
	}
	if !validDeploymentEvidenceID(receipt.ID) {
		return "", ErrConflict
	}
	item.ChainEntryID = receipt.ID
	if err := w.config.Repository.InsertEvidence(ctx, item); err != nil {
		return "", err
	}
	return item.ID, nil
}

func validateAttestationEvidencePayload(tenant string, in BuildAttestationEvidenceInput) error {
	p := in.StagedPayload
	if !p.Present() {
		if in.PayloadRef != "" {
			return ErrValidation
		}
		return nil
	}
	if p.TenantID != tenant || p.Digest != in.PayloadHash || p.Size != in.PayloadSize || p.MediaType != buildAttestationEvidenceMediaType || p.FinalKey == "" || p.Reference() != in.PayloadRef || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		return ErrValidation
	}
	if p.Status == PayloadStatusStaged && strings.TrimSpace(p.StagingKey) != "" || p.Status == PayloadStatusFinalized {
		return nil
	}
	return ErrValidation
}
