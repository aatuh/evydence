package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/verification/dsse"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type BuildAttestationStorageReader interface {
	BuildStorageReader
	releaseapp.BuildAttestationSnapshotReader
}

func BuildBuildAttestationCommands(reader BuildAttestationStorageReader, factory app.UnitOfWorkFactory, objects app.ObjectStore, workerOwned bool) (*releaseapp.BuildAttestationCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("attestation reader and transactions are required")
	}
	auth, err := releasequery.NewBuildAttestationAuthorizer(buildArtifactGrants{reader})
	if err != nil {
		return nil, err
	}
	clock := application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	ids := application.IDGeneratorFunc(application.NewID)
	return releaseapp.NewBuildAttestationCommands(releaseapp.BuildAttestationCommandConfig{
		Reader: attestationBuildReader{buildParentReader{reader}, reader}, Transactions: attestationTransactions{factory, ids}, Authorizer: auth,
		AttestationParser: dsse.BuildAttestationIngestionParser{}, PayloadStager: attestationPayloadStager{objects, clock}, WorkerOwnedParsers: workerOwned, Clock: clock, IDs: ids,
	})
}

type attestationBuildReader struct {
	buildParentReader
	snapshots releaseapp.BuildAttestationSnapshotReader
}

func (r attestationBuildReader) GetBuildRun(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	v, err := r.snapshots.ReadBuildAttestationBuild(ctx, tenant, id)
	return v, mapAttestationWriteError(err)
}

type attestationTransactions struct {
	factory app.UnitOfWorkFactory
	ids     application.IDGenerator
}

func (t attestationTransactions) ExecuteBuildAttestation(ctx context.Context, fn func(context.Context, releaseapp.BuildAttestationTransaction) error) error {
	return mapAttestationWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		parents, ok := repos.ReleaseCatalog.(BuildStorageReader)
		builds, valid := repos.Builds.(releaseapp.BuildAttestationSnapshotReader)
		if !ok || !valid || repos.Builds == nil || repos.Evidence == nil || repos.Audit == nil || repos.Outbox == nil || repos.Payloads == nil {
			return app.ErrValidation
		}
		auth, err := releasequery.NewBuildAttestationAuthorizer(buildArtifactGrants{parents})
		if err != nil {
			return err
		}
		return fn(ctx, attestationTransaction{buildTransaction: buildTransaction{reader: parents, builds: repos.Builds, audit: repos.Audit}, snapshots: builds, evidence: repos.Evidence, payloads: repos.Payloads, outbox: repos.Outbox, authorizer: auth, ids: t.ids})
	}))
}

type attestationTransaction struct {
	buildTransaction
	snapshots  releaseapp.BuildAttestationSnapshotReader
	evidence   app.EvidenceRepository
	payloads   app.ObjectPayloadRepository
	outbox     app.OutboxRepository
	authorizer application.Authorizer
	ids        application.IDGenerator
}

func (t attestationTransaction) GetBuildRun(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	v, err := t.snapshots.ReadBuildAttestationBuild(ctx, tenant, id)
	return v, mapAttestationWriteError(err)
}
func (t attestationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	v, err := appendAuditEvent(ctx, t.audit, event)
	return v, mapAttestationWriteError(err)
}
func (t attestationTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	return mapAttestationWriteError(t.outbox.Enqueue(ctx, app.OutboxJob{ID: event.ID, TenantID: event.TenantID, Kind: event.Kind, SubjectType: event.SubjectType, SubjectID: event.SubjectID, Payload: event.Payload, CreatedAt: event.CreatedAt}))
}
func (t attestationTransaction) InsertBuildAttestation(ctx context.Context, v releasedomain.BuildAttestation) error {
	return mapAttestationWriteError(t.builds.InsertBuildAttestation(ctx, domain.BuildAttestation{ID: v.ID, TenantID: v.TenantID, BuildID: v.BuildID, EvidenceID: v.EvidenceID, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize, PayloadType: v.PayloadType, PredicateType: v.PredicateType, SubjectDigests: v.SubjectDigests, BuilderID: v.BuilderID, BuildType: v.BuildType, MaterialsCount: v.MaterialsCount, SignatureCount: v.SignatureCount, VerificationStatus: v.VerificationStatus, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t attestationTransaction) WriteBuildAttestationEvidence(ctx context.Context, a identitydomain.Actor, in releaseapp.BuildAttestationEvidenceInput) (releaseapp.BuildAttestationEvidenceReceipt, error) {
	w, err := evidenceapp.NewBuildAttestationEvidenceWriter(evidenceapp.BuildAttestationEvidenceConfig{Repository: attestationEvidenceRepository{t.evidence, t.reader}, Audit: t, Payloads: attestationEvidencePayloads{t.payloads}, Outbox: t, Canonicalizer: evidenceCanonicalHasher{}, Authorizer: t.authorizer, IDs: t.ids})
	if err != nil {
		return releaseapp.BuildAttestationEvidenceReceipt{}, mapAttestationWriteError(err)
	}
	refs := make([]evidencedomain.SubjectRef, 0, len(in.Subjects))
	for _, r := range in.Subjects {
		refs = append(refs, evidencedomain.SubjectRef{Type: r.Type, ID: r.ID, Digest: r.Digest})
	}
	id, err := w.WriteBuildAttestationEvidence(ctx, a, evidenceapp.BuildAttestationEvidenceInput{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, SourceSystem: in.SourceSystem, SourceIdentity: in.SourceIdentity, ObservedAt: in.ObservedAt, CreatedAt: in.ObservedAt, PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash, PayloadSize: in.PayloadSize, StagedPayload: attestationPayloadToEvidence(in.StagedPayload), Subjects: refs, ParserVersion: in.ParserVersion, PayloadType: in.PayloadType, PredicateType: in.PredicateType, SignatureCount: in.SignatureCount})
	if err != nil {
		return releaseapp.BuildAttestationEvidenceReceipt{}, mapAttestationWriteError(err)
	}
	return releaseapp.BuildAttestationEvidenceReceipt{EvidenceID: id}, nil
}

type attestationEvidenceRepository struct {
	repository app.EvidenceRepository
	reader     releaseapp.BuildIdentityReader
}

func (r attestationEvidenceRepository) ValidateScope(ctx context.Context, tenant string, s evidenceapp.EvidenceScope) error {
	return mapAttestationEvidenceError(r.repository.ValidateEvidenceScope(ctx, tenant, s.ProductID, s.ProjectID, s.ReleaseID, s.BuildID, ""))
}
func (r attestationEvidenceRepository) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	v, err := r.reader.ReadBuildArtifact(ctx, tenant, id)
	if err != nil {
		return mapAttestationEvidenceError(err)
	}
	if v.ID != id || v.TenantID != tenant {
		return evidenceapp.ErrNotFound
	}
	if v.Digest != digest {
		return evidenceapp.ErrValidation
	}
	return nil
}
func (r attestationEvidenceRepository) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	return mapAttestationEvidenceError(r.repository.InsertEvidence(ctx, domain.EvidenceFromContextModel(v)))
}

type attestationEvidencePayloads struct{ repository app.ObjectPayloadRepository }

func (r attestationEvidencePayloads) RecordStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	return mapAttestationEvidenceError(r.repository.RecordStagedObjectPayload(ctx, attestationEvidencePayloadToLegacy(p)))
}
func (r attestationEvidencePayloads) ValidateStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return mapAttestationEvidenceError(app.ValidateObjectPayloadForRepository(attestationEvidencePayloadToLegacy(p)))
}
func attestationEvidencePayloadToLegacy(p evidenceapp.StagedPayload) app.ObjectPayload {
	return app.ObjectPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: app.ObjectPayloadStatus(p.Status), FailureCode: p.FailureCode, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, FinalizedAt: p.FinalizedAt, FailedAt: p.FailedAt, OrphanedAt: p.OrphanedAt}
}
func attestationPayloadToEvidence(p releaseapp.StagedBuildAttestationPayload) evidenceapp.StagedPayload {
	return evidenceapp.StagedPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: p.Status, FailureCode: p.FailureCode, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, FinalizedAt: p.FinalizedAt, FailedAt: p.FailedAt, OrphanedAt: p.OrphanedAt}
}

type attestationPayloadStager struct {
	objects app.ObjectStore
	clock   application.Clock
}

func (s attestationPayloadStager) StageBuildAttestationPayload(ctx context.Context, tenant string, source releaseapp.BuildAttestationPayloadSource) (releaseapp.StagedBuildAttestationPayload, error) {
	if s.objects == nil {
		return releaseapp.StagedBuildAttestationPayload{}, nil
	}
	objects, ok := s.objects.(app.PayloadObjectStore)
	if !ok {
		return releaseapp.StagedBuildAttestationPayload{}, releaseapp.ErrConflict
	}
	p, err := app.StageObjectPayload(ctx, objects, tenant, releaseapp.BuildAttestationMediaType, app.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open}, s.clock.Now())
	if err != nil {
		return releaseapp.StagedBuildAttestationPayload{}, mapAttestationWriteError(err)
	}
	return releaseapp.StagedBuildAttestationPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Reference: p.Reference(), Status: string(p.Status), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}, nil
}

func mapAttestationWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation) || errors.Is(err, evidenceapp.ErrValidation) || errors.Is(err, releasequery.ErrValidation):
		return releaseapp.ErrValidation
	case errors.Is(err, app.ErrNotFound) || errors.Is(err, evidenceapp.ErrNotFound) || errors.Is(err, releasequery.ErrNotFound):
		return releaseapp.ErrNotFound
	case errors.Is(err, app.ErrConflict) || errors.Is(err, evidenceapp.ErrConflict):
		return releaseapp.ErrConflict
	default:
		return err
	}
}
func mapAttestationEvidenceError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return evidenceapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return evidenceapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return evidenceapp.ErrConflict
	default:
		return err
	}
}
