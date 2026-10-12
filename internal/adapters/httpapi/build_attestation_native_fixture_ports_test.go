package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/adapters/verification/dsse"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type buildAttestationFixtureFacts interface {
	releaseapp.BuildAttestationSnapshotReader
	releaseapp.BuildAttestationCreationGuardReader
}
type buildAttestationNativeFixture struct {
	releaseWorkflowNativeFixture
	objects app.ObjectStore
}

func (f buildAttestationNativeFixture) Authorize(ctx context.Context, actor domain.Actor, r application.AuthorizationRequest) error {
	auth, err := releasequery.NewBuildAttestationAuthorizer(f)
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, actor, r)
}
func (f buildAttestationNativeFixture) buildFacts(ctx context.Context, run func(context.Context, buildAttestationFixtureFacts) error) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		facts, ok := r.Builds.(buildAttestationFixtureFacts)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, facts)
	})
}
func (f buildAttestationNativeFixture) GetBuildRun(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	if f.readOnly {
		panic("attestation replay read immutable build metadata")
	}
	var v releasedomain.BuildRun
	err := f.buildFacts(ctx, func(ctx context.Context, r buildAttestationFixtureFacts) error {
		var err error
		v, err = r.ReadBuildAttestationBuild(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	return v, nil
}
func (f buildAttestationNativeFixture) ReadBuildAttestationCreationScope(ctx context.Context, tenant, id string) (releaseapp.BuildAttestationCreationCoordinates, error) {
	var v releaseapp.BuildAttestationCreationCoordinates
	err := f.buildFacts(ctx, func(ctx context.Context, r buildAttestationFixtureFacts) error {
		var err error
		v, err = r.ReadBuildAttestationCreationScope(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releaseapp.BuildAttestationCreationCoordinates{}, err
	}
	return v, nil
}
func (f buildAttestationNativeFixture) ExecuteBuildAttestation(ctx context.Context, run func(context.Context, releaseapp.BuildAttestationTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, bound releaseWorkflowNativeFixture) error {
		if _, ok := bound.repositories.Builds.(buildAttestationFixtureFacts); !ok || bound.repositories.Evidence == nil || bound.repositories.Payloads == nil || bound.repositories.Outbox == nil {
			return app.ErrValidation
		}
		current := f
		current.releaseWorkflowNativeFixture = bound
		return run(ctx, current)
	})
}
func (f buildAttestationNativeFixture) InsertBuildAttestation(ctx context.Context, v releasedomain.BuildAttestation) error {
	if f.readOnly || f.repositories == nil {
		panic("attestation replay/unbound insert")
	}
	return releaseFixtureCoreError(f.repositories.Builds.InsertBuildAttestation(ctx, domain.BuildAttestation{ID: v.ID, TenantID: v.TenantID, BuildID: v.BuildID, EvidenceID: v.EvidenceID, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize, PayloadType: v.PayloadType, PredicateType: v.PredicateType, SubjectDigests: v.SubjectDigests, BuilderID: v.BuilderID, BuildType: v.BuildType, MaterialsCount: v.MaterialsCount, SignatureCount: v.SignatureCount, VerificationStatus: v.VerificationStatus, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (f buildAttestationNativeFixture) evidencePorts() evidenceCreationNativeFixture {
	return evidenceCreationNativeFixture{catalogFixtureCommands: f.catalogFixtureCommands, repositories: f.repositories, readOnly: f.readOnly}
}
func (f buildAttestationNativeFixture) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return f.evidencePorts().EnqueueOutbox(ctx, e)
}
func (f buildAttestationNativeFixture) WriteBuildAttestationEvidence(ctx context.Context, actor domain.Actor, in releaseapp.BuildAttestationEvidenceInput) (releaseapp.BuildAttestationEvidenceReceipt, error) {
	if f.readOnly || f.repositories == nil {
		panic("attestation replay/unbound evidence capability")
	}
	ports := f.evidencePorts()
	_, _, ids := f.nativeCatalog(false)
	w, err := evidenceapp.NewBuildAttestationEvidenceWriter(evidenceapp.BuildAttestationEvidenceConfig{Repository: ports, Audit: ports, Payloads: ports, Outbox: ports, Canonicalizer: ports, Authorizer: f, IDs: ids})
	if err != nil {
		return releaseapp.BuildAttestationEvidenceReceipt{}, err
	}
	refs := make([]evidencedomain.SubjectRef, 0, len(in.Subjects))
	for _, r := range in.Subjects {
		refs = append(refs, evidencedomain.SubjectRef{Type: r.Type, ID: r.ID, Digest: r.Digest})
	}
	p := in.StagedPayload
	id, err := w.WriteBuildAttestationEvidence(ctx, actor, evidenceapp.BuildAttestationEvidenceInput{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, SourceSystem: in.SourceSystem, SourceIdentity: in.SourceIdentity, ObservedAt: in.ObservedAt, CreatedAt: in.ObservedAt, PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash, PayloadSize: in.PayloadSize, StagedPayload: evidenceapp.StagedPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: p.Status, FailureCode: p.FailureCode, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, FinalizedAt: p.FinalizedAt, FailedAt: p.FailedAt, OrphanedAt: p.OrphanedAt}, Subjects: refs, ParserVersion: in.ParserVersion, PayloadType: in.PayloadType, PredicateType: in.PredicateType, SignatureCount: in.SignatureCount})
	if err != nil {
		return releaseapp.BuildAttestationEvidenceReceipt{}, releaseFixtureCoreError(mapEvidenceCreationCommandError(err))
	}
	return releaseapp.BuildAttestationEvidenceReceipt{EvidenceID: id}, nil
}
func (f buildAttestationNativeFixture) StageBuildAttestationPayload(ctx context.Context, tenant string, source releaseapp.BuildAttestationPayloadSource) (releaseapp.StagedBuildAttestationPayload, error) {
	if f.readOnly {
		panic("attestation replay staged payload")
	}
	if ctx == nil {
		return releaseapp.StagedBuildAttestationPayload{}, releaseapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releaseapp.StagedBuildAttestationPayload{}, err
	}
	if f.objects == nil {
		return releaseapp.StagedBuildAttestationPayload{}, nil
	}
	objects, ok := f.objects.(app.PayloadObjectStore)
	if !ok {
		return releaseapp.StagedBuildAttestationPayload{}, releaseapp.ErrConflict
	}
	p, err := app.StageObjectPayload(ctx, objects, tenant, releaseapp.BuildAttestationMediaType, app.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open}, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return releaseapp.StagedBuildAttestationPayload{}, releaseFixtureCoreError(err)
	}
	return releaseapp.StagedBuildAttestationPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, Reference: p.Reference(), StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: string(p.Status), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}, nil
}
func (f lifecycleFixtureCommands) nativeAttestation(readOnly bool) (*releaseapp.BuildAttestationCommands, error) {
	return f.nativeAttestationWithObjects(readOnly, nil)
}
func (f lifecycleFixtureCommands) nativeAttestationWithObjects(readOnly bool, objects app.ObjectStore) (*releaseapp.BuildAttestationCommands, error) {
	ports, clock, ids := f.nativeWorkflow(readOnly, "build")
	bound := buildAttestationNativeFixture{releaseWorkflowNativeFixture: ports, objects: objects}
	return releaseapp.NewBuildAttestationCommands(releaseapp.BuildAttestationCommandConfig{Reader: bound, Transactions: bound, Authorizer: bound, AttestationParser: dsse.BuildAttestationIngestionParser{}, PayloadStager: bound, Clock: clock, IDs: ids})
}
