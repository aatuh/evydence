package postgres

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Native fixture composition stays in this outer adapter test binary. Importing
// the full runtime wiring here would cycle back to the PostgreSQL adapter.
// No Ledger methods, maps, snapshot writes or publication participate in ingest.
type sbomIngestionFixture struct {
	store        *Store
	objects      app.PayloadObjectStore
	repositories *app.Repositories
	clock        application.Clock
}
type sbomFixtureArtifactReader interface {
	ReadBuildArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}

func newSBOMIngestionFixture(store *Store, objects app.PayloadObjectStore) (*evidenceapp.SBOMIngestionCommands, error) {
	if store == nil || objects == nil {
		return nil, app.ErrValidation
	}
	clock := application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	f := sbomIngestionFixture{store: store, objects: objects, clock: clock}
	return evidenceapp.NewSBOMIngestionCommands(evidenceapp.SBOMIngestionCommandConfig{Authorizer: f, Transactions: f, Parser: app.SBOMPayloadParser{}, Objects: f, Payloads: f, Canonicalizer: f, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: application.IDGeneratorFunc(application.NewID)})
}
func (f sbomIngestionFixture) read(ctx context.Context, run func(context.Context, app.Repositories) error) error {
	if f.repositories != nil {
		return run(ctx, *f.repositories)
	}
	return app.ExecuteUnitOfWork(ctx, f.store, run)
}
func (f sbomIngestionFixture) ExecuteSBOMIngestion(ctx context.Context, run func(context.Context, evidenceapp.SBOMIngestionTransaction) error) error {
	return app.ExecuteUnitOfWork(ctx, f.store, func(ctx context.Context, r app.Repositories) error {
		if r.Evidence == nil || r.Audit == nil || r.Outbox == nil || r.Payloads == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	})
}
func (f sbomIngestionFixture) ResolveEvidenceCreationScope(ctx context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	var out application.ResourceReferences
	err := f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidencequery.EvidenceCreationScopeReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ResolveEvidenceCreationScope(ctx, tenant, refs)
		return err
	})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return out, nil
}
func (f sbomIngestionFixture) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var out releasequery.ArtifactPoint
	err := f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(sbomFixtureArtifactReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}
func (f sbomIngestionFixture) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	artifacts, err := releasequery.NewArtifactWriteAuthorizer(f)
	if err != nil {
		return err
	}
	auth, err := evidencequery.NewEvidenceCreationAuthorizer(f, artifacts)
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, a, r)
}
func (f sbomIngestionFixture) ValidateScope(ctx context.Context, tenant string, s evidenceapp.EvidenceScope) error {
	if s.AllowPendingDeployment {
		return app.ErrValidation
	}
	_, err := f.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{ProductID: s.ProductID, ProjectID: s.ProjectID, ReleaseID: s.ReleaseID, BuildID: s.BuildID, DeploymentID: s.DeploymentID})
	return err
}
func (f sbomIngestionFixture) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	return f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(sbomFixtureArtifactReader)
		if !ok {
			return app.ErrValidation
		}
		v, err := reader.ReadBuildArtifact(ctx, tenant, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != tenant || digest != "" && v.Digest != digest {
			return app.ErrNotFound
		}
		return nil
	})
}
func (f sbomIngestionFixture) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	return f.repositories.Evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(v))
}
func (f sbomIngestionFixture) InsertSBOM(ctx context.Context, v evidencedomain.SBOM) error {
	return f.repositories.Evidence.InsertSBOM(ctx, domain.SBOMFromContext(v))
}
func (f sbomIngestionFixture) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := f.repositories.Audit.Append(ctx, domain.AuditChainEntry{ID: e.ID, TenantID: e.TenantID, EntryType: e.EntryType, SubjectType: e.SubjectType, SubjectID: e.SubjectID, ActorType: e.ActorType, ActorID: e.ActorID, OccurredAt: e.OccurredAt, PayloadHash: e.PayloadHash, SignatureRef: e.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	if err != nil {
		return application.AuditReceipt{}, err
	}
	return application.AuditReceipt{ID: v.ID}, nil
}
func (f sbomIngestionFixture) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return f.repositories.Outbox.Enqueue(ctx, app.OutboxJob{ID: e.ID, TenantID: e.TenantID, Kind: e.Kind, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Payload: e.Payload, CreatedAt: e.CreatedAt})
}
func sbomFixturePayload(p evidenceapp.StagedPayload) app.ObjectPayload {
	return app.ObjectPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: app.ObjectPayloadStatus(p.Status), FailureCode: p.FailureCode, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, FinalizedAt: p.FinalizedAt, FailedAt: p.FailedAt, OrphanedAt: p.OrphanedAt}
}
func (f sbomIngestionFixture) RecordStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	return f.repositories.Payloads.RecordStagedObjectPayload(ctx, sbomFixturePayload(p))
}
func (f sbomIngestionFixture) ValidateStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return app.ValidateObjectPayloadForRepository(sbomFixturePayload(p))
}
func (f sbomIngestionFixture) StagePayloadSource(ctx context.Context, tenant, media string, source evidenceapp.PayloadSource) (evidenceapp.StagedPayload, error) {
	p, err := app.StageObjectPayload(ctx, f.objects, tenant, media, app.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open}, f.clock.Now())
	if err != nil {
		return evidenceapp.StagedPayload{}, err
	}
	return evidenceapp.StagedPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: string(p.Status), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}, nil
}
func (f sbomIngestionFixture) HashEvidence(ctx context.Context, v evidencedomain.EvidenceItem) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(domain.EvidenceFromContextModel(evidencedomain.CanonicalEvidenceFields(v)))
}
