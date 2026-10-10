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

// Explicit consumers use the real flat creation service over current repositories,
// including deployment parents. This is not a runtime or cache compatibility port.
type evidenceCreationNativeFixture struct {
	catalogFixtureCommands
	repositories *app.Repositories
	readOnly     bool
}

func (f evidenceCreationNativeFixture) read(ctx context.Context, run func(context.Context, app.Repositories) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.repositories != nil {
		return run(ctx, *f.repositories)
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, run)
}
func (f evidenceCreationNativeFixture) ResolveEvidenceCreationScope(ctx context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
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
		return application.ResourceReferences{}, fixtureIngestionError(err)
	}
	return out, nil
}
func (f evidenceCreationNativeFixture) ValidateScope(ctx context.Context, tenant string, s evidenceapp.EvidenceScope) error {
	if s.AllowPendingDeployment {
		return evidenceapp.ErrValidation
	}
	_, err := f.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{ProductID: s.ProductID, ProjectID: s.ProjectID, ReleaseID: s.ReleaseID, BuildID: s.BuildID, DeploymentID: s.DeploymentID})
	return err
}
func (f evidenceCreationNativeFixture) artifactAuthority() repositoryIngestionFixtureAuthority {
	return repositoryIngestionFixtureAuthority{catalogFixtureCommands: f.catalogFixtureCommands, repositories: f.repositories}
}
func (f evidenceCreationNativeFixture) GetArtifactPoint(ctx context.Context, r releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return f.artifactAuthority().GetArtifactPoint(ctx, r)
}
func (f evidenceCreationNativeFixture) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	if f.readOnly {
		panic("evidence creation preflight read artifact metadata")
	}
	return fixtureIngestionError(f.artifactAuthority().ValidateArtifactReference(ctx, tenant, id, digest))
}
func (f evidenceCreationNativeFixture) ValidateArtifactIdentity(ctx context.Context, tenant, id string) error {
	return fixtureIngestionError(f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(interface {
			LockCreationArtifactIdentity(context.Context, string, string) error
		})
		if !ok {
			return app.ErrValidation
		}
		return reader.LockCreationArtifactIdentity(ctx, tenant, id)
	}))
}
func (f evidenceCreationNativeFixture) authorizer() (application.Authorizer, error) {
	artifacts, err := releasequery.NewArtifactWriteAuthorizer(f)
	if err != nil {
		return nil, err
	}
	return evidencequery.NewEvidenceCreationAuthorizer(f, artifacts)
}
func (f evidenceCreationNativeFixture) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	auth, err := f.authorizer()
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, a, r)
}
func (f evidenceCreationNativeFixture) ExecuteEvidenceCreation(ctx context.Context, run func(context.Context, evidenceapp.EvidenceCreationTransaction) error) error {
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
func (f evidenceCreationNativeFixture) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	if f.readOnly || f.repositories == nil {
		panic("evidence creation preflight/unbound insert")
	}
	return fixtureIngestionError(f.repositories.Evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(v)))
}
func (f evidenceCreationNativeFixture) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.readOnly || f.repositories == nil {
		panic("evidence creation preflight/unbound audit")
	}
	v, err := (governanceFixtureTransaction{audit: f.repositories.Audit}).AppendAudit(ctx, e)
	return v, fixtureIngestionError(err)
}
func (f evidenceCreationNativeFixture) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	if f.readOnly || f.repositories == nil {
		panic("evidence creation preflight/unbound outbox")
	}
	return fixtureIngestionError(f.repositories.Outbox.Enqueue(ctx, app.OutboxJob{ID: e.ID, TenantID: e.TenantID, Kind: e.Kind, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Payload: e.Payload, CreatedAt: e.CreatedAt}))
}
func nativeEvidenceFixturePayload(p evidenceapp.StagedPayload) app.ObjectPayload {
	return app.ObjectPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: app.ObjectPayloadStatus(p.Status), FailureCode: p.FailureCode, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, FinalizedAt: p.FinalizedAt, FailedAt: p.FailedAt, OrphanedAt: p.OrphanedAt}
}
func (f evidenceCreationNativeFixture) RecordStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	if f.readOnly || f.repositories == nil {
		panic("evidence creation preflight/unbound payload")
	}
	return fixtureIngestionError(f.repositories.Payloads.RecordStagedObjectPayload(ctx, nativeEvidenceFixturePayload(p)))
}
func (f evidenceCreationNativeFixture) ValidateStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	if f.readOnly {
		panic("evidence creation preflight inspected payload")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fixtureIngestionError(app.ValidateObjectPayloadForRepository(nativeEvidenceFixturePayload(p)))
}
func (f evidenceCreationNativeFixture) HashEvidence(ctx context.Context, v evidencedomain.EvidenceItem) (string, error) {
	if f.readOnly {
		panic("evidence creation preflight hashed")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(domain.EvidenceFromContextModel(evidencedomain.CanonicalEvidenceFields(v)))
}
func (f evidenceCreationNativeFixture) commands(readOnly bool) (*evidenceapp.EvidenceCreationCommands, error) {
	f.readOnly = readOnly
	auth, err := f.authorizer()
	if err != nil {
		return nil, err
	}
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return evidenceapp.NewEvidenceCreationCommands(evidenceapp.EvidenceCreationCommandConfig{Reader: f, Transactions: f, Authorizer: auth, Payloads: f, Canonicalizer: f, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: ids})
}
func (f evidenceCreationNativeFixture) AuthorizeEvidenceCreation(ctx context.Context, a domain.Actor, in evidenceapp.CreateEvidenceInput) error {
	c, err := f.commands(true)
	if err != nil {
		return err
	}
	return mapEvidenceCreationCommandError(c.AuthorizeEvidenceCreation(ctx, a, in))
}
func (f evidenceCreationNativeFixture) CreateEvidence(ctx context.Context, a domain.Actor, in evidenceapp.CreateEvidenceInput) (evidencedomain.EvidenceItem, error) {
	c, err := f.commands(false)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	v, err := c.CreateEvidence(ctx, a, in)
	return v, mapEvidenceCreationCommandError(err)
}

var _ EvidenceCreationCommands = evidenceCreationNativeFixture{}

// Preserve existing fixture setup inputs while creating through the focused
// service. This helper is test-only and never publishes a Ledger cache result.
func createEvidenceFixture(ctx context.Context, ledger *app.Ledger, actor domain.Actor, in app.CreateEvidenceInput) (domain.EvidenceItem, error) {
	refs := make([]evidencedomain.SubjectRef, 0, len(in.SubjectRefs))
	for _, ref := range in.SubjectRefs {
		refs = append(refs, evidencedomain.SubjectRef{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
	}
	p := in.StagedPayload
	input := evidenceapp.CreateEvidenceInput{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, DeploymentID: in.DeploymentID, Type: in.Type, Subtype: in.Subtype, Title: in.Title, SourceSystem: in.SourceSystem, SourceIdentity: in.SourceIdentity, CollectorID: in.CollectorID, ObservedAt: in.ObservedAt, PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash, PayloadMediaType: in.PayloadMediaType, PayloadSize: in.PayloadSize, SubjectRefs: refs, Metadata: in.Metadata, Tags: in.Tags, Limitations: in.Limitations, StagedPayload: evidenceapp.StagedPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: string(p.Status), FailureCode: p.FailureCode, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, FinalizedAt: p.FinalizedAt, FailedAt: p.FailedAt, OrphanedAt: p.OrphanedAt}}
	v, err := (evidenceCreationNativeFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}).CreateEvidence(ctx, actor, input)
	return domain.EvidenceFromContextModel(v), err
}
