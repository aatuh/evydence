package wiring

import (
	"context"
	"errors"
	"strings"
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

// BuildEvidenceCreationCommands composes generic creation using bounded reads
// and a flat transaction. Initial checks join an enclosing replay/compound UoW
// when present, so pending parents are visible without Ledger publication.
func BuildEvidenceCreationCommands(factory app.UnitOfWorkFactory) (*evidenceapp.EvidenceCreationCommands, error) {
	if factory == nil {
		return nil, errors.New("evidence creation transactions are required")
	}
	reads := evidenceCreationReads{factory}
	artifacts, err := releasequery.NewArtifactWriteAuthorizer(reads)
	if err != nil {
		return nil, err
	}
	auth, err := evidencequery.NewEvidenceCreationAuthorizer(reads, artifacts)
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewEvidenceCreationCommands(evidenceapp.EvidenceCreationCommandConfig{
		Reader: reads, Transactions: evidenceCreationTransactions{factory}, Authorizer: auth,
		Payloads: evidenceCreationPayloadValidator{}, Canonicalizer: evidenceCanonicalHasher{},
		CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion,
		Clock:                   application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type evidenceCreationPayloadValidator struct{}

func (evidenceCreationPayloadValidator) ValidateStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	if ctx == nil {
		return evidenceapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return mapEvidenceCreationError(app.ValidateObjectPayloadForRepository(attestationEvidencePayloadToLegacy(p)))
}

type evidenceCreationArtifactReader interface {
	ReadBuildArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}

type evidenceCreationReads struct{ factory app.UnitOfWorkFactory }

func (r evidenceCreationReads) ResolveEvidenceCreationScope(ctx context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	var resolved application.ResourceReferences
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Evidence.(evidencequery.EvidenceCreationScopeReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		resolved, err = reader.ResolveEvidenceCreationScope(ctx, tenant, refs)
		return err
	})
	return resolved, mapEvidenceCreationError(err)
}
func (r evidenceCreationReads) ValidateScope(ctx context.Context, tenant string, s evidenceapp.EvidenceScope) error {
	if s.AllowPendingDeployment {
		return evidenceapp.ErrValidation
	}
	_, err := r.ResolveEvidenceCreationScope(ctx, tenant, evidenceCreationRefs(s))
	return err
}
func (r evidenceCreationReads) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(evidenceCreationArtifactReader)
		if !ok {
			return app.ErrValidation
		}
		return validateCreationArtifact(ctx, reader, tenant, id, digest)
	}))
}
func (r evidenceCreationReads) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var point releasequery.ArtifactPoint
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.ReleaseCatalog.(evidenceCreationArtifactReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		point, err = reader.ReadBuildArtifactGrant(ctx, request)
		return err
	})
	return point, err
}
func evidenceCreationRefs(s evidenceapp.EvidenceScope) application.ResourceReferences {
	return application.ResourceReferences{ProductID: s.ProductID, ProjectID: s.ProjectID, ReleaseID: s.ReleaseID, BuildID: s.BuildID, DeploymentID: s.DeploymentID}
}
func validateCreationArtifact(ctx context.Context, reader evidenceCreationArtifactReader, tenant, id, digest string) error {
	v, err := reader.ReadBuildArtifact(ctx, tenant, id)
	if err != nil {
		return mapEvidenceCreationError(err)
	}
	if v.TenantID != tenant || v.ID != id || digest != "" && !strings.EqualFold(v.Digest, digest) {
		return evidenceapp.ErrNotFound
	}
	return nil
}

type evidenceCreationTransactions struct{ factory app.UnitOfWorkFactory }

func (r evidenceCreationTransactions) ExecuteEvidenceCreation(ctx context.Context, fn func(context.Context, evidenceapp.EvidenceCreationTransaction) error) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		tx, err := newEvidenceCreationTransaction(repos)
		if err != nil {
			return err
		}
		return fn(ctx, tx)
	}))
}

func newEvidenceCreationTransaction(repos app.Repositories) (evidenceCreationTransaction, error) {
	scopes, ok := repos.Evidence.(evidencequery.EvidenceCreationScopeReader)
	artifacts, valid := repos.ReleaseCatalog.(evidenceCreationArtifactReader)
	if !ok || !valid || repos.Audit == nil || repos.Payloads == nil || repos.Outbox == nil {
		return evidenceCreationTransaction{}, app.ErrValidation
	}
	artifactPolicy, err := releasequery.NewArtifactWriteAuthorizer(creationArtifactGrants{artifacts})
	if err != nil {
		return evidenceCreationTransaction{}, err
	}
	auth, err := evidencequery.NewEvidenceCreationAuthorizer(scopes, artifactPolicy)
	if err != nil {
		return evidenceCreationTransaction{}, err
	}
	return evidenceCreationTransaction{Authorizer: auth, scopes: scopes, artifacts: artifacts, evidence: repos.Evidence, audit: repos.Audit, payloads: repos.Payloads, outbox: repos.Outbox}, nil
}

type creationArtifactGrants struct {
	reader evidenceCreationArtifactReader
}

func (r creationArtifactGrants) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return r.reader.ReadBuildArtifactGrant(ctx, request)
}

type evidenceCreationTransaction struct {
	application.Authorizer
	scopes    evidencequery.EvidenceCreationScopeReader
	artifacts evidenceCreationArtifactReader
	evidence  app.EvidenceRepository
	audit     app.AuditRepository
	payloads  app.ObjectPayloadRepository
	outbox    app.OutboxRepository
}

func (t evidenceCreationTransaction) ValidateScope(ctx context.Context, tenant string, s evidenceapp.EvidenceScope) error {
	if s.AllowPendingDeployment {
		return evidenceapp.ErrValidation
	}
	_, err := t.scopes.ResolveEvidenceCreationScope(ctx, tenant, evidenceCreationRefs(s))
	return mapEvidenceCreationError(err)
}
func (t evidenceCreationTransaction) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	return validateCreationArtifact(ctx, t.artifacts, tenant, id, digest)
}
func (t evidenceCreationTransaction) ValidateArtifactIdentity(ctx context.Context, tenant, id string) error {
	r, ok := t.evidence.(interface {
		LockCreationArtifactIdentity(context.Context, string, string) error
	})
	if !ok {
		return evidenceapp.ErrValidation
	}
	return mapEvidenceCreationError(r.LockCreationArtifactIdentity(ctx, tenant, id))
}
func (t evidenceCreationTransaction) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	return mapEvidenceCreationError(t.evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(v)))
}
func (t evidenceCreationTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := appendAuditEvent(ctx, t.audit, e)
	return v, mapEvidenceCreationError(err)
}
func (t evidenceCreationTransaction) RecordStagedPayload(ctx context.Context, p evidenceapp.StagedPayload) error {
	return mapEvidenceCreationError(t.payloads.RecordStagedObjectPayload(ctx, attestationEvidencePayloadToLegacy(p)))
}
func (t evidenceCreationTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	return mapEvidenceCreationError(t.outbox.Enqueue(ctx, app.OutboxJob{ID: e.ID, TenantID: e.TenantID, Kind: e.Kind, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Payload: e.Payload, CreatedAt: e.CreatedAt}))
}
func mapEvidenceCreationError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation) || errors.Is(err, evidencequery.ErrValidation) || errors.Is(err, releasequery.ErrValidation):
		return evidenceapp.ErrValidation
	case errors.Is(err, app.ErrNotFound) || errors.Is(err, evidencequery.ErrNotFound) || errors.Is(err, releasequery.ErrNotFound):
		return evidenceapp.ErrNotFound
	case errors.Is(err, app.ErrConflict) || errors.Is(err, evidencequery.ErrConflict):
		return evidenceapp.ErrConflict
	default:
		return err
	}
}
