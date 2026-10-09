package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signatureFixtureTransactions struct {
	artifactSignatureFixture
	readOnly bool
}
type signatureFixtureTransaction struct {
	verificationapp.ArtifactSignatureCreationReader
	repos      app.Repositories
	authorizer application.Authorizer
	readOnly   bool
}

func (f signatureFixtureTransactions) ExecuteArtifactSignature(ctx context.Context, run func(context.Context, verificationapp.ArtifactSignatureTransaction) error) error {
	if ctx == nil || run == nil {
		return verificationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return signingFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.SupplyChain.(verificationapp.ArtifactSignatureCreationReader)
		grants, valid := r.SupplyChain.(releasequery.ArtifactPointReader)
		if !ok || !valid || r.Payloads == nil || r.Outbox == nil || r.Audit == nil {
			return app.ErrValidation
		}
		authorizer, err := releasequery.NewArtifactWriteAuthorizer(grants)
		if err != nil {
			return err
		}
		return run(ctx, signatureFixtureTransaction{reader, r, authorizer, f.readOnly})
	}))
}
func (t signatureFixtureTransaction) LockSignatureArtifact(ctx context.Context, tenant, id string) (verificationapp.SignatureArtifact, error) {
	if t.readOnly {
		panic("signature preflight selected artifact digest")
	}
	v, err := t.ArtifactSignatureCreationReader.LockSignatureArtifact(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t signatureFixtureTransaction) LockArtifactSignatureCreationScope(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	v, err := t.ArtifactSignatureCreationReader.LockArtifactSignatureCreationScope(ctx, tenant, id)
	return v, signingFixtureError(err)
}
func (t signatureFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, request application.AuthorizationRequest) error {
	err := t.authorizer.Authorize(ctx, a, request)
	if errors.Is(err, releasequery.ErrNotFound) {
		return verificationapp.ErrNotFound
	}
	if errors.Is(err, releasequery.ErrValidation) {
		return verificationapp.ErrValidation
	}
	return err
}
func (t signatureFixtureTransaction) InsertArtifactSignature(ctx context.Context, v verificationdomain.ArtifactSignature) error {
	if t.readOnly {
		panic("signature preflight inserted signature")
	}
	return signingFixtureError(t.repos.SupplyChain.InsertArtifactSignature(ctx, domain.ArtifactSignature(v)))
}
func (t signatureFixtureTransaction) RecordSignaturePayload(ctx context.Context, p verificationapp.SignaturePayload) error {
	if t.readOnly {
		panic("signature preflight recorded payload")
	}
	return signingFixtureError(t.repos.Payloads.RecordStagedObjectPayload(ctx, app.ObjectPayload{TenantID: p.TenantID, Digest: p.Digest, MediaType: p.MediaType, Size: p.Size, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: app.ObjectPayloadStaged, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}))
}
func (t signatureFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("signature preflight appended audit")
	}
	v, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
	return v, signingFixtureError(err)
}
func (t signatureFixtureTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	if t.readOnly {
		panic("signature preflight enqueued job")
	}
	return signingFixtureError(t.repos.Outbox.Enqueue(ctx, app.OutboxJob{ID: e.ID, TenantID: e.TenantID, Kind: e.Kind, SubjectType: e.SubjectType, SubjectID: e.SubjectID, Payload: e.Payload, CreatedAt: e.CreatedAt}))
}

type signatureFixturePayloadStager struct {
	objects  app.PayloadObjectStore
	readOnly bool
}

func (s signatureFixturePayloadStager) StageSignaturePayload(ctx context.Context, tenant, media, digest string, raw []byte, at time.Time) (verificationapp.SignaturePayload, error) {
	if s.readOnly {
		panic("signature preflight staged payload")
	}
	if s.objects == nil {
		return verificationapp.SignaturePayload{}, verificationapp.ErrConflict
	}
	source := app.BytesPayloadSource(raw)
	if source.Digest != digest {
		return verificationapp.SignaturePayload{}, verificationapp.ErrValidation
	}
	p, err := app.StageObjectPayload(ctx, s.objects, tenant, media, source, at)
	if err != nil {
		return verificationapp.SignaturePayload{}, signingFixtureError(err)
	}
	return verificationapp.SignaturePayload{TenantID: p.TenantID, Digest: p.Digest, MediaType: media, Size: p.Size, StagingKey: p.StagingKey, FinalKey: p.FinalKey, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}, nil
}

func (f artifactSignatureFixture) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	var out releasequery.ArtifactPoint
	if ctx == nil {
		return out, releasequery.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.SupplyChain.(releasequery.ArtifactPointReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.GetArtifactPoint(ctx, request)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}
func (f artifactSignatureFixture) nativeSignature(readOnly bool) (*verificationapp.ArtifactSignatureCommands, error) {
	authorizer, err := releasequery.NewArtifactWriteAuthorizer(f)
	if err != nil {
		return nil, err
	}
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return verificationapp.NewArtifactSignatureCommands(verificationapp.ArtifactSignatureConfig{Transactions: signatureFixtureTransactions{f, readOnly}, Authorizer: authorizer, Objects: signatureFixturePayloadStager{f.objects, readOnly}, Clock: clock, IDs: ids})
}
func signatureCreationFixtureError(err error) error {
	switch {
	case errors.Is(err, verificationapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, verificationapp.ErrValidation), errors.Is(err, releasequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, verificationapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, verificationapp.ErrForbidden), errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
func (s *Server) bindArtifactSignatureFixtureResources(objects app.PayloadObjectStore) {
	if f, ok := s.artifactSignatureCommands.(artifactSignatureFixture); ok {
		f.objects = objects
		s.artifactSignatureCommands = f
	}
}

func createFixtureArtifactSignature(ctx context.Context, ledger *app.Ledger, objects app.PayloadObjectStore, actor domain.Actor, input verificationapp.CreateArtifactSignatureInput) (domain.ArtifactSignature, error) {
	v, err := (artifactSignatureFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects}).CreateArtifactSignature(ctx, actor, input)
	return domain.ArtifactSignature(v), err
}

var _ verificationapp.ArtifactSignatureTransaction = signatureFixtureTransaction{}
