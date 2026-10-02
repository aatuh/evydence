package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func BuildArtifactSignatureCommands(reader releasequery.ArtifactPointReader, factory app.UnitOfWorkFactory, objects app.ObjectStore) (*verificationapp.ArtifactSignatureCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("artifact signature reader and transactions are required")
	}
	authorizer, err := releasequery.NewArtifactWriteAuthorizer(reader)
	if err != nil {
		return nil, err
	}
	return verificationapp.NewArtifactSignatureCommands(verificationapp.ArtifactSignatureConfig{Transactions: artifactSignatureTransactions{factory}, Authorizer: authorizer, Objects: signaturePayloadStager{objects}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type artifactSignatureTransactions struct{ factory app.UnitOfWorkFactory }

func (t artifactSignatureTransactions) ExecuteArtifactSignature(ctx context.Context, fn func(context.Context, verificationapp.ArtifactSignatureTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.SupplyChain.(verificationapp.ArtifactSignatureCreationReader)
		grants, valid := repos.SupplyChain.(releasequery.ArtifactPointReader)
		if !ok || !valid || repos.Payloads == nil || repos.Outbox == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		auth, err := releasequery.NewArtifactWriteAuthorizer(grants)
		if err != nil {
			return err
		}
		return fn(ctx, artifactSignatureTransaction{reader, auth, repos.SupplyChain, repos.Payloads, repos.Audit, repos.Outbox})
	}))
}

type artifactSignatureTransaction struct {
	reader     verificationapp.ArtifactSignatureCreationReader
	authorizer application.Authorizer
	supply     app.SupplyChainRepository
	payloads   app.ObjectPayloadRepository
	audit      app.AuditRepository
	outbox     app.OutboxRepository
}

func (t artifactSignatureTransaction) LockSignatureArtifact(ctx context.Context, tenant, id string) (verificationapp.SignatureArtifact, error) {
	a, err := t.reader.LockSignatureArtifact(ctx, tenant, id)
	return a, mapSigningKeyWriteError(err)
}
func (t artifactSignatureTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return mapArtifactSignatureGrantError(t.authorizer.Authorize(ctx, a, r))
}
func mapArtifactSignatureGrantError(err error) error {
	if errors.Is(err, releasequery.ErrNotFound) {
		return verificationapp.ErrNotFound
	}
	if errors.Is(err, releasequery.ErrValidation) {
		return verificationapp.ErrValidation
	}
	return err
}
func (t artifactSignatureTransaction) InsertArtifactSignature(ctx context.Context, v verificationdomain.ArtifactSignature) error {
	return mapSigningKeyWriteError(t.supply.InsertArtifactSignature(ctx, domain.ArtifactSignature{ID: v.ID, TenantID: v.TenantID, ArtifactID: v.ArtifactID, SubjectDigest: v.SubjectDigest, Algorithm: v.Algorithm, KeyID: v.KeyID, Signature: v.Signature, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, VerificationStatus: v.VerificationStatus, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func signaturePayloadToLegacy(p verificationapp.SignaturePayload) app.ObjectPayload {
	return app.ObjectPayload{TenantID: p.TenantID, Digest: p.Digest, MediaType: p.MediaType, Size: p.Size, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: app.ObjectPayloadStaged, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}
func (t artifactSignatureTransaction) RecordSignaturePayload(ctx context.Context, p verificationapp.SignaturePayload) error {
	return mapSigningKeyWriteError(t.payloads.RecordStagedObjectPayload(ctx, signaturePayloadToLegacy(p)))
}
func (t artifactSignatureTransaction) AppendAudit(ctx context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, a)
	return r, mapSigningKeyWriteError(err)
}
func (t artifactSignatureTransaction) EnqueueOutbox(ctx context.Context, j application.OutboxEvent) error {
	return (verificationReceiptWriter{outbox: t.outbox}).EnqueueOutbox(ctx, j)
}

type signaturePayloadStager struct{ objects app.ObjectStore }

func (s signaturePayloadStager) StageSignaturePayload(ctx context.Context, tenant, media, digest string, raw []byte, at time.Time) (verificationapp.SignaturePayload, error) {
	objects, ok := s.objects.(app.PayloadObjectStore)
	if !ok {
		return verificationapp.SignaturePayload{}, verificationapp.ErrConflict
	}
	source := app.BytesPayloadSource(raw)
	if source.Digest != digest {
		return verificationapp.SignaturePayload{}, verificationapp.ErrValidation
	}
	p, err := app.StageObjectPayload(ctx, objects, tenant, media, source, at)
	if err != nil {
		return verificationapp.SignaturePayload{}, mapSigningKeyWriteError(err)
	}
	return verificationapp.SignaturePayload{TenantID: p.TenantID, Digest: p.Digest, MediaType: media, Size: p.Size, StagingKey: p.StagingKey, FinalKey: p.FinalKey, CreatedAt: at, UpdatedAt: p.UpdatedAt}, nil
}
