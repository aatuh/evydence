package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func BuildSecurityDocumentCommands(factory app.UnitOfWorkFactory, objects app.ObjectStore) (*evidenceapp.SecurityDocumentCommands, error) {
	if factory == nil {
		return nil, errors.New("security document transactions are required")
	}
	reads := evidenceCreationReads{factory}
	artifacts, err := releasequery.NewArtifactSecurityWriteAuthorizer(reads)
	if err != nil {
		return nil, err
	}
	auth, err := evidencequery.NewSecurityDocumentAuthorizer(reads, artifacts)
	if err != nil {
		return nil, err
	}
	clock := application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	return evidenceapp.NewSecurityDocumentCommands(evidenceapp.SecurityDocumentCommandConfig{Authorizer: auth, Transactions: securityDocumentTransactions{factory}, Objects: securityDocumentObjects{evidenceDocumentStager{objects, clock}, evidenceCreationPayloadValidator{}}, Canonicalizer: evidenceCanonicalHasher{}, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: application.IDGeneratorFunc(application.NewID)})
}

type securityDocumentObjects struct {
	evidenceDocumentStager
	evidenceCreationPayloadValidator
}

func (s securityDocumentObjects) StagePayload(ctx context.Context, tenant, media, digest string, raw []byte) (evidenceapp.StagedPayload, error) {
	source := evidenceapp.BytesPayloadSource(raw)
	if source.Digest != digest {
		return evidenceapp.StagedPayload{}, evidenceapp.ErrValidation
	}
	return s.StagePayloadSource(ctx, tenant, media, source)
}

type securityDocumentRepository interface {
	InsertSecurityScan(context.Context, domain.SecurityScan) error
	InsertManualSecurityDocument(context.Context, domain.ManualSecurityDocument) error
}
type securityDocumentTransactions struct{ factory app.UnitOfWorkFactory }

func (t securityDocumentTransactions) ExecuteSecurityDocument(ctx context.Context, fn func(context.Context, evidenceapp.SecurityDocumentTransaction) error) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		tx, err := newEvidenceCreationTransaction(repos)
		if err != nil {
			return err
		}
		if repos.Risk == nil {
			return app.ErrValidation
		}
		artifacts, err := releasequery.NewArtifactSecurityWriteAuthorizer(creationArtifactGrants{tx.artifacts})
		if err != nil {
			return err
		}
		tx.Authorizer, err = evidencequery.NewSecurityDocumentAuthorizer(tx.scopes, artifacts)
		if err != nil {
			return err
		}
		return fn(ctx, securityDocumentTransaction{tx, repos.Risk})
	}))
}

type securityDocumentTransaction struct {
	evidenceCreationTransaction
	documents securityDocumentRepository
}

func (t securityDocumentTransaction) InsertSecurityScan(ctx context.Context, v evidencedomain.SecurityScan) error {
	return mapEvidenceCreationError(t.documents.InsertSecurityScan(ctx, domain.SecurityScanFromContext(v)))
}
func (t securityDocumentTransaction) InsertManualSecurityDocument(ctx context.Context, v evidencedomain.ManualSecurityDocument) error {
	return mapEvidenceCreationError(t.documents.InsertManualSecurityDocument(ctx, domain.ManualSecurityDocumentFromContext(v)))
}
