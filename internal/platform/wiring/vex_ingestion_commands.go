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

func BuildVEXIngestionCommands(factory app.UnitOfWorkFactory, objects app.ObjectStore) (*evidenceapp.VEXIngestionCommands, error) {
	if factory == nil {
		return nil, errors.New("VEX ingestion transactions are required")
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
	clock := application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	return evidenceapp.NewVEXIngestionCommands(evidenceapp.VEXIngestionCommandConfig{Authorizer: auth, Transactions: vexIngestionTransactions{factory}, Parser: app.VEXPayloadParser{}, Objects: evidenceDocumentStager{objects, clock}, Payloads: evidenceCreationPayloadValidator{}, Canonicalizer: evidenceCanonicalHasher{}, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: application.IDGeneratorFunc(application.NewID)})
}

type vexIngestionTransactions struct{ factory app.UnitOfWorkFactory }

func (t vexIngestionTransactions) ExecuteVEXIngestion(ctx context.Context, fn func(context.Context, evidenceapp.VEXIngestionTransaction) error) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		tx, err := newEvidenceCreationTransaction(repos)
		if err != nil {
			return err
		}
		return fn(ctx, vexIngestionTransaction{tx})
	}))
}

type vexIngestionTransaction struct{ evidenceCreationTransaction }

func (t vexIngestionTransaction) InsertVEXDocument(ctx context.Context, v evidencedomain.VEXDocument) error {
	return mapEvidenceCreationError(t.evidence.InsertVEXDocument(ctx, domain.VEXDocumentFromContext(v)))
}
func (t vexIngestionTransaction) InsertVEXImportReport(ctx context.Context, v evidencedomain.VEXImportReport) error {
	return mapEvidenceCreationError(t.evidence.InsertVEXImportReport(ctx, domain.VEXImportReportFromContext(v)))
}
