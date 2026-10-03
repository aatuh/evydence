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

func BuildSBOMIngestionCommands(factory app.UnitOfWorkFactory, objects app.ObjectStore, workerOwned bool) (*evidenceapp.SBOMIngestionCommands, error) {
	if factory == nil {
		return nil, errors.New("SBOM ingestion transactions are required")
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
	return evidenceapp.NewSBOMIngestionCommands(evidenceapp.SBOMIngestionCommandConfig{Authorizer: auth, Transactions: sbomIngestionTransactions{factory}, Parser: app.SBOMPayloadParser{}, Objects: evidenceDocumentStager{objects, clock}, Payloads: evidenceCreationPayloadValidator{}, Canonicalizer: evidenceCanonicalHasher{}, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: application.IDGeneratorFunc(application.NewID), WorkerOwnedParsers: workerOwned})
}

type sbomIngestionTransactions struct{ factory app.UnitOfWorkFactory }

func (t sbomIngestionTransactions) ExecuteSBOMIngestion(ctx context.Context, fn func(context.Context, evidenceapp.SBOMIngestionTransaction) error) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		tx, err := newEvidenceCreationTransaction(repos)
		if err != nil {
			return err
		}
		return fn(ctx, sbomIngestionTransaction{tx})
	}))
}

type sbomIngestionTransaction struct{ evidenceCreationTransaction }

func (t sbomIngestionTransaction) InsertSBOM(ctx context.Context, v evidencedomain.SBOM) error {
	return mapEvidenceCreationError(t.evidence.InsertSBOM(ctx, domain.SBOMFromContext(v)))
}
