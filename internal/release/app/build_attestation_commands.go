package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// BuildAttestationReader supplies only the parent/output identities and the
// immutable build snapshot needed to bind an uploaded attestation.
type BuildAttestationReader interface {
	BuildReader
	GetBuildRun(context.Context, string, string) (releasedomain.BuildRun, error)
}

// BuildAttestationTransaction commits the attestation, fixed-shape evidence
// capability, audit and parser job together. It exposes no unrelated context
// repositories. Reads must lock the current coordinates before any write.
type BuildAttestationTransaction interface {
	BuildAttestationReader
	BuildAttestationEvidenceWriter
	application.AuditAppender
	application.OutboxEnqueuer
	InsertBuildAttestation(context.Context, releasedomain.BuildAttestation) error
}

type BuildAttestationTransactionRunner interface {
	ExecuteBuildAttestation(context.Context, func(context.Context, BuildAttestationTransaction) error) error
}

type BuildAttestationCommandConfig struct {
	Reader             BuildAttestationReader
	Transactions       BuildAttestationTransactionRunner
	Authorizer         application.Authorizer
	AttestationParser  BuildAttestationParser
	PayloadStager      BuildAttestationPayloadStager
	WorkerOwnedParsers bool
	Clock              application.Clock
	IDs                application.IDGenerator
}

type BuildAttestationCommands struct {
	reader             BuildAttestationReader
	transactions       BuildAttestationTransactionRunner
	authorizer         application.Authorizer
	attestationParser  BuildAttestationParser
	payloadStager      BuildAttestationPayloadStager
	workerOwnedParsers bool
	clock              application.Clock
	ids                application.IDGenerator
}

func NewBuildAttestationCommands(config BuildAttestationCommandConfig) (*BuildAttestationCommands, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.AttestationParser == nil || config.PayloadStager == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &BuildAttestationCommands{
		reader: config.Reader, transactions: config.Transactions, authorizer: config.Authorizer,
		attestationParser: config.AttestationParser, payloadStager: config.PayloadStager,
		workerOwnedParsers: config.WorkerOwnedParsers, clock: config.Clock, ids: config.IDs,
	}, nil
}

// releaseBuildAttestationTransactions is only the legacy/local Service bridge.
// Durable composition must supply a focused runner directly; the production
// attestation binding remains transitional until those adapters are migrated.
type releaseBuildAttestationTransactions struct{ runner TransactionRunner }

func (r releaseBuildAttestationTransactions) ExecuteBuildAttestation(ctx context.Context, fn func(context.Context, BuildAttestationTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, releaseBuildAttestationTransaction{tx: tx})
	})
}

type releaseBuildAttestationTransaction struct{ tx Transaction }

func (t releaseBuildAttestationTransaction) GetProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	return t.tx.Catalog().GetProject(ctx, tenant, id)
}
func (t releaseBuildAttestationTransaction) GetRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	return t.tx.Catalog().GetRelease(ctx, tenant, id)
}
func (t releaseBuildAttestationTransaction) GetArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	return t.tx.Catalog().GetArtifact(ctx, tenant, id)
}
func (t releaseBuildAttestationTransaction) GetBuildRun(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	return t.tx.Builds().GetBuildRun(ctx, tenant, id)
}
func (t releaseBuildAttestationTransaction) WriteBuildAttestationEvidence(ctx context.Context, actor identitydomain.Actor, input BuildAttestationEvidenceInput) (BuildAttestationEvidenceReceipt, error) {
	return t.tx.BuildAttestationEvidence().WriteBuildAttestationEvidence(ctx, actor, input)
}
func (t releaseBuildAttestationTransaction) InsertBuildAttestation(ctx context.Context, value releasedomain.BuildAttestation) error {
	return t.tx.Builds().InsertBuildAttestation(ctx, value)
}
func (t releaseBuildAttestationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
func (t releaseBuildAttestationTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	return t.tx.Outbox().EnqueueOutbox(ctx, event)
}
