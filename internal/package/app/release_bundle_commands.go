package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type ReleaseBundleTransaction interface {
	InsertReleaseBundle(context.Context, packagedomain.ReleaseBundle) error
	InsertReleaseBundleSignature(context.Context, PackageSignature, string) error
	application.Authorizer
	application.AuditAppender
	application.OutboxEnqueuer
}
type ReleaseBundleTransactions interface {
	ExecuteReleaseBundle(context.Context, func(context.Context, ReleaseBundleTransaction) error) error
}
type ReleaseBundleCommandConfig struct {
	Reader       ReleaseBundleSnapshotReader
	Transactions ReleaseBundleTransactions
	Authorizer   application.Authorizer
	Hasher       ManifestHasher
	Signer       PackageSigner
	Clock        application.Clock
	IDs          application.IDGenerator
}

// ReleaseBundleCommands needs only committed manifest inputs, hashing/signing
// adapters and one transaction for its bundle, signature, audit and worker job.
type ReleaseBundleCommands struct{ config ReleaseBundleCommandConfig }

func NewReleaseBundleCommands(config ReleaseBundleCommandConfig) (*ReleaseBundleCommands, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Signer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ReleaseBundleCommands{config}, nil
}
func (s *Service) CreateReleaseBundle(ctx context.Context, actor identitydomain.Actor, releaseID string) (packagedomain.ReleaseBundle, error) {
	commands, err := NewReleaseBundleCommands(ReleaseBundleCommandConfig{Reader: serviceReleaseBundleReader{s}, Transactions: serviceReleaseBundleTransactions{s.transactions}, Authorizer: s.authorizer, Hasher: s.canonicalizer, Signer: s.signer, Clock: s.clock, IDs: s.ids})
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	return commands.CreateReleaseBundle(ctx, actor, releaseID)
}

type serviceReleaseBundleReader struct{ service *Service }

func (r serviceReleaseBundleReader) ReadReleaseBundleSnapshot(ctx context.Context, tenantID, releaseID string, _ time.Time) (ReleaseBundleSnapshot, error) {
	if refresher := r.service.projectionRefresher; refresher != nil {
		if err := refresher.RefreshPackageProjection(ctx, tenantID); err != nil {
			return ReleaseBundleSnapshot{}, err
		}
	}
	return r.service.reader.ReadCommittedReleaseBundleSnapshot(ctx, tenantID, releaseID)
}

type serviceReleaseBundleTransactions struct{ transactions TransactionRunner }

func (t serviceReleaseBundleTransactions) ExecuteReleaseBundle(ctx context.Context, command func(context.Context, ReleaseBundleTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, serviceReleaseBundleTransaction{tx.Packages(), tx.Signatures(), tx.Authorization(), tx.Audit(), tx.Outbox()})
	})
}

type serviceReleaseBundleTransaction struct {
	Repository
	PackageSignatureRepository
	application.Authorizer
	application.AuditAppender
	application.OutboxEnqueuer
}

func (t serviceReleaseBundleTransaction) InsertReleaseBundleSignature(ctx context.Context, signature PackageSignature, _ string) error {
	return t.InsertPackageSignature(ctx, signature)
}
