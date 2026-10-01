package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type ManifestHasher interface {
	HashPackageManifest(context.Context, map[string]any) (string, error)
}

type ImportTransaction interface {
	InsertEvidenceBundleImport(context.Context, packagedomain.EvidenceBundleImport) error
	application.Authorizer
	application.AuditAppender
}

type ImportTransactions interface {
	ExecuteBundleImport(context.Context, func(context.Context, ImportTransaction) error) error
}

type ImportCommandConfig struct {
	Transactions ImportTransactions
	Authorizer   application.Authorizer
	Hasher       ManifestHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}

// ImportCommands validates the portable manifest and records a local receipt.
// It does not dereference evidence, ingest payloads, or establish signature
// trust. The receipt and its audit entry commit through one narrow transaction.
type ImportCommands struct{ config ImportCommandConfig }

func NewImportCommands(config ImportCommandConfig) (*ImportCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ImportCommands{config}, nil
}

func (s *Service) ImportEvidenceBundle(ctx context.Context, actor identitydomain.Actor, bundle packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	commands, err := NewImportCommands(ImportCommandConfig{Transactions: serviceImportTransactions{s.transactions}, Authorizer: s.authorizer, Hasher: s.canonicalizer, Clock: s.clock, IDs: s.ids})
	if err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	return commands.ImportEvidenceBundle(ctx, actor, bundle)
}

type serviceImportTransactions struct{ transactions TransactionRunner }

func (t serviceImportTransactions) ExecuteBundleImport(ctx context.Context, command func(context.Context, ImportTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, serviceImportTransaction{tx.Packages(), tx.Authorization(), tx.Audit()})
	})
}

type serviceImportTransaction struct {
	Repository
	application.Authorizer
	application.AuditAppender
}
