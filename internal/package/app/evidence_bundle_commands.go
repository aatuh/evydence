package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type EvidenceBundleSnapshotReader interface {
	ReadEvidenceBundleSnapshot(context.Context, string, string, time.Time) (EvidenceBundleSnapshot, error)
}
type ExportTransaction interface {
	AuthorizeEvidenceBundleSelection(context.Context, identitydomain.Actor, application.ResourceReferences, []EvidenceBundleEvidence) error
	InsertEvidenceBundleSignature(context.Context, PackageSignature, string) error
	InsertEvidenceBundle(context.Context, packagedomain.EvidenceBundle) error
	application.AuditAppender
}
type ExportTransactions interface {
	ExecuteEvidenceBundleExport(context.Context, func(context.Context, ExportTransaction) error) error
}
type ExportCommandConfig struct {
	Reader       EvidenceBundleSnapshotReader
	Transactions ExportTransactions
	Authorizer   application.Authorizer
	Hasher       ManifestHasher
	Signer       PackageSigner
	Clock        application.Clock
	IDs          application.IDGenerator
}

// ExportCommands exports evidence references from one bounded committed view.
// Persistence rechecks selection ownership and signing validity atomically.
type ExportCommands struct{ config ExportCommandConfig }

func NewExportCommands(config ExportCommandConfig) (*ExportCommands, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Signer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ExportCommands{config}, nil
}
func (s *Service) ExportEvidenceBundle(ctx context.Context, actor identitydomain.Actor, releaseID string, evidenceIDs []string) (packagedomain.EvidenceBundle, error) {
	commands, err := NewExportCommands(ExportCommandConfig{Reader: serviceExportReader{s}, Transactions: serviceExportTransactions{s.transactions}, Authorizer: s.authorizer, Hasher: s.canonicalizer, Signer: s.signer, Clock: s.clock, IDs: s.ids})
	if err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	return commands.ExportEvidenceBundle(ctx, actor, releaseID, evidenceIDs)
}

type serviceExportReader struct{ service *Service }

func (r serviceExportReader) ReadEvidenceBundleSnapshot(ctx context.Context, tenantID, releaseID string, _ time.Time) (EvidenceBundleSnapshot, error) {
	if refresher := r.service.projectionRefresher; refresher != nil {
		if err := refresher.RefreshPackageProjection(ctx, tenantID); err != nil {
			return EvidenceBundleSnapshot{}, err
		}
	}
	return r.service.reader.ReadCommittedEvidenceBundleSnapshot(ctx, tenantID, releaseID)
}

type serviceExportTransactions struct{ transactions TransactionRunner }

func (t serviceExportTransactions) ExecuteEvidenceBundleExport(ctx context.Context, command func(context.Context, ExportTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error { return command(ctx, serviceExportTransaction{tx}) })
}

type serviceExportTransaction struct{ Transaction }

func (t serviceExportTransaction) AuthorizeEvidenceBundleSelection(ctx context.Context, actor identitydomain.Actor, root application.ResourceReferences, selected []EvidenceBundleEvidence) error {
	if root.ReleaseID != "" {
		if err := t.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: root}); err != nil {
			return err
		}
	}
	for _, item := range selected {
		if err := t.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: item.Resources}); err != nil {
			return err
		}
	}
	return nil
}
func (t serviceExportTransaction) InsertEvidenceBundleSignature(ctx context.Context, signature PackageSignature, _ string) error {
	return t.Signatures().InsertPackageSignature(ctx, signature)
}
func (t serviceExportTransaction) InsertEvidenceBundle(ctx context.Context, bundle packagedomain.EvidenceBundle) error {
	return t.Packages().InsertEvidenceBundle(ctx, bundle)
}
func (t serviceExportTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.Audit().AppendAudit(ctx, event)
}
