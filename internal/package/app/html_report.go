package app

import (
	"context"
	"html"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const CRAReadinessHTMLSnapshotVersion = "cra-readiness-html-snapshot.v1.0.0"

// CRAReadinessHTMLSnapshot is one committed, tenant-scoped report result. Its
// adapter obtains policy facts and limitations from the same read view.
type CRAReadinessHTMLSnapshot struct {
	SnapshotVersion string
	TenantID        string
	ProductID       string
	ReleaseID       string
	Result          string
	Limitations     []string
}

type HTMLReportReader interface {
	ReadCRAReadinessHTMLSnapshot(context.Context, identitydomain.Actor, string, string) (CRAReadinessHTMLSnapshot, error)
}

type HTMLReportTransaction interface {
	InsertHTMLReportPackage(context.Context, packagedomain.HTMLReportPackage) error
	application.Authorizer
	application.AuditAppender
}

type HTMLReportTransactions interface {
	ExecuteHTMLReport(context.Context, func(context.Context, HTMLReportTransaction) error) error
}

type ReportBytesHasher interface {
	HashPackageBytes(context.Context, []byte) (string, error)
}

type HTMLReportCommandConfig struct {
	Reader       HTMLReportReader
	Transactions HTMLReportTransactions
	Authorizer   application.Authorizer
	Hasher       ReportBytesHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}

// HTMLReportCommands generates and persists one escaped report and its audit
// entry. Its reader must use a committed, bounded view of the requested scope.
type HTMLReportCommands struct{ config HTMLReportCommandConfig }

func NewHTMLReportCommands(config HTMLReportCommandConfig) (*HTMLReportCommands, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &HTMLReportCommands{config: config}, nil
}

func (s *HTMLReportCommands) CRAReadinessHTMLPackage(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.HTMLReportPackage, error) {
	if s == nil {
		return packagedomain.HTMLReportPackage{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	if productID == "" {
		return packagedomain.HTMLReportPackage{}, ErrValidation
	}
	resources := application.ResourceReferences{ProductID: productID, ReleaseID: releaseID}
	request := application.AuthorizationRequest{Scope: ScopeReportRead, Resources: resources}
	if err := s.config.Authorizer.Authorize(ctx, actor, request); err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	snapshot, err := s.config.Reader.ReadCRAReadinessHTMLSnapshot(ctx, actor, productID, releaseID)
	if err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	snapshot = cloneCRAReadinessHTMLSnapshot(snapshot)
	if snapshot.TenantID != actor.TenantID || snapshot.ProductID != productID || snapshot.ReleaseID != releaseID {
		return packagedomain.HTMLReportPackage{}, ErrNotFound
	}
	if snapshot.SnapshotVersion != CRAReadinessHTMLSnapshotVersion || strings.TrimSpace(snapshot.Result) == "" {
		return packagedomain.HTMLReportPackage{}, ErrConflict
	}
	if len(snapshot.Result) > MaxGeneratedReportBytes {
		return packagedomain.HTMLReportPackage{}, ErrValidation
	}
	var body strings.Builder
	body.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>CRA readiness</title></head><body><h1>CRA readiness</h1><p>Result: ")
	body.WriteString(html.EscapeString(snapshot.Result))
	body.WriteString("</p><h2>Limitations</h2><ul>")
	for _, limitation := range snapshot.Limitations {
		if len(limitation) > MaxGeneratedReportBytes {
			return packagedomain.HTMLReportPackage{}, ErrValidation
		}
		body.WriteString("<li>")
		body.WriteString(html.EscapeString(limitation))
		body.WriteString("</li>")
		if body.Len() > MaxGeneratedReportBytes {
			return packagedomain.HTMLReportPackage{}, ErrValidation
		}
	}
	body.WriteString("</ul></body></html>")
	if body.Len() > MaxGeneratedReportBytes {
		return packagedomain.HTMLReportPackage{}, ErrValidation
	}
	htmlBody := body.String()
	hash, err := s.config.Hasher.HashPackageBytes(ctx, []byte(htmlBody))
	if err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	if strings.TrimSpace(hash) == "" {
		return packagedomain.HTMLReportPackage{}, ErrValidation
	}
	now := s.config.Clock.Now().UTC()
	report := packagedomain.HTMLReportPackage{
		ID: s.config.IDs.NewID("html"), TenantID: actor.TenantID, ReportType: "cra_readiness",
		ProductID: productID, ReleaseID: releaseID, HTML: htmlBody, Hash: hash,
		SchemaVersion: "html-report-package.v1.0.0", CreatedAt: now,
	}
	err = s.config.Transactions.ExecuteHTMLReport(ctx, func(ctx context.Context, tx HTMLReportTransaction) error {
		if err := tx.Authorize(ctx, actor, request); err != nil {
			return err
		}
		if err := tx.InsertHTMLReportPackage(ctx, report); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "html_report.generated", SubjectType: "html_report", SubjectID: report.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: now, PayloadHash: hash})
		return err
	})
	if err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	return report, nil
}

func (s *Service) CRAReadinessHTMLPackage(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.HTMLReportPackage, error) {
	commands, err := NewHTMLReportCommands(HTMLReportCommandConfig{Reader: serviceHTMLReportReader{s.reader}, Transactions: serviceHTMLReportTransactions{s.transactions}, Authorizer: s.authorizer, Hasher: s.canonicalizer, Clock: s.clock, IDs: s.ids})
	if err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	return commands.CRAReadinessHTMLPackage(ctx, actor, productID, releaseID)
}

type serviceHTMLReportReader struct{ reader Reader }

func (r serviceHTMLReportReader) ReadCRAReadinessHTMLSnapshot(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (CRAReadinessHTMLSnapshot, error) {
	return r.reader.ReadCommittedCRAReadinessHTMLSnapshot(ctx, actor.TenantID, productID, releaseID)
}

type serviceHTMLReportTransactions struct{ transactions TransactionRunner }

func (t serviceHTMLReportTransactions) ExecuteHTMLReport(ctx context.Context, command func(context.Context, HTMLReportTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, serviceHTMLReportTransaction{tx.Packages(), tx.Authorization(), tx.Audit()})
	})
}

type serviceHTMLReportTransaction struct {
	Repository
	application.Authorizer
	application.AuditAppender
}

func cloneCRAReadinessHTMLSnapshot(value CRAReadinessHTMLSnapshot) CRAReadinessHTMLSnapshot {
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}
