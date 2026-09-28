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

func (s *Service) CRAReadinessHTMLPackage(ctx context.Context, actor identitydomain.Actor, productID, releaseID string) (packagedomain.HTMLReportPackage, error) {
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
	if err := s.authorize(ctx, actor, ScopeReportRead, resources, false); err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	snapshot, err := s.reader.ReadCommittedCRAReadinessHTMLSnapshot(ctx, actor.TenantID, productID, releaseID)
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
	hash, err := s.canonicalizer.HashPackageBytes(ctx, []byte(htmlBody))
	if err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	if strings.TrimSpace(hash) == "" {
		return packagedomain.HTMLReportPackage{}, ErrValidation
	}
	now := s.clock.Now().UTC()
	report := packagedomain.HTMLReportPackage{
		ID: s.ids.NewID("html"), TenantID: actor.TenantID, ReportType: "cra_readiness",
		ProductID: productID, ReleaseID: releaseID, HTML: htmlBody, Hash: hash,
		SchemaVersion: "html-report-package.v1.0.0", CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, Resources: resources}); err != nil {
			return err
		}
		if err := tx.Packages().InsertHTMLReportPackage(ctx, report); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "html_report.generated", "html_report", report.ID, hash))
		return err
	})
	if err != nil {
		return packagedomain.HTMLReportPackage{}, err
	}
	return report, nil
}

func cloneCRAReadinessHTMLSnapshot(value CRAReadinessHTMLSnapshot) CRAReadinessHTMLSnapshot {
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}
