package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func BuildEvidenceSummaryCommands(factory app.UnitOfWorkFactory) (*packageapp.EvidenceSummaryCommands, error) {
	if factory == nil {
		return nil, errors.New("evidence summary transactions are required")
	}
	return packageapp.NewEvidenceSummaryCommands(packageapp.EvidenceSummaryCommandConfig{Transactions: summaryTransactions{factory}, Authorizer: packagequery.NewEvidenceSummaryAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type summaryTransactions struct{ factory app.UnitOfWorkFactory }

func (t summaryTransactions) ExecuteEvidenceSummary(ctx context.Context, tenant string, fn func(context.Context, packageapp.EvidenceSummaryTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Future.(packageapp.EvidenceSummaryReader)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		// Preflight may reuse the HTTP replay transaction. Acquire the shared
		// worker/audit fence and tenant lock before any root/evidence row locks.
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, summaryTransaction{reader: reader, future: repos.Future, audit: repos.Audit})
	}))
}

type summaryTransaction struct {
	reader packageapp.EvidenceSummaryReader
	future app.FutureExtensionsRepository
	audit  app.AuditRepository
}

func (t summaryTransaction) ReadEvidenceSummaryScope(ctx context.Context, tenant, kind, id string) (packageapp.EvidenceSummaryScope, error) {
	v, err := t.reader.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	return v, mapPackageAccessWriteError(err)
}
func (t summaryTransaction) ReadEvidenceSummaryItems(ctx context.Context, scope packageapp.EvidenceSummaryScope, ids []string) ([]packageapp.EvidenceSummaryItem, error) {
	v, err := t.reader.ReadEvidenceSummaryItems(ctx, scope, ids)
	return v, mapPackageAccessWriteError(err)
}
func (t summaryTransaction) InsertEvidenceSummary(ctx context.Context, v packagedomain.EvidenceSummary) error {
	citations := make([]domain.EvidenceCitation, len(v.Citations))
	for i, c := range v.Citations {
		citations[i] = domain.EvidenceCitation{EvidenceID: c.EvidenceID, Type: c.Type, Title: c.Title, CanonicalHash: c.CanonicalHash}
	}
	return mapPackageAccessWriteError(t.future.InsertEvidenceSummary(ctx, domain.EvidenceSummary{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, EvidenceIDs: v.EvidenceIDs, Summary: v.Summary, Citations: citations, Assumptions: v.Assumptions, Limitations: v.Limitations, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t summaryTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewEvidenceSummaryAuthorizer().Authorize(ctx, a, r)
}
func (t summaryTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
