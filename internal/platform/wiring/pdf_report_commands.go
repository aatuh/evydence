package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func BuildPDFReportCommands(factory app.UnitOfWorkFactory, objects app.ObjectStore, production bool) (*packageapp.PDFReportCommands, error) {
	if factory == nil {
		return nil, errors.New("PDF report transactions are required")
	}
	var staged app.PayloadObjectStore
	if objects != nil {
		var ok bool
		staged, ok = objects.(app.PayloadObjectStore)
		if !ok {
			return nil, errors.New("PDF reports require transactional object staging")
		}
	} else if production {
		return nil, errors.New("production PDF reports require object storage")
	}
	return packageapp.NewPDFReportCommands(packageapp.PDFReportCommandConfig{Transactions: pdfReportTransactions{factory, staged}, Authorizer: packagequery.NewPDFReportAuthorizer(), Hasher: htmlReportBytesHasher{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type pdfReportRepository interface {
	packageapp.PDFReportReader
	InsertFocusedPDFReportPackage(context.Context, packagedomain.PDFReportPackage) error
}
type pdfReportTransactions struct {
	factory app.UnitOfWorkFactory
	objects app.PayloadObjectStore
}

func (t pdfReportTransactions) ExecutePDFReport(ctx context.Context, tenant string, fn func(context.Context, packageapp.PDFReportTransaction) error) error {
	return mapPackageAccessWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(pdfReportRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence || repos.Audit == nil || repos.Payloads == nil || repos.Outbox == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, pdfReportTransaction{r, t.objects, repos.Payloads, repos.Outbox, repos.Audit})
	}))
}

type pdfReportTransaction struct {
	pdfReportRepository
	objects  app.PayloadObjectStore
	payloads app.ObjectPayloadRepository
	outbox   app.OutboxRepository
	audit    app.AuditRepository
}

func (t pdfReportTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewPDFReportAuthorizer().Authorize(ctx, a, r)
}
func (t pdfReportTransaction) InsertPDFReportPackage(ctx context.Context, v packagedomain.PDFReportPackage) error {
	return mapPackageAccessWriteError(t.InsertFocusedPDFReportPackage(ctx, v))
}
func (t pdfReportTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return appendPackageAudit(ctx, t.audit, e)
}
func (t pdfReportTransaction) StagePDFReportPayload(ctx context.Context, tenant, digest string, raw []byte, at time.Time) (string, error) {
	if t.objects == nil {
		return "", nil
	}
	source := app.BytesPayloadSource(raw)
	if source.Digest != digest {
		return "", app.ErrValidation
	}
	p, err := app.StageObjectPayload(ctx, t.objects, tenant, "application/pdf", source, at)
	if err != nil {
		return "", err
	}
	if err := t.payloads.RecordStagedObjectPayload(ctx, p); err != nil {
		return "", err
	}
	err = t.outbox.Enqueue(ctx, app.OutboxJob{ID: application.NewID("job"), TenantID: tenant, Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: digest, Payload: map[string]any{"payload_digest": digest, "payload_lifecycle": app.PayloadLifecycleVersion}, CreatedAt: at})
	if err != nil {
		return "", err
	}
	return p.Reference(), nil
}
