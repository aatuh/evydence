package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// Native query policies and current repository rows supply every point. This
// test-only bridge keeps historical application error assertions unchanged.
func legacyParsedPointError(err error) error {
	switch {
	case errors.Is(err, evidencequery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, evidencequery.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, evidencequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}

func parsedFixtureRead[T any](ctx context.Context, f catalogFixtureCommands, read func(context.Context, app.Repositories) (T, error)) (T, error) {
	var zero, out T
	if ctx == nil {
		return zero, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		var err error
		out, err = read(ctx, r)
		return err
	})
	if err != nil {
		return zero, err
	}
	return out, nil
}

func (f evidenceReadFixture) GetSBOMPoint(ctx context.Context, tenant, id string) (evidencequery.SBOMPoint, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (evidencequery.SBOMPoint, error) {
		reader, ok := r.Evidence.(evidencequery.SBOMPointReader)
		if !ok {
			return evidencequery.SBOMPoint{}, app.ErrValidation
		}
		return reader.GetSBOMPoint(ctx, tenant, id)
	})
}

func (f evidenceReadFixture) GetEvidencePoint(ctx context.Context, tenant, id string, guard evidencequery.EvidenceReadGuard) (evidencequery.EvidencePoint, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (evidencequery.EvidencePoint, error) {
		reader, ok := r.Evidence.(evidencequery.EvidencePointReader)
		if !ok {
			return evidencequery.EvidencePoint{}, app.ErrValidation
		}
		return reader.GetEvidencePoint(ctx, tenant, id, guard)
	})
}

func (f evidencePageFixture) PageEvidence(ctx context.Context, request evidencequery.EvidencePageRequest, guard evidencequery.EvidenceReadGuard) (appquery.Result[evidencequery.EvidencePoint], error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (appquery.Result[evidencequery.EvidencePoint], error) {
		reader, ok := r.Evidence.(evidencequery.EvidencePageReader)
		if !ok {
			return appquery.Result[evidencequery.EvidencePoint]{}, app.ErrValidation
		}
		return reader.PageEvidence(ctx, request, guard)
	})
}

// Preserve historical DTO comparisons through the native query, not caches.
func readFixtureEvidence(ctx context.Context, ledger *app.Ledger, actor domain.Actor, id string) (domain.EvidenceItem, error) {
	value, err := (evidenceReadFixture{catalogFixtureCommands{ledger: ledger}}).GetEvidence(ctx, actor, id)
	return domain.EvidenceFromContextModel(value), err
}

func (f sbomComponentsFixture) PageSBOMComponents(ctx context.Context, request evidencequery.SBOMComponentPageRequest) (appquery.Result[evidencequery.SBOMComponentPoint], error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (appquery.Result[evidencequery.SBOMComponentPoint], error) {
		reader, ok := r.Evidence.(evidencequery.SBOMComponentReader)
		if !ok {
			return appquery.Result[evidencequery.SBOMComponentPoint]{}, app.ErrValidation
		}
		return reader.PageSBOMComponents(ctx, request)
	})
}

func (f lifecyclePageFixture) PageLifecycleEvents(ctx context.Context, tenant, id string, request appquery.PageRequest, after *appquery.SortKey, guard evidencequery.EvidenceReadGuard) (evidencequery.LifecyclePage, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (evidencequery.LifecyclePage, error) {
		reader, ok := r.Evidence.(evidencequery.LifecycleEventReader)
		if !ok {
			return evidencequery.LifecyclePage{}, app.ErrValidation
		}
		return reader.PageLifecycleEvents(ctx, tenant, id, request, after, guard)
	})
}

func (f evidenceReadFixture) GetVulnerabilityScanPoint(ctx context.Context, tenant, id string) (evidencequery.VulnerabilityScanPoint, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (evidencequery.VulnerabilityScanPoint, error) {
		reader, ok := r.Evidence.(evidencequery.VulnerabilityScanPointReader)
		if !ok {
			return evidencequery.VulnerabilityScanPoint{}, app.ErrValidation
		}
		return reader.GetVulnerabilityScanPoint(ctx, tenant, id)
	})
}

func (f evidenceReadFixture) GetOpenAPIContractPoint(ctx context.Context, tenant, id string) (evidencequery.OpenAPIContractPoint, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (evidencequery.OpenAPIContractPoint, error) {
		reader, ok := r.Evidence.(evidencequery.OpenAPIContractPointReader)
		if !ok {
			return evidencequery.OpenAPIContractPoint{}, app.ErrValidation
		}
		return reader.GetOpenAPIContractPoint(ctx, tenant, id)
	})
}

func (f evidenceReadFixture) GetVEXDocumentPoint(ctx context.Context, tenant, id string) (evidencequery.VEXDocumentPoint, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (evidencequery.VEXDocumentPoint, error) {
		reader, ok := r.Evidence.(evidencequery.VEXPointReader)
		if !ok {
			return evidencequery.VEXDocumentPoint{}, app.ErrValidation
		}
		return reader.GetVEXDocumentPoint(ctx, tenant, id)
	})
}

func (f evidenceReadFixture) GetVEXImportReportPoint(ctx context.Context, tenant, id string) (evidencequery.VEXImportReportPoint, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (evidencequery.VEXImportReportPoint, error) {
		reader, ok := r.Evidence.(evidencequery.VEXPointReader)
		if !ok {
			return evidencequery.VEXImportReportPoint{}, app.ErrValidation
		}
		return reader.GetVEXImportReportPoint(ctx, tenant, id)
	})
}

// The synchronous repository-free VEX characterization supplies only its real
// immutable upload receipt. These readers model receipt identity/provenance,
// not a current storage snapshot. The decision guard rechecks owned parents.
type immutableScanReceiptFixture struct {
	point evidencequery.VulnerabilityScanPoint
}

func (f immutableScanReceiptFixture) GetVulnerabilityScanPoint(ctx context.Context, tenant, id string) (evidencequery.VulnerabilityScanPoint, error) {
	if err := ctx.Err(); err != nil {
		return evidencequery.VulnerabilityScanPoint{}, err
	}
	if f.point.Scan.TenantID != tenant || f.point.Scan.ID != id {
		return evidencequery.VulnerabilityScanPoint{}, evidencequery.ErrNotFound
	}
	return f.point, nil
}

func (f immutableScanReceiptFixture) GetEvidencePoint(ctx context.Context, tenant, id string, guard evidencequery.EvidenceReadGuard) (evidencequery.EvidencePoint, error) {
	var empty evidencequery.EvidencePoint
	if ctx == nil || guard == nil {
		return empty, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	scan := f.point.Scan
	if scan.TenantID != tenant || scan.EvidenceID != id {
		return empty, evidencequery.ErrNotFound
	}
	source := domain.EvidenceItem{ID: id, TenantID: tenant, ProductID: f.point.ProductID, ReleaseID: scan.ReleaseID, Type: "vulnerability_scan"}
	if err := guard(application.ResourceReferences{ProductID: source.ProductID, ReleaseID: source.ReleaseID}); err != nil {
		return empty, err
	}
	if app.ValidateWorkerEvidenceRecord(source, vulnerabilityScanFromQuery(scan)) != nil {
		return empty, evidencequery.ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return evidencequery.EvidencePoint{Item: evidencedomain.EvidenceItem{ID: id, TenantID: tenant, ProductID: source.ProductID, ReleaseID: source.ReleaseID, Type: source.Type}, ProductID: source.ProductID, ReleaseID: source.ReleaseID, WorkerProjectionValidated: true}, nil
}

func TestImmutableScanReceiptSourceRequiresMatchingIdentityAndWorkerCoherence(t *testing.T) {
	reader := immutableScanReceiptFixture{point: evidencequery.VulnerabilityScanPoint{ProductID: "product", Scan: evidencedomain.VulnerabilityScan{ID: "scan", TenantID: "tenant", EvidenceID: "source", ReleaseID: "release", Scanner: "generic", Adapter: "generic", AdapterVersion: "generic.v1", SourceSchema: "generic.v1", TargetRef: "pkg:generic/api@1", Findings: []evidencedomain.VulnerabilityFinding{{ID: "finding", Vulnerability: "CVE-fixture"}}, CreatedAt: time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)}}}
	query, err := evidencequery.NewEvidencePoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{"evidence:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:read"}}}}
	item, err := query.GetEvidence(t.Context(), actor, "source")
	if err != nil || item.ID != "source" || item.Type != "vulnerability_scan" || item.ProductID != "product" || item.ReleaseID != "release" {
		t.Fatal("receipt source lost known immutable identity", item, err)
	}
	for _, id := range []string{"missing", "scan"} {
		if item, err := query.GetEvidence(t.Context(), actor, id); !errors.Is(err, evidencequery.ErrNotFound) || item.ID != "" {
			t.Fatal("receipt reader accepted a different source identity", item, err)
		}
	}
	denied := actor
	denied.ResourceGrants = nil
	if _, err := query.GetEvidence(t.Context(), denied, "source"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("receipt reader bypassed current actor grants", err)
	}
	denied = actor
	denied.TenantID = "foreign"
	if _, err := query.GetEvidence(t.Context(), denied, "source"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatal("receipt reader crossed tenants", err)
	}
	reader.point.Scan.Findings = append(reader.point.Scan.Findings, reader.point.Scan.Findings[0])
	query, err = evidencequery.NewEvidencePoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	if item, err := query.GetEvidence(t.Context(), actor, "source"); !errors.Is(err, evidencequery.ErrConflict) || item.ID != "" {
		t.Fatal("corrupt receipt was marked as validated provenance", item, err)
	}
	denied = actor
	denied.ResourceGrants = nil
	if _, err := query.GetEvidence(t.Context(), denied, "source"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("receipt provenance was inspected before authorization", err)
	}
}
