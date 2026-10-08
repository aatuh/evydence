package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
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

// Only the explicitly synchronous, repository-free VEX characterization uses
// its immutable upload receipt as a reader fixture. The native query still
// validates tenant/identity/grants; its decision guard independently rechecks
// actual source and parent authority. Ordinary point routes require a repository.
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
