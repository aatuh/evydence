package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

var _ packagequery.ReleaseBundleReader = packageBundleReadFixture{}

func (f packageBundleReadFixture) GetReleaseBundlePoint(ctx context.Context, tenant, id string) (packagequery.ReleaseBundlePoint, error) {
	if ctx == nil {
		return packagequery.ReleaseBundlePoint{}, packagequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return packagequery.ReleaseBundlePoint{}, err
	}
	var out packagequery.ReleaseBundlePoint
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packagequery.ReleaseBundleReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.GetReleaseBundlePoint(ctx, tenant, id)
		return err
	})
	if err != nil {
		return packagequery.ReleaseBundlePoint{}, err
	}
	return out, nil
}
