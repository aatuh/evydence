package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func (f packageReadinessFixtureQuery) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

func (f packageMissingFixture) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

func (f packageReadinessFixtureQuery) ReadReleaseReadinessReportSnapshot(ctx context.Context, tenant, release string, at time.Time) (packagequery.ReleaseReadinessReportSnapshot, error) {
	if ctx == nil {
		return packagequery.ReleaseReadinessReportSnapshot{}, packagequery.ErrReleaseReadinessValidation
	}
	if err := ctx.Err(); err != nil {
		return packagequery.ReleaseReadinessReportSnapshot{}, err
	}
	var out packagequery.ReleaseReadinessReportSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packagequery.ReleaseReadinessReportReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadReleaseReadinessReportSnapshot(ctx, tenant, release, at)
		return err
	})
	if err != nil {
		return packagequery.ReleaseReadinessReportSnapshot{}, err
	}
	return out, nil
}

func (f packageMissingFixture) ReadReleaseReadinessSnapshot(ctx context.Context, tenant, release string) (riskapp.ReadinessSnapshot, error) {
	if ctx == nil {
		return riskapp.ReadinessSnapshot{}, riskapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return riskapp.ReadinessSnapshot{}, err
	}
	var out riskapp.ReadinessSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Decisions.(interface {
			ReadReleaseReadinessSnapshotAt(context.Context, string, string, time.Time) (riskapp.ReadinessSnapshot, error)
		})
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadReleaseReadinessSnapshotAt(ctx, tenant, release, f.now())
		return err
	})
	if err != nil {
		return riskapp.ReadinessSnapshot{}, err
	}
	return out, nil
}

var (
	_ packagequery.ReleaseReadinessReportReader = packageReadinessFixtureQuery{}
	_ riskquery.ReleaseReadinessReader          = packageMissingFixture{}
)
