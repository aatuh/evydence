package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type releaseSummaryNativeFixture struct {
	catalogFixtureCommands
	clock func() time.Time
}

func (f releaseSummaryNativeFixture) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}
func (f releaseSummaryNativeFixture) Summary(ctx context.Context, a domain.Actor, release string) (riskdomain.ReleaseSecuritySummary, error) {
	query, err := riskquery.NewReleaseSecuritySummary(f, f.now)
	if err != nil {
		return riskdomain.ReleaseSecuritySummary{}, err
	}
	return query.Summary(ctx, a, release)
}
func (f releaseSummaryNativeFixture) ReadReleaseSecuritySummarySnapshot(ctx context.Context, tenant, release string) (riskquery.ReleaseSecuritySummarySnapshot, error) {
	if ctx == nil {
		return riskquery.ReleaseSecuritySummarySnapshot{}, riskquery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return riskquery.ReleaseSecuritySummarySnapshot{}, err
	}
	var out riskquery.ReleaseSecuritySummarySnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Decisions.(interface {
			ReadReleaseSecuritySummarySnapshotAt(context.Context, string, string, time.Time) (riskquery.ReleaseSecuritySummarySnapshot, error)
		})
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadReleaseSecuritySummarySnapshotAt(ctx, tenant, release, f.now())
		return err
	})
	if err != nil {
		return riskquery.ReleaseSecuritySummarySnapshot{}, err
	}
	return out, nil
}
func (s *Server) bindReleaseSummaryFixtureClock(clock func() time.Time) {
	if f, ok := s.releaseSecuritySummaryQuery.(releaseSummaryNativeFixture); ok {
		f.clock = clock
		s.releaseSecuritySummaryQuery = f
	}
}

var _ ReleaseSecuritySummaryQuery = releaseSummaryNativeFixture{}
var _ riskquery.ReleaseSecuritySummaryReader = releaseSummaryNativeFixture{}
