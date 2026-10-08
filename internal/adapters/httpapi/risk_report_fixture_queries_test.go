package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Test-only composition of the actual Package query and current repository
// counts; no aggregate report/cache fallback or implicit aggregate clock.
type riskReportFixture struct {
	catalogFixtureCommands
	clock func() time.Time
}

func (f riskReportFixture) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

func (f riskReportFixture) Report(ctx context.Context, a domain.Actor, release string) (packagedomain.VulnerabilityPostureReport, error) {
	query, err := packagequery.NewVulnerabilityPosture(f, f.now)
	if err != nil {
		return packagedomain.VulnerabilityPostureReport{}, err
	}
	return query.Report(ctx, a, release)
}
func (f riskReportFixture) ReadVulnerabilityPosture(ctx context.Context, tenant, release string) (packagequery.VulnerabilityPosturePoint, error) {
	if ctx == nil {
		return packagequery.VulnerabilityPosturePoint{}, packagequery.ErrPostureValidation
	}
	if err := ctx.Err(); err != nil {
		return packagequery.VulnerabilityPosturePoint{}, err
	}
	var out packagequery.VulnerabilityPosturePoint
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packagequery.VulnerabilityPostureReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadVulnerabilityPosture(ctx, tenant, release)
		return err
	})
	if err != nil {
		return packagequery.VulnerabilityPosturePoint{}, err
	}
	return out, nil
}
func (s *Server) bindRiskReportFixtureQueries(ledger *app.Ledger) {
	commands := catalogFixtureCommands{ledger: ledger}
	if query, fixture := s.releaseSecuritySummaryQuery.(releaseSummaryNativeFixture); s.releaseSecuritySummaryQuery == nil || fixture {
		query.catalogFixtureCommands = commands
		s.releaseSecuritySummaryQuery = query
	}
	if query, fixture := s.vulnerabilityPostureQuery.(riskReportFixture); s.vulnerabilityPostureQuery == nil || fixture {
		query.catalogFixtureCommands = commands
		s.vulnerabilityPostureQuery = query
	}
}

func (s *Server) bindVulnerabilityPostureFixtureClock(clock func() time.Time) {
	if f, ok := s.vulnerabilityPostureQuery.(riskReportFixture); ok {
		f.clock = clock
		s.vulnerabilityPostureQuery = f
	}
}

var (
	_ VulnerabilityPostureQuery               = riskReportFixture{}
	_ packagequery.VulnerabilityPostureReader = riskReportFixture{}
)
