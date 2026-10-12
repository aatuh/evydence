package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func (f packageCoverageFixture) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}
func (f packageHandlingFixture) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

func (f packageUpdateFixture) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

func (f packageUpdateFixture) ReadSecurityUpdateSnapshot(ctx context.Context, tenant, product, release string) (packagequery.SecurityUpdateSnapshot, error) {
	if ctx == nil {
		return packagequery.SecurityUpdateSnapshot{}, packagequery.ErrSecurityUpdateValidation
	}
	if err := ctx.Err(); err != nil {
		return packagequery.SecurityUpdateSnapshot{}, err
	}
	var out packagequery.SecurityUpdateSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packagequery.SecurityUpdateReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadSecurityUpdateSnapshot(ctx, tenant, product, release)
		return err
	})
	if err != nil {
		return packagequery.SecurityUpdateSnapshot{}, err
	}
	return out, nil
}

func (f packageCoverageFixture) ReadControlCoverageSnapshot(ctx context.Context, tenant, framework, product, release string, at time.Time) (packagequery.ControlCoverageSnapshot, error) {
	if ctx == nil {
		return packagequery.ControlCoverageSnapshot{}, packagequery.ErrControlCoverageValidation
	}
	if err := ctx.Err(); err != nil {
		return packagequery.ControlCoverageSnapshot{}, err
	}
	var out packagequery.ControlCoverageSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packagequery.ControlCoverageReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadControlCoverageSnapshot(ctx, tenant, framework, product, release, at)
		return err
	})
	if err != nil {
		return packagequery.ControlCoverageSnapshot{}, err
	}
	return out, nil
}

func (f packageHandlingFixture) ReadCRAVulnerabilitySnapshot(ctx context.Context, tenant, product, release string, at time.Time) (packagequery.CRAVulnerabilitySnapshot, error) {
	if ctx == nil {
		return packagequery.CRAVulnerabilitySnapshot{}, packagequery.ErrCRAVulnerabilityValidation
	}
	if err := ctx.Err(); err != nil {
		return packagequery.CRAVulnerabilitySnapshot{}, err
	}
	var out packagequery.CRAVulnerabilitySnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Packages.(packagequery.CRAVulnerabilityReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadCRAVulnerabilitySnapshot(ctx, tenant, product, release, at)
		return err
	})
	if err != nil {
		return packagequery.CRAVulnerabilitySnapshot{}, err
	}
	return out, nil
}

func (s *Server) bindPackageReportFixtureClock(clock func() time.Time) {
	if f, ok := s.controlCoverageQuery.(packageCoverageFixture); ok {
		f.clock = clock
		s.controlCoverageQuery = f
	}
	if f, ok := s.craVulnerabilityQuery.(packageHandlingFixture); ok {
		f.clock = clock
		s.craVulnerabilityQuery = f
	}
	if f, ok := s.securityUpdateEvidenceQuery.(packageUpdateFixture); ok {
		f.clock = clock
		s.securityUpdateEvidenceQuery = f
	}
	if f, ok := s.releaseReadinessReportQuery.(packageReadinessFixtureQuery); ok {
		f.clock = clock
		s.releaseReadinessReportQuery = f
	}
	if f, ok := s.missingEvidenceQuery.(packageMissingFixture); ok {
		f.clock = clock
		s.missingEvidenceQuery = f
	}
}

var (
	_ packagequery.ControlCoverageReader  = packageCoverageFixture{}
	_ packagequery.CRAVulnerabilityReader = packageHandlingFixture{}
	_ packagequery.SecurityUpdateReader   = packageUpdateFixture{}
)
