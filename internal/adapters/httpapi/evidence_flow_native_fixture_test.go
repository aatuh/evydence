package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// A test-only composition of the actual focused query, current repository
// counts and an explicit clock; never an aggregate plan/count fallback.
type evidenceFlowFixture struct {
	catalogFixtureCommands
	clock application.Clock
}

func (f evidenceFlowFixture) Plan(ctx context.Context, actor domain.Actor, id string) (releasedomain.ReleaseEvidenceFlow, error) {
	clock := f.clock
	if clock == nil {
		clock = application.ClockFunc(time.Now)
	}
	query, err := releasequery.NewEvidenceFlows(f, releasequery.NewCatalogAuthorizer(), clock)
	if err != nil {
		return releasedomain.ReleaseEvidenceFlow{}, err
	}
	return query.Plan(ctx, actor, id)
}

func (f evidenceFlowFixture) ReadEvidenceFlowSnapshot(ctx context.Context, tenant, id string) (releasequery.EvidenceFlowSnapshot, error) {
	if ctx == nil {
		return releasequery.EvidenceFlowSnapshot{}, releasequery.ErrValidation
	}
	var out releasequery.EvidenceFlowSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(releasequery.EvidenceFlowReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadEvidenceFlowSnapshot(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasequery.EvidenceFlowSnapshot{}, err
	}
	return out, nil
}

func (s *Server) bindEvidenceFlowFixtureClock(clock application.Clock) {
	if f, ok := s.evidenceFlowQuery.(evidenceFlowFixture); ok {
		f.clock = clock
		s.evidenceFlowQuery = f
	}
}

var (
	_ EvidenceFlowQuery               = evidenceFlowFixture{}
	_ releasequery.EvidenceFlowReader = evidenceFlowFixture{}
)
