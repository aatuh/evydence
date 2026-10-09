package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

// Focused services select current transaction projections, never aggregate
// query methods. External fakes are explicit test resources, not rollback-
// capable SQL adapters or snapshot-consistent storage.
type operatorFixtureResources struct {
	checks         []operationsquery.ReadinessCheck
	now            func() time.Time
	operator       app.OutboxAdmin
	reconciliation app.ObjectReconciliationMetricsStore
}
type operatorFixtureQueries struct {
	catalogFixtureCommands
	resources operatorFixtureResources
}
type readinessFixture struct{ operatorFixtureQueries }
type metricsFixture struct{ operatorFixtureQueries }
type instanceAdminFixture struct{ operatorFixtureQueries }
type outboxDiagnosticsFixture struct{ operatorFixtureQueries }
type outboxReplayFixture struct{ operatorFixtureQueries }

func (f operatorFixtureQueries) now() time.Time {
	if f.resources.now != nil {
		return f.resources.now()
	}
	return time.Now()
}

func (f readinessFixture) Public(ctx context.Context) (map[string]any, error) {
	return operationsquery.NewReadiness(f.resources.checks).Public(ctx)
}

func (f readinessFixture) Operator(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	return operationsquery.NewReadiness(f.resources.checks).Operator(ctx, actor)
}

func (f metricsFixture) Snapshot(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	query, err := operationsquery.NewMetrics(f, f.now)
	if err != nil {
		return nil, err
	}
	return query.Snapshot(ctx, actor)
}

func (f metricsFixture) ReadMetricsSnapshot(ctx context.Context, tenant string, includeOutbox bool) (operationsquery.MetricsSnapshot, error) {
	if ctx == nil {
		return operationsquery.MetricsSnapshot{}, app.ErrValidation
	}
	var out operationsquery.MetricsSnapshot
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Enterprise.(operationsquery.MetricsReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadMetricsSnapshot(ctx, tenant, includeOutbox)
		if err != nil {
			return err
		}
		if f.resources.reconciliation != nil {
			v, err := f.resources.reconciliation.ObjectReconciliationMetrics(ctx, tenant)
			if err != nil {
				return err
			}
			out.Reconciliation = operationsquery.ReconciliationCounts(v)
		}
		if includeOutbox && f.resources.operator != nil {
			v, err := outboxDiagnosticsFixture(f).ReadOutboxCounts(ctx)
			if err != nil {
				return err
			}
			out.Outbox = &v
		}
		return nil
	})
	if err != nil {
		return operationsquery.MetricsSnapshot{}, err
	}
	return out, nil
}

func (f instanceAdminFixture) Snapshot(ctx context.Context, actor domain.Actor) (operationsdomain.InstanceAdminSnapshot, error) {
	query, err := operationsquery.NewInstanceAdmin(f, f.now)
	if err != nil {
		return operationsdomain.InstanceAdminSnapshot{}, err
	}
	return query.Snapshot(ctx, actor)
}

func (f instanceAdminFixture) ReadInstanceCounts(ctx context.Context) (operationsquery.InstanceCounts, error) {
	if ctx == nil {
		return operationsquery.InstanceCounts{}, app.ErrValidation
	}
	var out operationsquery.InstanceCounts
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Enterprise.(operationsquery.InstanceCountsReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadInstanceCounts(ctx)
		return err
	})
	if err != nil {
		return operationsquery.InstanceCounts{}, err
	}
	return out, nil
}

func (f outboxDiagnosticsFixture) Diagnostics(ctx context.Context, actor domain.Actor) (operationsquery.OutboxCounts, error) {
	query, err := operationsquery.NewOutboxDiagnostics(f)
	if err != nil {
		return operationsquery.OutboxCounts{}, err
	}
	return query.Diagnostics(ctx, actor)
}

func (f outboxDiagnosticsFixture) ReadOutboxCounts(ctx context.Context) (operationsquery.OutboxCounts, error) {
	if ctx == nil {
		return operationsquery.OutboxCounts{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return operationsquery.OutboxCounts{}, err
	}
	if f.resources.operator == nil {
		return operationsquery.OutboxCounts{}, app.ErrConflict
	}
	v, err := f.resources.operator.OutboxDiagnostics(ctx)
	if err != nil {
		return operationsquery.OutboxCounts{}, err
	}
	return operationsquery.OutboxCounts(v), nil
}

func (f outboxReplayFixture) ReplayIdempotent(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, jobID string) (int, any, error) {
	// Current explicit instance authority also gates completed receipts; a
	// revoked operator cannot retrieve an earlier successful replay response.
	if err := application.AuthorizeInstanceScope(ctx, actor, app.ScopeInstanceAdmin); err != nil {
		return 0, nil, mapInstanceAdminQueryError(err)
	}
	commands, err := operationsapp.NewOutboxReplayCommands(f)
	if err != nil {
		return 0, nil, err
	}
	return f.ledger.WithIdempotency(ctx, actor, method, path, key, body, func(commandCtx context.Context, _ *app.Ledger) (int, any, error) {
		// The actual service joins the receipt transaction. The external
		// fake itself cannot roll back its observable side effects.
		v, err := commands.ReplayTerminalJob(commandCtx, actor, jobID)
		if errors.Is(err, operationsapp.ErrValidation) {
			err = app.ErrValidation
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, app.OutboxReplay{JobID: v.JobID, Status: v.Status, ReplayedAt: v.ReplayedAt}, nil
	})
}

func (f outboxReplayFixture) ExecuteReplay(ctx context.Context, run func(context.Context, operationsapp.ReplayRepository) error) error {
	if f.resources.operator == nil {
		return app.ErrConflict
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, _ app.Repositories) error {
		return run(ctx, operatorReplayFixtureRepository{f.resources.operator})
	})
}

type operatorReplayFixtureRepository struct{ operator app.OutboxAdmin }

func (f operatorReplayFixtureRepository) ReplayTerminalJob(ctx context.Context, id, actorID string) (operationsapp.OutboxReplay, error) {
	v, err := f.operator.ReplayTerminalJob(ctx, id, actorID)
	if err != nil {
		return operationsapp.OutboxReplay{}, err
	}
	return operationsapp.OutboxReplay{JobID: v.JobID, Status: v.Status, ReplayedAt: v.ReplayedAt}, nil
}

func (s *Server) bindOperatorFixturePorts(ledger *app.Ledger) {
	base := operatorFixtureQueries{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if f, ok := s.readinessQuery.(readinessFixture); ok {
		f.ledger = ledger
		s.readinessQuery = f
	} else if s.readinessQuery == nil {
		s.readinessQuery = readinessFixture{base}
	}
	if f, ok := s.metricsQuery.(metricsFixture); ok {
		f.ledger = ledger
		s.metricsQuery = f
	} else if s.metricsQuery == nil {
		s.metricsQuery = metricsFixture{base}
	}
	if f, ok := s.instanceAdminQuery.(instanceAdminFixture); ok {
		f.ledger = ledger
		s.instanceAdminQuery = f
	} else if s.instanceAdminQuery == nil {
		s.instanceAdminQuery = instanceAdminFixture{base}
	}
	if f, ok := s.outboxDiagnosticsQuery.(outboxDiagnosticsFixture); ok {
		f.ledger = ledger
		s.outboxDiagnosticsQuery = f
	} else if s.outboxDiagnosticsQuery == nil {
		s.outboxDiagnosticsQuery = outboxDiagnosticsFixture{base}
	}
	if f, ok := s.outboxReplayCommand.(outboxReplayFixture); ok {
		f.ledger = ledger
		s.outboxReplayCommand = f
	} else if s.outboxReplayCommand == nil {
		s.outboxReplayCommand = outboxReplayFixture{base}
	}
}

func (s *Server) bindOperatorFixtureResources(resources operatorFixtureResources) {
	resources.checks = slices.Clone(resources.checks)
	if f, ok := s.readinessQuery.(readinessFixture); ok {
		f.resources = resources
		s.readinessQuery = f
	}
	if f, ok := s.metricsQuery.(metricsFixture); ok {
		f.resources = resources
		s.metricsQuery = f
	}
	if f, ok := s.instanceAdminQuery.(instanceAdminFixture); ok {
		f.resources = resources
		s.instanceAdminQuery = f
	}
	if f, ok := s.outboxDiagnosticsQuery.(outboxDiagnosticsFixture); ok {
		f.resources = resources
		s.outboxDiagnosticsQuery = f
	}
	if f, ok := s.outboxReplayCommand.(outboxReplayFixture); ok {
		f.resources = resources
		s.outboxReplayCommand = f
	}
}

var (
	_ ReadinessQuery         = readinessFixture{}
	_ MetricsQuery           = metricsFixture{}
	_ InstanceAdminQuery     = instanceAdminFixture{}
	_ OutboxDiagnosticsQuery = outboxDiagnosticsFixture{}
	_ OutboxReplayCommand    = outboxReplayFixture{}
)
