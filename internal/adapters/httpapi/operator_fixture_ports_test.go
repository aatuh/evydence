package httpapi

import (
	"context"
	"maps"
	"net/http"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

// These adapters preserve historical test fixtures, not a runtime backend.
// Native replay uses a transaction-owned repository, audit and receipt. A
// fixture's configured external OutboxAdmin is not rollback-capable SQL storage.
type readinessFixture struct{ catalogFixtureCommands }
type metricsFixture struct{ catalogFixtureCommands }
type instanceAdminFixture struct{ catalogFixtureCommands }
type outboxDiagnosticsFixture struct{ catalogFixtureCommands }
type outboxReplayFixture struct{ catalogFixtureCommands }

func (f readinessFixture) Public(ctx context.Context) (map[string]any, error) {
	return f.commandLedger(ctx).ReadinessStatus(ctx)
}

func (f readinessFixture) Operator(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	return f.commandLedger(ctx).ReadinessDiagnostics(ctx, actor)
}

func (f metricsFixture) Snapshot(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	return f.commandLedger(ctx).Metrics(ctx, actor)
}

func (f instanceAdminFixture) Snapshot(ctx context.Context, actor domain.Actor) (operationsdomain.InstanceAdminSnapshot, error) {
	value, err := f.commandLedger(ctx).InstanceAdminSnapshot(ctx, actor)
	return operationsdomain.InstanceAdminSnapshot{
		ReportType: value.ReportType, TenantCount: value.TenantCount,
		ResourceCounts: maps.Clone(value.ResourceCounts), Limitations: slices.Clone(value.Limitations),
		GeneratedAt: value.GeneratedAt,
	}, err
}

func (f outboxDiagnosticsFixture) Diagnostics(ctx context.Context, actor domain.Actor) (operationsquery.OutboxCounts, error) {
	value, err := f.commandLedger(ctx).OutboxOperatorDiagnostics(ctx, actor)
	return operationsquery.OutboxCounts{
		PendingJobs: value.PendingJobs, RunningJobs: value.RunningJobs,
		TerminalJobs: value.TerminalJobs, OldestPendingCreatedAt: value.OldestPendingCreatedAt,
	}, err
}

func (f outboxReplayFixture) ReplayIdempotent(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, jobID string) (int, any, error) {
	// Current explicit instance authority also gates completed receipts; a
	// revoked operator cannot retrieve an earlier successful replay response.
	if err := application.AuthorizeInstanceScope(ctx, actor, app.ScopeInstanceAdmin); err != nil {
		return 0, nil, mapInstanceAdminQueryError(err)
	}
	return f.ledger.WithIdempotency(ctx, actor, method, path, key, body, func(commandCtx context.Context, _ *app.Ledger) (int, any, error) {
		// This historical method delegates only to the externally configured
		// operator and writes no aggregate maps. Command clones do not carry
		// that external adapter. Use its real configured root, not a no-op;
		// external effects are deliberately not claimed to be rollback-safe.
		replay, err := f.ledger.ReplayTerminalOutboxJob(commandCtx, actor, jobID)
		return http.StatusOK, replay, err
	})
}

func (s *Server) bindOperatorFixturePorts(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	if _, fixture := s.readinessQuery.(readinessFixture); s.readinessQuery == nil || fixture {
		s.readinessQuery = readinessFixture{f}
	}
	if _, fixture := s.metricsQuery.(metricsFixture); s.metricsQuery == nil || fixture {
		s.metricsQuery = metricsFixture{f}
	}
	if _, fixture := s.instanceAdminQuery.(instanceAdminFixture); s.instanceAdminQuery == nil || fixture {
		s.instanceAdminQuery = instanceAdminFixture{f}
	}
	if _, fixture := s.outboxDiagnosticsQuery.(outboxDiagnosticsFixture); s.outboxDiagnosticsQuery == nil || fixture {
		s.outboxDiagnosticsQuery = outboxDiagnosticsFixture{f}
	}
	if _, fixture := s.outboxReplayCommand.(outboxReplayFixture); s.outboxReplayCommand == nil || fixture {
		s.outboxReplayCommand = outboxReplayFixture{f}
	}
}

var (
	_ ReadinessQuery         = readinessFixture{}
	_ MetricsQuery           = metricsFixture{}
	_ InstanceAdminQuery     = instanceAdminFixture{}
	_ OutboxDiagnosticsQuery = outboxDiagnosticsFixture{}
	_ OutboxReplayCommand    = outboxReplayFixture{}
)
