package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Historical fixture readers keep actual ownership/grant checks and detach
// mutable values. Runtime report readers remain bounded PostgreSQL projections.
type incidentReportFixture struct{ catalogFixtureCommands }
type retentionReportFixture struct{ catalogFixtureCommands }

func (f incidentReportFixture) Report(ctx context.Context, a domain.Actor, id string) (packagedomain.IncidentReport, error) {
	v, err := f.commandLedger(ctx).IncidentReport(ctx, a, id)
	timeline := make([]packagedomain.IncidentTimelineEventSnapshot, 0, len(v.Timeline))
	for _, event := range v.Timeline {
		timeline = append(timeline, packagedomain.IncidentTimelineEventSnapshot(event))
	}
	tasks := make([]packagedomain.RemediationTaskSnapshot, 0, len(v.Tasks))
	for _, task := range v.Tasks {
		model := packagedomain.RemediationTaskSnapshot(task)
		if task.DueAt != nil {
			at := *task.DueAt
			model.DueAt = &at
		}
		tasks = append(tasks, model)
	}
	return packagedomain.IncidentReport{ReportType: v.ReportType, TemplateVersion: v.TemplateVersion, IncidentID: v.IncidentID, Result: v.Result, Timeline: timeline, Tasks: tasks, LinkedEvidence: slices.Clone(v.LinkedEvidence), Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, err
}
func (f retentionReportFixture) Report(ctx context.Context, a domain.Actor, kind, id string) (operationsdomain.RetentionReport, error) {
	if err := application.AuthorizeTenantWideScope(ctx, a, "admin"); err != nil {
		return operationsdomain.RetentionReport{}, err
	}
	v, err := f.commandLedger(ctx).RetentionReport(ctx, a, kind, id)
	holds := make([]operationsdomain.LegalHold, 0, len(v.LegalHolds))
	for _, value := range v.LegalHolds {
		model := operationsdomain.LegalHold(value)
		if value.ReleasedAt != nil {
			at := *value.ReleasedAt
			model.ReleasedAt = &at
		}
		holds = append(holds, model)
	}
	overrides := make([]operationsdomain.RetentionOverride, 0, len(v.RetentionOverrides))
	for _, value := range v.RetentionOverrides {
		overrides = append(overrides, operationsdomain.RetentionOverride(value))
	}
	return operationsdomain.RetentionReport{ReportType: v.ReportType, ScopeType: v.ScopeType, ScopeID: v.ScopeID, LegalHolds: holds, RetentionOverrides: overrides, Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, err
}
func (s *Server) bindOperationsFixtureQueries(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	if _, fixture := s.incidentReportQuery.(incidentReportFixture); s.incidentReportQuery == nil || fixture {
		s.incidentReportQuery = incidentReportFixture{f}
	}
	if _, fixture := s.retentionQuery.(retentionReportFixture); s.retentionQuery == nil || fixture {
		s.retentionQuery = retentionReportFixture{f}
	}
}

var (
	_ IncidentReportQuery = incidentReportFixture{}
	_ RetentionQuery      = retentionReportFixture{}
)
