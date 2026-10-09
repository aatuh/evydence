package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Compose the actual focused report queries over current typed repositories.
// Incident entries are capped; retention inventories retain the native unbounded
// row behavior. Neither typed model establishes SQL work/locks or durability.
type incidentReportFixture struct {
	catalogFixtureCommands
	now func() time.Time
}
type retentionReportFixture struct {
	catalogFixtureCommands
	now func() time.Time
}

func (f incidentReportFixture) Report(ctx context.Context, a domain.Actor, id string) (packagedomain.IncidentReport, error) {
	now := f.now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	q, err := packagequery.NewIncidentReport(f, now)
	if err != nil {
		return packagedomain.IncidentReport{}, err
	}
	v, err := q.Report(ctx, a, id)
	return v, mapIncidentReportQueryError(err)
}
func (f retentionReportFixture) Report(ctx context.Context, a domain.Actor, kind, id string) (operationsdomain.RetentionReport, error) {
	now := f.now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	q, err := operationsquery.NewRetentionReport(f, now)
	if err != nil {
		return operationsdomain.RetentionReport{}, err
	}
	v, err := q.Report(ctx, a, kind, id)
	return v, mapInstanceAdminQueryError(err)
}

func (f incidentReportFixture) ReadIncidentReport(ctx context.Context, tenant, id string) (packagequery.IncidentReportSnapshot, error) {
	var out packagequery.IncidentReportSnapshot
	if ctx == nil {
		return out, packagequery.ErrIncidentReportValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Risk.(packagequery.IncidentReportReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadIncidentReport(ctx, tenant, id)
		return err
	})
	if err != nil {
		return packagequery.IncidentReportSnapshot{}, err
	}
	return out, nil
}
func (f retentionReportFixture) ReadRetentionRecords(ctx context.Context, tenant, kind, id string) (operationsquery.RetentionSnapshot, error) {
	var out operationsquery.RetentionSnapshot
	if ctx == nil {
		return out, operationsquery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Governance.(operationsquery.RetentionReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadRetentionRecords(ctx, tenant, kind, id)
		return err
	})
	if err != nil {
		return operationsquery.RetentionSnapshot{}, err
	}
	return out, nil
}
func (s *Server) bindOperationsFixtureQueries(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	if old, fixture := s.incidentReportQuery.(incidentReportFixture); fixture {
		old.ledger = ledger
		s.incidentReportQuery = old
	} else if s.incidentReportQuery == nil {
		s.incidentReportQuery = incidentReportFixture{catalogFixtureCommands: f}
	}
	if old, fixture := s.retentionQuery.(retentionReportFixture); fixture {
		old.ledger = ledger
		s.retentionQuery = old
	} else if s.retentionQuery == nil {
		s.retentionQuery = retentionReportFixture{catalogFixtureCommands: f}
	}
}

var (
	_ IncidentReportQuery = incidentReportFixture{}
	_ RetentionQuery      = retentionReportFixture{}
)
