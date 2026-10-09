package httpapi

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

// Only legacy HTTP tests use these readers. Actual former scope/filter rules
// remain in force; runtime ports perform bounded committed PostgreSQL queries.
type decisionQueryFixture struct{ catalogFixtureCommands }

func decisionQueryFixtureModel(value domain.VulnerabilityDecision) (riskdomain.VulnerabilityDecision, error) {
	// The real query never selects private notes. Omit them before crossing the
	// fixture query port too, not only when serializing its external response.
	value.InternalNotes = ""
	model, err := domain.VulnerabilityDecisionToContextModel(value)
	if err != nil {
		return riskdomain.VulnerabilityDecision{}, riskquery.ErrInvalidProjection
	}
	return model, nil
}

func (f decisionQueryFixture) ListPage(ctx context.Context, actor domain.Actor, filter riskquery.DecisionFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.VulnerabilityDecision], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[riskdomain.VulnerabilityDecision]{}, err
	}
	values, err := f.commandLedger(ctx).ListVulnerabilityDecisions(ctx, actor, app.ListVulnerabilityDecisionsInput{ProductID: filter.ProductID, ReleaseID: filter.ReleaseID, Vulnerability: filter.Vulnerability, Component: filter.Component, Status: filter.Status, Active: filter.Active})
	if err != nil {
		return appquery.Result[riskdomain.VulnerabilityDecision]{}, err
	}
	items := make([]riskdomain.VulnerabilityDecision, 0, len(values))
	for _, value := range values {
		item, err := decisionQueryFixtureModel(value)
		if err != nil {
			return appquery.Result[riskdomain.VulnerabilityDecision]{}, err
		}
		items = append(items, item)
	}
	return appquery.Page(items, request, after, func(value riskdomain.VulnerabilityDecision, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
}

type exceptionQueryFixture struct{ catalogFixtureCommands }

func (f exceptionQueryFixture) ListPage(ctx context.Context, actor domain.Actor, releaseID string, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.Exception], error) {
	query, err := riskquery.NewExceptions(f)
	if err != nil {
		return appquery.Result[riskdomain.Exception]{}, err
	}
	return query.ListPage(ctx, actor, releaseID, request, after)
}

func (f exceptionQueryFixture) PageExceptions(ctx context.Context, request riskquery.ExceptionPageRequest) (riskquery.ExceptionPage, error) {
	if ctx == nil {
		return riskquery.ExceptionPage{}, riskquery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return riskquery.ExceptionPage{}, err
	}
	var out riskquery.ExceptionPage
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Decisions.(riskquery.ExceptionReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageExceptions(ctx, request)
		return err
	})
	if err != nil {
		return riskquery.ExceptionPage{}, err
	}
	return out, nil
}

type decisionSummaryQueryFixture struct{ catalogFixtureCommands }

func decisionSummaryFixtureModel(value domain.VulnerabilityDecisionSummaryReport) riskdomain.VulnerabilityDecisionSummaryReport {
	items := make([]riskdomain.VulnerabilityDecisionCustomerSummary, 0, len(value.Decisions))
	for _, decision := range value.Decisions {
		refs := make([]riskdomain.SupportingReference, 0, len(decision.SupportingRefs))
		for _, ref := range decision.SupportingRefs {
			refs = append(refs, riskdomain.SupportingReference{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
		}
		items = append(items, riskdomain.VulnerabilityDecisionCustomerSummary{ID: decision.ID, FindingID: decision.FindingID, ScanID: decision.ScanID, ReleaseID: decision.ReleaseID, Vulnerability: decision.Vulnerability, Component: decision.Component, SBOMID: decision.SBOMID, SBOMComponentPURL: decision.SBOMComponentPURL, SBOMComponentName: decision.SBOMComponentName, Status: decision.Status, Justification: decision.Justification, ImpactStatement: decision.ImpactStatement, ActionStatement: decision.ActionStatement, Source: decision.Source, EvidenceID: decision.EvidenceID, EvidenceIDs: slices.Clone(decision.EvidenceIDs), SupportingRefs: refs, VEXDocumentID: decision.VEXDocumentID, ReviewedAt: copyDecisionSummaryTime(decision.ReviewedAt), ReviewDueAt: copyDecisionSummaryTime(decision.ReviewDueAt), CreatedAt: decision.CreatedAt})
	}
	return riskdomain.VulnerabilityDecisionSummaryReport{ReportType: value.ReportType, TemplateVersion: value.TemplateVersion, ProductID: value.ProductID, ReleaseID: value.ReleaseID, Decisions: items, Assumptions: slices.Clone(value.Assumptions), Limitations: slices.Clone(value.Limitations), GeneratedAt: value.GeneratedAt}
}

func (f decisionSummaryQueryFixture) SummaryReport(ctx context.Context, actor domain.Actor, releaseID string) (riskdomain.VulnerabilityDecisionSummaryReport, error) {
	query, err := riskquery.NewVulnerabilityDecisionSummary(f, time.Now)
	if err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	value, err := query.SummaryReport(ctx, actor, releaseID)
	if errors.Is(err, riskquery.ErrNotFound) {
		err = app.ErrNotFound
	} else if errors.Is(err, riskquery.ErrValidation) {
		err = app.ErrValidation
	}
	return value, legacyParsedPointError(err)
}

func (f decisionSummaryQueryFixture) ReadVulnerabilityDecisionSummary(ctx context.Context, request riskquery.DecisionSummaryRequest) (riskquery.DecisionSummarySnapshot, error) {
	return parsedFixtureRead(ctx, f.catalogFixtureCommands, func(ctx context.Context, r app.Repositories) (riskquery.DecisionSummarySnapshot, error) {
		reader, ok := r.Decisions.(riskquery.DecisionSummaryReader)
		if !ok {
			return riskquery.DecisionSummarySnapshot{}, app.ErrValidation
		}
		return reader.ReadVulnerabilityDecisionSummary(ctx, request)
	})
}

func (s *Server) bindRiskQueryFixturePorts(ledger *app.Ledger) {
	base := catalogFixtureCommands{ledger: ledger}
	if _, fixture := s.vulnerabilityDecisionQuery.(decisionQueryFixture); s.vulnerabilityDecisionQuery == nil || fixture {
		s.vulnerabilityDecisionQuery = decisionQueryFixture{base}
	}
	if _, fixture := s.exceptionsQuery.(exceptionQueryFixture); s.exceptionsQuery == nil || fixture {
		s.exceptionsQuery = exceptionQueryFixture{base}
	}
	if _, fixture := s.vulnerabilityDecisionSummaryQuery.(decisionSummaryQueryFixture); s.vulnerabilityDecisionSummaryQuery == nil || fixture {
		s.vulnerabilityDecisionSummaryQuery = decisionSummaryQueryFixture{base}
	}
}

var (
	_ VulnerabilityDecisionQuery        = decisionQueryFixture{}
	_ ExceptionsQuery                   = exceptionQueryFixture{}
	_ VulnerabilityDecisionSummaryQuery = decisionSummaryQueryFixture{}
)
