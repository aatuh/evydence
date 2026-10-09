package httpapi

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	"github.com/aatuh/evydence/internal/platform/vexpreview"
)

// Only legacy HTTP tests use these readers. Actual former ownership and scope
// policies remain in force; runtime ports use bounded PostgreSQL projections.
type evidenceReadFixture struct{ catalogFixtureCommands }
type evidencePageFixture struct{ catalogFixtureCommands }
type lifecyclePageFixture struct{ catalogFixtureCommands }
type sbomComponentsFixture struct{ catalogFixtureCommands }

func (f evidenceReadFixture) GetEvidence(ctx context.Context, actor domain.Actor, id string) (evidencedomain.EvidenceItem, error) {
	query, err := evidencequery.NewEvidencePoints(f)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	value, err := query.GetEvidence(ctx, actor, id)
	return value, legacyParsedPointError(err)
}

func (f evidencePageFixture) ListPage(ctx context.Context, actor domain.Actor, filter evidencequery.EvidencePageFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.EvidenceItem], error) {
	query, err := evidencequery.NewEvidencePages(f)
	if err != nil {
		return appquery.Result[evidencedomain.EvidenceItem]{}, err
	}
	result, err := query.ListPage(ctx, actor, filter, request, after)
	return result, legacyParsedPointError(err)
}

func (f lifecyclePageFixture) ListPage(ctx context.Context, actor domain.Actor, id string, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.EvidenceLifecycleEvent], error) {
	query, err := evidencequery.NewLifecycleEvents(f)
	if err != nil {
		return appquery.Result[evidencedomain.EvidenceLifecycleEvent]{}, err
	}
	result, err := query.ListPage(ctx, actor, id, request, after)
	return result, legacyParsedPointError(err)
}

func fixtureSBOM(value domain.SBOM) evidencedomain.SBOM {
	components := make([]evidencedomain.SBOMComponent, 0, len(value.Components))
	for _, component := range value.Components {
		components = append(components, evidencedomain.SBOMComponent(component))
	}
	return evidencedomain.SBOM{ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, Format: value.Format, SpecVersion: value.SpecVersion, ComponentCount: value.ComponentCount, Components: components, CreatedAt: value.CreatedAt}
}

func (f evidenceReadFixture) GetSBOM(ctx context.Context, actor domain.Actor, id string) (evidencedomain.SBOM, error) {
	query, err := evidencequery.NewSBOMPoints(f)
	if err != nil {
		return evidencedomain.SBOM{}, err
	}
	value, err := query.GetSBOM(ctx, actor, id)
	return value, legacyParsedPointError(err)
}

func (f sbomComponentsFixture) ListPage(ctx context.Context, actor domain.Actor, filter evidencequery.SBOMComponentFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.SBOMComponentRecord], error) {
	query, err := evidencequery.NewSBOMComponents(f)
	if err != nil {
		return appquery.Result[evidencedomain.SBOMComponentRecord]{}, err
	}
	result, err := query.ListPage(ctx, actor, filter, request, after)
	return result, legacyParsedPointError(err)
}

func fixtureVulnerabilityScan(value domain.VulnerabilityScan) evidencedomain.VulnerabilityScan {
	var findings []evidencedomain.VulnerabilityFinding
	if value.Findings != nil {
		findings = make([]evidencedomain.VulnerabilityFinding, 0, len(value.Findings))
	}
	for _, finding := range value.Findings {
		findings = append(findings, evidencedomain.VulnerabilityFinding{ID: finding.ID, Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity, State: finding.State, SeveritySource: finding.SeveritySource, FixVersion: finding.FixVersion, Identity: evidencedomain.VulnerabilityIdentity(finding.Identity)})
	}
	return evidencedomain.VulnerabilityScan{ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID, Scanner: value.Scanner, Adapter: value.Adapter, AdapterVersion: value.AdapterVersion, SourceSchema: value.SourceSchema, TargetRef: value.TargetRef, Summary: maps.Clone(value.Summary), Findings: findings, CreatedAt: value.CreatedAt}
}

func (f evidenceReadFixture) GetVulnerabilityScan(ctx context.Context, actor domain.Actor, id string) (evidencedomain.VulnerabilityScan, error) {
	query, err := evidencequery.NewVulnerabilityScanPoints(f)
	if err != nil {
		return evidencedomain.VulnerabilityScan{}, err
	}
	value, err := query.GetVulnerabilityScan(ctx, actor, id)
	return value, legacyParsedPointError(err)
}

func fixtureOpenAPIContract(value domain.OpenAPIContract) evidencedomain.OpenAPIContract {
	var operations []evidencedomain.OpenAPIOperation
	for _, operation := range value.Operations {
		operations = append(operations, evidencedomain.OpenAPIOperation{Path: operation.Path, Method: operation.Method, OperationID: operation.OperationID, Deprecated: operation.Deprecated, RequestBodyRequired: operation.RequestBodyRequired, RequiredRequestFields: slices.Clone(operation.RequiredRequestFields), ResponseStatuses: slices.Clone(operation.ResponseStatuses)})
	}
	return evidencedomain.OpenAPIContract{ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, ReleaseID: value.ReleaseID, Version: value.Version, Hash: value.Hash, PathCount: value.PathCount, EvidenceID: value.EvidenceID, Operations: operations, CreatedAt: value.CreatedAt}
}

func (f evidenceReadFixture) GetOpenAPIContract(ctx context.Context, actor domain.Actor, id string) (evidencedomain.OpenAPIContract, error) {
	query, err := evidencequery.NewOpenAPIContractPoints(f)
	if err != nil {
		return evidencedomain.OpenAPIContract{}, err
	}
	value, err := query.GetOpenAPIContract(ctx, actor, id)
	return value, legacyParsedPointError(err)
}

func fixtureVEXDocument(value domain.VEXDocument) evidencedomain.VEXDocument {
	return evidencedomain.VEXDocument{ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, Format: value.Format, Author: value.Author, Version: value.Version, StatementCount: value.StatementCount, StatusSummary: maps.Clone(value.StatusSummary), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}

func (f evidenceReadFixture) GetVEXDocument(ctx context.Context, actor domain.Actor, id string) (evidencedomain.VEXDocument, error) {
	query, err := evidencequery.NewVEXPoints(f)
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	value, err := query.GetVEXDocument(ctx, actor, id)
	return value, legacyParsedPointError(err)
}

func fixtureVEXIssues(values []domain.VEXImportIssue) []evidencedomain.VEXImportIssue {
	if values == nil {
		return nil
	}
	issues := make([]evidencedomain.VEXImportIssue, 0, len(values))
	for _, issue := range values {
		issues = append(issues, evidencedomain.VEXImportIssue(issue))
	}
	return issues
}

func fixtureVEXReport(value domain.VEXImportReport) evidencedomain.VEXImportReport {
	return evidencedomain.VEXImportReport{ID: value.ID, TenantID: value.TenantID, VEXDocumentID: value.VEXDocumentID, EvidenceID: value.EvidenceID, ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, ParserVersion: value.ParserVersion, Status: value.Status, StatementCount: value.StatementCount, DecisionsCreated: value.DecisionsCreated, DecisionsSuperseded: value.DecisionsSuperseded, UnsupportedFields: slices.Clone(value.UnsupportedFields), Warnings: slices.Clone(value.Warnings), InvalidStatements: fixtureVEXIssues(value.InvalidStatements), MappingFailures: fixtureVEXIssues(value.MappingFailures), FailureCode: value.FailureCode, FailureDetail: value.FailureDetail, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

func (f evidenceReadFixture) GetVEXImportReport(ctx context.Context, actor domain.Actor, id string) (evidencedomain.VEXImportReport, error) {
	query, err := evidencequery.NewVEXPoints(f)
	if err != nil {
		return evidencedomain.VEXImportReport{}, err
	}
	value, err := query.GetVEXImportReport(ctx, actor, id)
	return value, legacyParsedPointError(err)
}

func fixtureVEXPreview(value domain.VEXImportPreview) evidencedomain.VEXImportPreview {
	return evidencedomain.VEXImportPreview{TenantID: value.TenantID, ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, Format: value.Format, ParserVersion: value.ParserVersion, Advisory: value.Advisory, StatementCount: value.StatementCount, StatusSummary: maps.Clone(value.StatusSummary), DecisionsWouldCreate: value.DecisionsWouldCreate, DecisionsWouldSupersede: value.DecisionsWouldSupersede, Warnings: slices.Clone(value.Warnings), InvalidStatements: fixtureVEXIssues(value.InvalidStatements), MappingFailures: fixtureVEXIssues(value.MappingFailures), Assumptions: slices.Clone(value.Assumptions), Limitations: slices.Clone(value.Limitations), SchemaVersion: value.SchemaVersion, GeneratedAt: value.GeneratedAt}
}

func (f evidenceReadFixture) PreviewVEXImport(ctx context.Context, actor domain.Actor, input evidencequery.VEXPreviewInput) (evidencedomain.VEXImportPreview, error) {
	query, err := evidencequery.NewVEXPreviews(f, app.VEXPayloadParser{}, vexpreview.MapEffects, time.Now)
	if err != nil {
		return evidencedomain.VEXImportPreview{}, err
	}
	value, err := query.PreviewVEXImport(ctx, actor, input)
	return value, legacyParsedPointError(err)
}

func (s *Server) bindEvidenceReadFixturePorts(ledger *app.Ledger) {
	base := catalogFixtureCommands{ledger: ledger}
	read := evidenceReadFixture{base}
	if _, fixture := s.evidencePointQuery.(evidenceReadFixture); s.evidencePointQuery == nil || fixture {
		s.evidencePointQuery = read
	}
	if _, fixture := s.sbomPointQuery.(evidenceReadFixture); s.sbomPointQuery == nil || fixture {
		s.sbomPointQuery = read
	}
	if _, fixture := s.vulnerabilityScanPointQuery.(evidenceReadFixture); s.vulnerabilityScanPointQuery == nil || fixture {
		s.vulnerabilityScanPointQuery = read
	}
	if _, fixture := s.openAPIContractPointQuery.(evidenceReadFixture); s.openAPIContractPointQuery == nil || fixture {
		s.openAPIContractPointQuery = read
	}
	if _, fixture := s.vexPointQuery.(evidenceReadFixture); s.vexPointQuery == nil || fixture {
		s.vexPointQuery = read
	}
	if _, fixture := s.vexPreviewQuery.(evidenceReadFixture); s.vexPreviewQuery == nil || fixture {
		s.vexPreviewQuery = read
	}
	if _, fixture := s.evidencePageQuery.(evidencePageFixture); s.evidencePageQuery == nil || fixture {
		s.evidencePageQuery = evidencePageFixture{base}
	}
	if _, fixture := s.lifecycleEventsQuery.(lifecyclePageFixture); s.lifecycleEventsQuery == nil || fixture {
		s.lifecycleEventsQuery = lifecyclePageFixture{base}
	}
	if _, fixture := s.sbomComponentsQuery.(sbomComponentsFixture); s.sbomComponentsQuery == nil || fixture {
		s.sbomComponentsQuery = sbomComponentsFixture{base}
	}
}

var (
	_ EvidencePointQuery          = evidenceReadFixture{}
	_ SBOMPointQuery              = evidenceReadFixture{}
	_ VulnerabilityScanPointQuery = evidenceReadFixture{}
	_ OpenAPIContractPointQuery   = evidenceReadFixture{}
	_ VEXPointQuery               = evidenceReadFixture{}
	_ VEXPreviewQuery             = evidenceReadFixture{}
	_ EvidencePageQuery           = evidencePageFixture{}
	_ LifecycleEventsQuery        = lifecyclePageFixture{}
	_ SBOMComponentsQuery         = sbomComponentsFixture{}
)
