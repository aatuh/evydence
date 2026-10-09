package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

type vexCompletionFixturePort interface {
	CompleteVEXImportReport(context.Context, domain.VEXImportReport) error
}

func vexCompletionTestServer(t *testing.T) (*Server, string, *app.MemoryUnitOfWorkFactory) {
	t.Helper()
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	server.bindRepositoryIngestionFixtureScope()
	return server, secret, factory
}

// This explicit test worker reads the real producer's normalized request and
// uses the same pure Risk mapper as production. Effects go through repositories
// in one UoW. It is not proof of production dispatch, claims, SQL or durability.
func completeVEXFixtureJob(ctx context.Context, factory app.UnitOfWorkFactory, snapshot app.MemoryUnitOfWorkSnapshot, vexID string) error {
	if ctx == nil || factory == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	doc, exists := snapshot.VEXDocuments[vexID]
	if !exists || doc.ID != vexID {
		return app.ErrNotFound
	}
	var job app.OutboxJob
	for _, candidate := range snapshot.OutboxJobs {
		if candidate.Kind == "parse_vex" && candidate.SubjectType == "vex_document" && candidate.SubjectID == vexID && candidate.TenantID == doc.TenantID {
			if job.ID != "" {
				return app.ErrConflict
			}
			job = candidate
		}
	}
	text := func(key string) string { value, _ := job.Payload[key].(string); return value }
	if job.ID == "" || job.Payload["worker_create_decisions"] != true || text("decision_request_schema") != evidenceapp.VEXDecisionRequestSchemaVersion || text("evidence_id") != doc.EvidenceID || text("release_id") != doc.ReleaseID || text("artifact_id") != doc.ArtifactID || text("actor_id") == "" || text("actor_type") == "" {
		return app.ErrValidation
	}
	var statements []struct {
		Index           int      `json:"statement_index"`
		Vulnerability   string   `json:"vulnerability"`
		Products        []string `json:"products"`
		Status          string   `json:"status"`
		Justification   string   `json:"justification"`
		ImpactStatement string   `json:"impact_statement"`
		ActionStatement string   `json:"action_statement"`
	}
	raw, err := json.Marshal(job.Payload["decision_statements"])
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&statements); err != nil || len(statements) == 0 || len(statements) > doc.StatementCount {
		return app.ErrValidation
	}
	return app.ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Evidence.(evidencequery.VEXPointReader)
		completion, writable := r.Evidence.(vexCompletionFixturePort)
		scans, readable := r.Evidence.(evidencequery.VulnerabilityScanPointReader)
		if !ok || !writable || !readable {
			return app.ErrValidation
		}
		point, err := reader.GetVEXImportReportPoint(ctx, doc.TenantID, vexID)
		if err != nil {
			return err
		}
		report := vexImportReportFromQuery(point.Report)
		if report.ID != text("import_report_id") || report.EvidenceID != doc.EvidenceID || report.ReleaseID != doc.ReleaseID || report.ArtifactID != doc.ArtifactID || report.ParserVersion != text("parser_version") {
			return app.ErrConflict
		}
		if report.Status == "parsed" {
			return nil // The real committed completion is replayed, never zeroed.
		}
		if report.Status != "accepted" {
			return app.ErrConflict
		}
		source, err := r.Evidence.GetEvidence(ctx, doc.TenantID, doc.EvidenceID)
		if err != nil {
			return err
		}
		if source.Type != "vex" || source.PayloadHash != text("payload_hash") {
			return app.ErrConflict
		}
		now := report.UpdatedAt.Add(time.Second)
		input := riskapp.VEXMappingInput{TenantID: doc.TenantID, ReleaseID: doc.ReleaseID, VEXDocumentID: doc.ID, EvidenceID: doc.EvidenceID, ActorID: text("actor_id"), Source: "vex", CreatedAt: now}
		if doc.Format == "cyclonedx" {
			input.Source = "cyclonedx_vex"
		}
		for _, s := range statements {
			input.Statements = append(input.Statements, riskapp.VEXStatement{Index: s.Index, Vulnerability: s.Vulnerability, Products: s.Products, Status: s.Status, Justification: s.Justification, ImpactStatement: s.ImpactStatement, ActionStatement: s.ActionStatement})
		}
		for id, candidate := range snapshot.VulnerabilityScans {
			if candidate.TenantID != doc.TenantID || candidate.ReleaseID != doc.ReleaseID {
				continue
			}
			scan, err := scans.GetVulnerabilityScanPoint(ctx, doc.TenantID, id)
			if err != nil {
				return err
			}
			if scan.Scan.ReleaseID != doc.ReleaseID {
				return app.ErrConflict
			}
			for _, finding := range scan.Scan.Findings {
				input.Findings = append(input.Findings, riskapp.VEXFinding{ID: finding.ID, ScanID: scan.Scan.ID, TenantID: doc.TenantID, ReleaseID: doc.ReleaseID, Vulnerability: finding.Vulnerability, Component: finding.Component})
			}
		}
		for _, prior := range snapshot.Decisions {
			if prior.TenantID == doc.TenantID && prior.ReleaseID == doc.ReleaseID {
				value, err := domain.VulnerabilityDecisionToContextModel(prior)
				if err != nil {
					return err
				}
				input.ExistingDecisions = append(input.ExistingDecisions, value)
			}
		}
		mapping, err := riskapp.MapVEXDecisions(input, riskapp.VEXDecisionIDFunc(func(vex, finding, status string) string { return "fixture-" + vex + "-" + finding + "-" + status }))
		if err != nil {
			return err
		}
		appendAudit := func(kind, subjectType, id string) error {
			_, err := r.Audit.Append(ctx, domain.AuditChainEntry{ID: "fixture-" + job.ID + "-" + kind + "-" + id, TenantID: doc.TenantID, EntryType: "vulnerability_decision." + kind, SubjectType: subjectType, SubjectID: id, ActorType: text("actor_type"), ActorID: text("actor_id"), PayloadHash: source.PayloadHash, OccurredAt: now, SchemaVersion: domain.AuditChainEntrySchemaVersion})
			return err
		}
		for _, created := range mapping.Created {
			var superseded []domain.VulnerabilityDecision
			for _, prior := range mapping.Superseded {
				if prior.SupersededBy == created.ID {
					superseded = append(superseded, domain.VulnerabilityDecisionFromContextModel(prior))
				}
			}
			decision := domain.VulnerabilityDecisionFromContextModel(created)
			if err := r.Decisions.SupersedeAndInsert(ctx, decision, superseded); err != nil {
				return err
			}
			for _, prior := range superseded {
				if err := appendAudit("superseded", "vulnerability_decision", prior.ID); err != nil {
					return err
				}
			}
			if err := appendAudit("created", "vulnerability_finding", decision.FindingID); err != nil {
				return err
			}
		}
		report.Status, report.DecisionsCreated, report.DecisionsSuperseded, report.UpdatedAt = "parsed", len(mapping.Created), len(mapping.Superseded), now
		report.FailureCode, report.FailureDetail, report.MappingFailures = "", "", []domain.VEXImportIssue{}
		for _, issue := range mapping.Failures {
			report.MappingFailures = append(report.MappingFailures, domain.VEXImportIssue{StatementIndex: issue.StatementIndex, Code: issue.Code, Detail: issue.Detail})
		}
		report.Warnings = slices.DeleteFunc(slices.Clone(report.Warnings), func(w string) bool { return w == evidenceapp.VEXAsyncDecisionWarning })
		if mapping.HadDuplicate {
			return fmt.Errorf("fixture expects unique normalized statements")
		}
		return completion.CompleteVEXImportReport(ctx, report)
	})
}
