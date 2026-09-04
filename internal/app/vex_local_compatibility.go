package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

// completeLocalVEXDecision drains the compatibility handoff only after the
// evidence/report transaction has committed. The transaction adapter owns
// this dispatch so the deprecated public Ledger facade remains forwarding-only.
func (r ledgerEvidenceTransactions) completeLocalVEXDecision(ctx context.Context, vexID string) {
	ctx = context.WithoutCancel(ctx)
	l := r.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	job, ok := l.localVEXJobs[strings.TrimSpace(vexID)]
	if !ok {
		return
	}
	tx := newLedgerEvidenceTransaction(l)
	if err := tx.processLocalVEXDecisionJob(ctx, job); err != nil {
		tx = newLedgerEvidenceTransaction(l)
		tx.stageLocalVEXDecisionFailure(job)
	}
	if err := tx.commitCompatibility(ctx); err != nil {
		return
	}
	delete(l.localVEXJobs, job.SubjectID)
}

func (t *ledgerEvidenceTransaction) stageLocalVEXDecisionFailure(job OutboxJob) {
	reportID, ok := exactPayloadString(job.Payload, "import_report_id")
	if !ok {
		return
	}
	report, ok := t.ledger.vexImportReports[reportID]
	if !ok || report.TenantID != job.TenantID || report.VEXDocumentID != job.SubjectID {
		return
	}
	report.Status = "failed"
	report.FailureCode = "local_decision_processing_failed"
	report.FailureDetail = "Local VEX decision processing failed."
	report.UpdatedAt = t.ledger.now().UTC()
	t.vexReports[report.ID] = report
}

// processLocalVEXDecisionJob preserves the pre-worker local API behavior when
// no durable outbox implementation exists. It stages every decision, report,
// and audit effect in a second compatibility transaction.
func (t *ledgerEvidenceTransaction) processLocalVEXDecisionJob(ctx context.Context, event OutboxJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	vex, report, evidence, statements, actorTypeValue, actorIDValue, payloadHash, err := t.validateLocalVEXDecisionEvent(event)
	if err != nil {
		return err
	}

	createdForFinding := map[string]struct{}{}
	created, superseded := 0, 0
	mappingFailures := []domain.VEXImportIssue{}
	duplicateStatements := false
	source := "vex"
	if vex.Format == "cyclonedx" {
		source = "cyclonedx_vex"
	}
	for _, normalized := range statements {
		statement := normalized.statement
		matches, ambiguous := t.ledger.findMatchingFindingsLocked(event.TenantID, vex.ReleaseID, statement)
		if ambiguous {
			mappingFailures = append(mappingFailures, vexImportIssue(normalized.index, "ambiguous_finding", "Multiple plausible findings matched this VEX statement; no decision was applied."))
			continue
		}
		if len(matches) == 0 {
			mappingFailures = append(mappingFailures, vexImportIssue(normalized.index, "finding_not_found", "No matching vulnerability scan finding was found for this VEX statement."))
		}
		for _, matched := range matches {
			if _, duplicate := createdForFinding[matched.finding.ID]; duplicate {
				duplicateStatements = true
				continue
			}
			createdForFinding[matched.finding.ID] = struct{}{}
			decision, replaced := t.ledger.newDecisionLocked(event.TenantID, matched.scan, matched.finding, CreateVulnerabilityDecisionInput{
				Status: statement.Status, Justification: statement.Justification, ImpactStatement: statement.ImpactStatement,
				ActionStatement: statement.ActionStatement, CustomerVisible: strings.TrimSpace(statement.ImpactStatement) != "",
			}, source, actorIDValue, evidence.ID, vex.ID)
			for _, prior := range replaced {
				t.decisions[prior.ID] = prior
				if _, err := t.AppendAudit(ctx, application.AuditEvent{
					ID: newID("ace"), TenantID: event.TenantID, EntryType: "vulnerability_decision.superseded",
					SubjectType: "vulnerability_decision", SubjectID: prior.ID, ActorType: actorTypeValue,
					ActorID: actorIDValue, OccurredAt: decision.CreatedAt, PayloadHash: payloadHash,
				}); err != nil {
					return err
				}
			}
			t.decisions[decision.ID] = decision
			if _, err := t.AppendAudit(ctx, application.AuditEvent{
				ID: newID("ace"), TenantID: event.TenantID, EntryType: "vulnerability_decision.created",
				SubjectType: "vulnerability_finding", SubjectID: matched.finding.ID, ActorType: actorTypeValue,
				ActorID: actorIDValue, OccurredAt: decision.CreatedAt, PayloadHash: payloadHash,
			}); err != nil {
				return err
			}
			created++
			superseded += len(replaced)
		}
	}

	report.Status = "parsed"
	report.DecisionsCreated = created
	report.DecisionsSuperseded = superseded
	report.MappingFailures = mappingFailures
	report.FailureCode = ""
	report.FailureDetail = ""
	report.Warnings = removeString(report.Warnings, evidenceapp.VEXAsyncDecisionWarning)
	if duplicateStatements {
		warning := "Duplicate VEX statements for an already mapped finding were ignored."
		if vex.Format == "cyclonedx" {
			warning = "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored."
		}
		report.Warnings = appendUniqueLocalString(report.Warnings, warning)
	}
	report.UpdatedAt = t.ledger.now().UTC()
	t.vexReports[report.ID] = report
	return nil
}

func (t *ledgerEvidenceTransaction) validateLocalVEXDecisionEvent(event OutboxJob) (domain.VEXDocument, domain.VEXImportReport, domain.EvidenceItem, []localVEXDecisionStatement, string, string, string, error) {
	invalid := func() (domain.VEXDocument, domain.VEXImportReport, domain.EvidenceItem, []localVEXDecisionStatement, string, string, string, error) {
		return domain.VEXDocument{}, domain.VEXImportReport{}, domain.EvidenceItem{}, nil, "", "", "", evidenceapp.ErrValidation
	}
	if event.Kind != "parse_vex" || event.SubjectType != "vex_document" || strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.TenantID) == "" || strings.TrimSpace(event.SubjectID) == "" || event.Payload["worker_create_decisions"] != true {
		return invalid()
	}
	if value, ok := event.Payload["decision_request_schema"].(string); !ok || value != evidenceapp.VEXDecisionRequestSchemaVersion {
		return invalid()
	}
	vex, ok := t.ledger.vexDocuments[event.SubjectID]
	if !ok || vex.ID != event.SubjectID || vex.TenantID != event.TenantID || (vex.Format != "openvex" && vex.Format != "cyclonedx") || vex.StatementCount <= 0 {
		return invalid()
	}
	reportID, reportIDOK := exactPayloadString(event.Payload, "import_report_id")
	report, reportOK := t.ledger.vexImportReports[reportID]
	evidenceID, evidenceIDOK := exactPayloadString(event.Payload, "evidence_id")
	evidence, evidenceOK := t.ledger.evidence[evidenceID]
	releaseID, releaseIDOK := exactPayloadString(event.Payload, "release_id")
	artifactID, artifactIDOK := exactPayloadStringAllowEmpty(event.Payload, "artifact_id")
	payloadHash, payloadHashOK := exactPayloadString(event.Payload, "payload_hash")
	actorTypeValue, actorTypeOK := exactPayloadString(event.Payload, "actor_type")
	actorIDValue, actorIDOK := exactPayloadString(event.Payload, "actor_id")
	if !reportIDOK || !reportOK || report.ID != reportID || report.TenantID != event.TenantID || report.VEXDocumentID != vex.ID || report.EvidenceID != vex.EvidenceID || report.ReleaseID != vex.ReleaseID || report.ArtifactID != vex.ArtifactID || report.Status != "accepted" || report.StatementCount != vex.StatementCount || !evidenceIDOK || !evidenceOK || evidence.ID != vex.EvidenceID || evidence.TenantID != event.TenantID || evidence.ReleaseID != vex.ReleaseID || evidence.PayloadHash != payloadHash || !releaseIDOK || releaseID != vex.ReleaseID || !artifactIDOK || artifactID != vex.ArtifactID || !payloadHashOK || !actorTypeOK || !actorIDOK {
		return invalid()
	}
	expectedParser := ParserVersionOpenVEXJSON
	if vex.Format == "cyclonedx" {
		expectedParser = ParserVersionCycloneDXVEXJSON
	}
	parserVersion, parserVersionOK := exactPayloadString(event.Payload, "parser_version")
	if !parserVersionOK || parserVersion != expectedParser || report.ParserVersion != expectedParser {
		return invalid()
	}
	statements, ok := localVEXDecisionStatements(event.Payload["decision_statements"], vex)
	if !ok {
		return invalid()
	}
	return vex, report, evidence, statements, actorTypeValue, actorIDValue, payloadHash, nil
}

type localVEXDecisionStatement struct {
	index     int
	statement openVEXStatement
}

func localVEXDecisionStatements(value any, vex domain.VEXDocument) ([]localVEXDecisionStatement, bool) {
	rows, ok := value.([]map[string]any)
	if !ok || len(rows) == 0 || len(rows) > vex.StatementCount {
		return nil, false
	}
	result := make([]localVEXDecisionStatement, 0, len(rows))
	seenIndexes := map[int]struct{}{}
	statusSummary := map[string]int{}
	for _, row := range rows {
		if !localVEXDecisionKeysValid(row) {
			return nil, false
		}
		statementIndex, indexOK := row["statement_index"].(int)
		vulnerability, vulnerabilityOK := exactMapString(row, "vulnerability", false)
		status, statusOK := exactMapString(row, "status", false)
		justification, justificationOK := exactMapString(row, "justification", true)
		impact, impactOK := exactMapString(row, "impact_statement", true)
		action, actionOK := exactMapString(row, "action_statement", true)
		products, productsOK := row["products"].([]string)
		if !indexOK || statementIndex <= 0 || statementIndex > vex.StatementCount || !vulnerabilityOK || !statusOK || !justificationOK || !impactOK || !actionOK || !productsOK || !validDecisionStatus(status) {
			return nil, false
		}
		if _, duplicate := seenIndexes[statementIndex]; duplicate {
			return nil, false
		}
		seenIndexes[statementIndex] = struct{}{}
		productRefs := make([]openVEXProduct, 0, len(products))
		seenProducts := map[string]struct{}{}
		for _, product := range products {
			product = strings.TrimSpace(product)
			if product == "" {
				return nil, false
			}
			if _, duplicate := seenProducts[product]; duplicate {
				return nil, false
			}
			seenProducts[product] = struct{}{}
			productRefs = append(productRefs, openVEXProduct{ID: product})
		}
		if vex.Format == "openvex" && len(productRefs) == 0 {
			return nil, false
		}
		statusSummary[status]++
		if justification == "" {
			justification = "vex"
			if vex.Format == "cyclonedx" {
				justification = "cyclonedx_vex"
			}
		}
		result = append(result, localVEXDecisionStatement{index: statementIndex, statement: openVEXStatement{
			Vulnerability: openVEXVulnerability{Name: vulnerability}, Products: productRefs, Status: status,
			Justification: justification, ImpactStatement: impact, ActionStatement: action,
		}})
	}
	if len(statusSummary) != len(vex.StatusSummary) {
		return nil, false
	}
	for status, count := range statusSummary {
		if vex.StatusSummary[status] != count {
			return nil, false
		}
	}
	return result, true
}

func localVEXDecisionKeysValid(row map[string]any) bool {
	allowed := map[string]struct{}{
		"statement_index": {}, "vulnerability": {}, "products": {}, "status": {},
		"justification": {}, "impact_statement": {}, "action_statement": {},
	}
	for key := range row {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	for _, key := range []string{"statement_index", "vulnerability", "products", "status", "justification", "impact_statement", "action_statement"} {
		if _, ok := row[key]; !ok {
			return false
		}
	}
	return true
}

func exactPayloadString(payload map[string]any, key string) (string, bool) {
	return exactMapString(payload, key, false)
}

func exactPayloadStringAllowEmpty(payload map[string]any, key string) (string, bool) {
	return exactMapString(payload, key, true)
}

func exactMapString(values map[string]any, key string, allowEmpty bool) (string, bool) {
	value, ok := values[key].(string)
	if !ok || value != strings.TrimSpace(value) || (!allowEmpty && value == "") {
		return "", false
	}
	return value, true
}

func removeString(values []string, target string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func appendUniqueLocalString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func cloneVulnerabilityDecisionMap(values map[string]domain.VulnerabilityDecision) map[string]domain.VulnerabilityDecision {
	result := make(map[string]domain.VulnerabilityDecision, len(values))
	for id, decision := range values {
		decision.EvidenceIDs = append([]string(nil), decision.EvidenceIDs...)
		decision.SupportingRefs = cloneSubjectRefs(decision.SupportingRefs)
		decision.ReviewedAt = cloneTimePtr(decision.ReviewedAt)
		decision.ReviewDueAt = cloneTimePtr(decision.ReviewDueAt)
		result[id] = decision
	}
	return result
}
