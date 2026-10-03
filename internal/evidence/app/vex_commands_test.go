package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestUploadVEXPayloadAuthorizesReleaseAndArtifactBeforeParserOrStager(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.scopeErr = ErrNotFound

	_, err := fixture.service.UploadVEXPayload(context.Background(), fixture.actor, " rel_missing ", " art_missing ", testPayloadSource(`{"author":"attacker"}`))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("UploadVEXPayload error = %v, want not found", err)
	}
	if fixture.parser.vexCalls != 0 || fixture.objects.sourceStageCalls != 0 {
		t.Fatalf("untrusted bytes reached parser/stager before target rejection: parser=%d stager=%d", fixture.parser.vexCalls, fixture.objects.sourceStageCalls)
	}
}

func TestUploadVEXPayloadRejectsArtifactOnlyAuthorizationBeforeParserOrStager(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.reader.artifactDigests["art_1"] = testDigest('a')
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactDigests["art_1"] = testDigest('a')
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources == (application.ResourceReferences{ArtifactID: "art_1"}) {
			return errAuthorizationFailure
		}
		return nil
	}

	_, err := fixture.service.UploadVEXPayload(context.Background(), fixture.actor, "rel_1", "art_1", testPayloadSource(`{"author":"attacker"}`))
	if !errors.Is(err, errAuthorizationFailure) {
		t.Fatalf("UploadVEXPayload error = %v, want authorization failure", err)
	}
	if fixture.parser.vexCalls != 0 || fixture.objects.sourceStageCalls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("denied artifact reached parser, stager, or transaction: parser=%d stager=%d transactions=%#v", fixture.parser.vexCalls, fixture.objects.sourceStageCalls, fixture.transactions)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, application.ResourceReferences{ArtifactID: "art_1"}) {
		t.Fatalf("artifact-only authorization missing: %#v", fixture.authorizer.requests)
	}
}

func TestUploadVEXPayloadPersistsInitialRecordsAndReplayJobAtomically(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.actor = identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", SessionID: "ses_1", Scopes: []string{"*"}}
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	fixture.parser.vex = ParsedVEX{
		Format: "openvex", Author: "security@example.test", Version: "1", ParserVersion: OpenVEXParserVersion,
		StatementCount: 1, ValidStatementCount: 1, StatusSummary: map[string]int{"fixed": 1},
		Statements: []VEXDecisionStatement{{
			StatementIndex: 1, Vulnerability: "CVE-2026-0903", Products: []string{"pkg:generic/api@1"}, Status: "fixed",
			Justification: "fixed_in_release", ImpactStatement: "Fixed before release.", ActionStatement: "Upgrade to this release.",
		}},
		Warnings: []string{"parser warning"}, Metadata: map[string]any{"format": "openvex"},
	}
	source := testPayloadSource(`{"author":"security@example.test"}`)

	vex, err := fixture.service.UploadVEXPayload(context.Background(), fixture.actor, " rel_1 ", " art_1 ", source)
	if err != nil {
		t.Fatalf("UploadVEXPayload: %v", err)
	}
	if vex.ReleaseID != "rel_1" || vex.ArtifactID != "art_1" || vex.Format != "openvex" || vex.StatementCount != 1 || vex.StatusSummary["fixed"] != 1 {
		t.Fatalf("returned VEX = %#v", vex)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 1 || len(state.vexDocuments) != 1 || len(state.vexImportReports) != 1 || len(state.payloads) != 1 || len(state.audit) != 2 || len(state.outbox) != 2 || fixture.transactions.commits != 1 {
		t.Fatalf("atomic state evidence=%d vex=%d reports=%d payloads=%d audit=%d outbox=%d commits=%d", len(state.evidence), len(state.vexDocuments), len(state.vexImportReports), len(state.payloads), len(state.audit), len(state.outbox), fixture.transactions.commits)
	}
	var report evidencedomain.VEXImportReport
	for _, value := range state.vexImportReports {
		report = value
	}
	if report.Status != "accepted" || report.VEXDocumentID != vex.ID || report.EvidenceID != vex.EvidenceID || report.DecisionsCreated != 0 || report.DecisionsSuperseded != 0 || report.ParserVersion != OpenVEXParserVersion || !stringSliceContains(report.Warnings, "parser warning") || !stringSliceContains(report.Warnings, VEXAsyncDecisionWarning) {
		t.Fatalf("initial report = %#v", report)
	}
	if state.outbox[0].Kind != "finalize_payload" || state.outbox[1].Kind != "parse_vex" {
		t.Fatalf("outbox = %#v", state.outbox)
	}
	job := state.outbox[1]
	if job.Payload["worker_create_decisions"] != true || job.Payload["decision_request_schema"] != VEXDecisionRequestSchemaVersion || job.Payload["actor_type"] != "human_user" || job.Payload["actor_id"] != "usr_1" || job.Payload["evidence_id"] != vex.EvidenceID || job.Payload["release_id"] != vex.ReleaseID || job.Payload["artifact_id"] != vex.ArtifactID || job.Payload["import_report_id"] != report.ID || job.Payload["parser_version"] != OpenVEXParserVersion || job.Payload["payload_ref"] == "" {
		t.Fatalf("parse job = %#v", job)
	}
	requireNormalizedVEXStatement(t, job.Payload, 0, 1, "CVE-2026-0903", []string{"pkg:generic/api@1"}, "fixed")
	for _, event := range state.audit {
		if event.ActorType != "human_user" || event.ActorID != "usr_1" {
			t.Fatalf("audit actor = %#v", event)
		}
	}
	if got := fixture.transactions.validatedArtifacts; len(got) != 1 || got[0] != "art_1" {
		t.Fatalf("transaction artifact rechecks = %#v", got)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, application.ResourceReferences{ArtifactID: "art_1"}) {
		t.Fatalf("artifact-only authorization missing: %#v", fixture.authorizer.requests)
	}
}

func TestUploadVEXPayloadWithoutObjectStoreQueuesNormalizedDecisionRequest(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.objects.noObject = true
	fixture.parser.vex = ParsedVEX{
		Format: "openvex", Author: "security@example.test", Version: "1", ParserVersion: OpenVEXParserVersion,
		StatementCount: 1, ValidStatementCount: 1, StatusSummary: map[string]int{"not_affected": 1},
		Statements: []VEXDecisionStatement{{
			StatementIndex: 1, Vulnerability: "CVE-2026-0904", Products: []string{"pkg:generic/api@1"}, Status: "not_affected",
			Justification: "component_not_present", ImpactStatement: "The component is absent.", ActionStatement: "No action is required.",
		}},
	}

	vex, err := fixture.service.UploadVEXPayload(context.Background(), fixture.actor, "rel_1", "", testPayloadSource(`{"author":"security@example.test"}`))
	if err != nil {
		t.Fatalf("UploadVEXPayload: %v", err)
	}
	state := fixture.transactions.state
	if len(state.payloads) != 0 || len(state.outbox) != 1 || state.outbox[0].Kind != "parse_vex" {
		t.Fatalf("no-object state payloads=%#v outbox=%#v", state.payloads, state.outbox)
	}
	job := state.outbox[0]
	if job.Payload["worker_create_decisions"] != true || job.Payload["decision_request_schema"] != VEXDecisionRequestSchemaVersion || job.Payload["payload_ref"] != "" || job.Payload["evidence_id"] != vex.EvidenceID || job.Payload["release_id"] != vex.ReleaseID || job.Payload["artifact_id"] != "" {
		t.Fatalf("no-object parse job = %#v", job)
	}
	requireNormalizedVEXStatement(t, job.Payload, 0, 1, "CVE-2026-0904", []string{"pkg:generic/api@1"}, "not_affected")
	var report evidencedomain.VEXImportReport
	for _, value := range state.vexImportReports {
		report = value
	}
	if report.Status != "accepted" || report.DecisionsCreated != 0 || report.DecisionsSuperseded != 0 || !stringSliceContains(report.Warnings, VEXAsyncDecisionWarning) {
		t.Fatalf("no-object report = %#v", report)
	}
	if state.audit[1].EntryType != "vex.accepted" {
		t.Fatalf("no-object VEX audit = %#v", state.audit)
	}
}

func TestUploadCycloneDXVEXRollsBackEvidenceDocumentReportAuditsAndJobsTogether(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.parser.vex = ParsedVEX{
		Format: "cyclonedx", Author: "cyclonedx", Version: "1.6", ParserVersion: CycloneDXVEXParserVersion,
		StatementCount: 2, ValidStatementCount: 1, StatusSummary: map[string]int{"fixed": 1},
		Statements: []VEXDecisionStatement{{
			StatementIndex: 1, Vulnerability: "CVE-2026-0905", Products: []string{"pkg:generic/api@1"}, Status: "fixed",
			Justification: "fixed_in_release", ImpactStatement: "Fixed before release.", ActionStatement: "Upgrade to this release.",
		}},
		InvalidStatements: []evidencedomain.VEXImportIssue{{StatementIndex: 2, Code: "missing_vulnerability", Detail: "missing id"}},
	}
	fixture.transactions.auditFailAt = 2

	_, err := fixture.service.UploadCycloneDXVEX(context.Background(), fixture.actor, "rel_1", "", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`))
	if !errors.Is(err, errAuditFailure) {
		t.Fatalf("UploadCycloneDXVEX error = %v, want audit failure", err)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 0 || len(state.vexDocuments) != 0 || len(state.vexImportReports) != 0 || len(state.payloads) != 0 || len(state.audit) != 0 || len(state.outbox) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("partial VEX state survived rollback: %#v", state)
	}
}

func TestUploadVEXPayloadRejectsInvalidParserProjectionBeforeStaging(t *testing.T) {
	tests := []struct {
		name   string
		parsed ParsedVEX
	}{
		{name: "format mismatch", parsed: ParsedVEX{Format: "cyclonedx", Author: "author", ParserVersion: OpenVEXParserVersion, StatementCount: 1, ValidStatementCount: 1, StatusSummary: map[string]int{"fixed": 1}, Statements: []VEXDecisionStatement{{StatementIndex: 1, Vulnerability: "CVE-2026-0906", Products: []string{"pkg:generic/api@1"}, Status: "fixed"}}}},
		{name: "parser version mismatch", parsed: ParsedVEX{Format: "openvex", Author: "author", ParserVersion: CycloneDXVEXParserVersion, StatementCount: 1, ValidStatementCount: 1, StatusSummary: map[string]int{"fixed": 1}, Statements: []VEXDecisionStatement{{StatementIndex: 1, Vulnerability: "CVE-2026-0906", Products: []string{"pkg:generic/api@1"}, Status: "fixed"}}}},
		{name: "all invalid", parsed: ParsedVEX{Format: "openvex", Author: "author", ParserVersion: OpenVEXParserVersion, StatementCount: 1, ValidStatementCount: 0, InvalidStatements: []evidencedomain.VEXImportIssue{{StatementIndex: 1, Code: "invalid", Detail: "invalid"}}}},
		{name: "summary mismatch", parsed: ParsedVEX{Format: "openvex", Author: "author", ParserVersion: OpenVEXParserVersion, StatementCount: 1, ValidStatementCount: 1, StatusSummary: map[string]int{"fixed": 2}, Statements: []VEXDecisionStatement{{StatementIndex: 1, Vulnerability: "CVE-2026-0906", Products: []string{"pkg:generic/api@1"}, Status: "fixed"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvidenceServiceFixture(t)
			fixture.parser.vex = test.parsed
			_, err := fixture.service.UploadVEXPayload(context.Background(), fixture.actor, "rel_1", "", testPayloadSource(`{"author":"security@example.test"}`))
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("UploadVEXPayload error = %v, want validation", err)
			}
			if fixture.objects.sourceStageCalls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
				t.Fatalf("invalid projection reached effects: objects=%#v tx=%#v", fixture.objects, fixture.transactions)
			}
		})
	}
}

func requireNormalizedVEXStatement(t *testing.T, payload map[string]any, position, statementIndex int, vulnerability string, products []string, status string) {
	t.Helper()
	statements, ok := payload["decision_statements"].([]map[string]any)
	if !ok || len(statements) <= position {
		t.Fatalf("normalized VEX decision statements = %#v", payload["decision_statements"])
	}
	statement := statements[position]
	if statement["statement_index"] != statementIndex || statement["vulnerability"] != vulnerability || statement["status"] != status {
		t.Fatalf("normalized VEX decision statement = %#v", statement)
	}
	gotProducts, ok := statement["products"].([]string)
	if !ok || strings.Join(gotProducts, "\x00") != strings.Join(products, "\x00") {
		t.Fatalf("normalized VEX decision products = %#v, want %#v", statement["products"], products)
	}
}

func stringSliceContains(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}
