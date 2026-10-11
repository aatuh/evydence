package httpapi

import (
	"fmt"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func newNativeGovernanceAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativeAuthorizationFixture(t)
	commands := governanceFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: f.ledger}}
	expires := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	waiver, err := commands.CreateWaiver(t.Context(), f.owner.actor, riskapp.CreateWaiverInput{ScopeType: "release", ScopeID: f.owner.release.ID, Owner: "Security", Risk: "low", Reason: "Reviewed", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	exception, err := commands.CreateException(t.Context(), f.owner.actor, riskapp.CreateExceptionInput{ReleaseID: f.owner.release.ID, Reason: "Reviewed", Owner: "Security", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	f.waiver, f.exception = domain.Waiver(waiver), domain.Exception(exception)
	return f
}

func newNativeWorkflowAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedRiskWorkflowFixtureScope(t, ledger, "Owner"), seedRiskWorkflowFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, operationsFixtureScope{actor: owner.actor, product: owner.product, release: owner.release, evidence: owner.original}, operationsFixtureScope{actor: foreign.actor, product: foreign.product, release: foreign.release, evidence: foreign.original})
	f.workflow = owner
	return f
}

func newNativeQuestionnaireAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedQuestionnaireFixtureScope(t, ledger, "Owner"), seedQuestionnaireFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner.operationsFixtureScope, foreign.operationsFixtureScope)
	f.questionnaire = owner
	template, err := (packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}).CreateCustomReportTemplate(t.Context(), owner.actor, packageapp.CreateReportTemplateInput{Name: "Review", Version: "1", ReportType: "release", AllowedFields: []string{"subject_id"}, Template: "Reviewed {{.subject_id}}"})
	if err != nil {
		t.Fatal(err)
	}
	f.template = reportTemplateFromCommands(template)
	return f
}

func newNativePeripheralAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedPeripheralFixtureScope(t, ledger, "Owner"), seedPeripheralFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner.operationsFixtureScope, foreign.operationsFixtureScope)
	f.peripheral = owner
	return f
}

func addNativeRiskPackageAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation string
		input     func(nativeAuthorizationFixture) (string, []byte)
		status    int
	}{
		{"createWaiver", func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/waivers", []byte(fmt.Sprintf(`{"scope_type":"release","scope_id":%q,"owner":"Security","risk":"low","reason":"New review","expires_at":"2099-01-01T00:00:00Z"}`, f.owner.release.ID))
		}, 201},
		{"approveWaiver", func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/waivers/" + f.waiver.ID + "/approve", []byte(`{}`)
		}, 200},
		{"createException", func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/exceptions", []byte(fmt.Sprintf(`{"release_id":%q,"owner":"Security","reason":"Reviewed","expires_at":"2099-01-01T00:00:00Z"}`, f.owner.release.ID))
		}, 201},
		{"approveException", func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/exceptions/" + f.exception.ID + "/approve", []byte(`{}`)
		}, 200},
		{"createApproval", func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/approvals", []byte(fmt.Sprintf(`{"subject_type":"waiver","subject_id":%q,"decision":"accepted","reason":"Reviewed","evidence_id":%q}`, f.waiver.ID, f.owner.evidence.ID))
		}, 201},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeGovernanceAuthorizationFixture, tc.input, tc.status, 404)
	}
	for _, tc := range []struct {
		operation              string
		index, foreign, status int
	}{
		{"createCustomPolicy", 0, 0, 201}, {"evaluateCustomPolicy", 1, 404, 201}, {"recordVulnerabilityWorkflow", 2, 404, 201},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeWorkflowAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := riskWorkflowFixtureRequests(f.workflow)[tc.index]
			return r.path, []byte(r.body)
		}, tc.status, tc.foreign)
	}
	cases["createVulnerabilityDecision"] = nativeMutationAuthorizationFixtureCase("createVulnerabilityDecision", newNativeWorkflowAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/vulnerability-findings/" + f.workflow.head.FindingID + "/decisions", []byte(`{"status":"under_investigation","justification":"Reviewing","impact_statement":"Review underway","action_statement":"Review planned"}`)
	}, nativeMutationExpectation{status: 201, foreignStatus: 404, auditDelta: 2}) // superseded plus created
	cases["evaluatePolicy"] = nativeWriteAuthorizationFixtureCase("evaluatePolicy", newNativeWorkflowAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/policies/evaluate", []byte(fmt.Sprintf(`{"release_id":%q}`, f.owner.release.ID))
	}, 201, 404)
	for _, tc := range []struct {
		operation string
		index     int
	}{
		{"createQuestionnaireTemplate", 0}, {"createQuestionnaireAnswerLibraryEntry", 1}, {"createQuestionnairePackage", 2},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeQuestionnaireAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := questionnaireFixtureRequests(f.questionnaire)[tc.index]
			return r.path, []byte(r.body)
		}, 201, 404)
	}
	for _, tc := range []struct {
		operation string
		index     int
	}{{"createEvidenceSummary", 0}, {"createQuestionnaireDraft", 1}} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeQuestionnaireAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := summaryDraftFixtureRequests(f.questionnaire)[tc.index]
			return r.path, []byte(r.body)
		}, 201, 404)
	}
	cases["listQuestionnaireAnswerLibrary"] = nativeReadAuthorizationFixtureCase("listQuestionnaireAnswerLibrary", newNativeQuestionnaireAuthorizationFixture, func(nativeAuthorizationFixture) string { return "/v1/questionnaire-answer-library" }, func(f nativeAuthorizationFixture) string { return f.questionnaire.entry.ID }, 200)
	for _, tc := range []struct {
		operation string
		foreign   int
		input     func(nativeAuthorizationFixture) (string, []byte)
	}{
		{"createReportTemplate", 0, func(nativeAuthorizationFixture) (string, []byte) {
			return "/v1/report-templates", []byte(`{"name":"New review","version":"2","report_type":"release","allowed_fields":["subject_id"],"template":"Review {{.subject_id}}"}`)
		}},
		{"renderReportTemplate", 404, func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/report-templates/" + f.template.ID + "/render", []byte(fmt.Sprintf(`{"subject_type":"release","subject_id":%q}`, f.owner.release.ID))
		}},
		{"createRedactionProfile", 0, func(nativeAuthorizationFixture) (string, []byte) {
			return "/v1/redaction-profiles", []byte(`{"preset":"customer_safe"}`)
		}},
		{"createCustomerPackage", 404, func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/customer-packages", []byte(fmt.Sprintf(`{"product_id":%q,"release_id":%q,"redaction_profile_id":%q,"title":"New package","expires_at":"2099-01-01T00:00:00Z"}`, f.owner.product.ID, f.owner.release.ID, f.questionnaire.pkg.RedactionProfileID))
		}},
		{"createReleaseBundle", 404, func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/release-bundles", []byte(fmt.Sprintf(`{"release_id":%q}`, f.owner.release.ID))
		}},
		{"exportEvidenceBundle", 404, func(f nativeAuthorizationFixture) (string, []byte) {
			return "/v1/evidence-bundles", []byte(fmt.Sprintf(`{"release_id":%q,"evidence_ids":[%q]}`, f.owner.release.ID, f.owner.evidence.ID))
		}},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeQuestionnaireAuthorizationFixture, tc.input, 201, tc.foreign)
	}
	for _, tc := range []struct {
		operation string
		index     int
	}{{"createGraphSnapshot", 0}, {"createMarketplaceCollector", 2}} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativePeripheralAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := peripheralFixtureRequests(f.peripheral, f.owner.actor.TenantID)[tc.index]
			return r.path, []byte(r.body)
		}, 201, 404)
	}
}
