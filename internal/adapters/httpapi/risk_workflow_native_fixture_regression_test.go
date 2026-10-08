package httpapi

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestRiskWorkflowNativeFixturesRetainExplicitResourcesAndCommitOnlyOwnedRowsAndAudit(t *testing.T) {
	for _, kind := range []string{"creation", "evaluation", "workflow"} {
		t.Run(kind, func(t *testing.T) {
			ledger, factory := integrationRegressionLedger()
			owner := seedRiskWorkflowFixtureScope(t, ledger, "Owner")
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			clock := &evidenceFlowFixtureClock{at: owner.release.CreatedAt.Add(time.Hour).Add(1234 * time.Nanosecond)}
			idCalls := 0
			ids := application.IDGeneratorFunc(func(prefix string) string { idCalls++; return fmt.Sprintf("%s-native-%d", prefix, idCalls) })
			server.bindRiskWorkflowFixtureResources(clock, ids)
			rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { panic("Risk command consulted aggregate clock") }})
			server.bindLegacyLedgerFixture(rebound)
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			at := clock.at.UTC().Truncate(time.Microsecond)
			var got, want any
			var changedID, auditKind, subjectType, subjectID, hash string
			switch kind {
			case "creation":
				in := riskapp.CreateCustomPolicyInput{Name: " Native policy ", Version: "2", Description: " Requirements ", Rules: []riskdomain.PolicyRule{{Name: "SBOM", EvidenceType: "sbom", Severity: "high", Required: true}}}
				value, callErr := server.customPolicyCommands.CreateCustomPolicy(t.Context(), owner.actor, in)
				got, err = value, callErr
				changedID, auditKind, subjectType, subjectID = "cpol-native-1", "custom_policy.created", "custom_policy", "cpol-native-1"
				want = riskdomain.CustomPolicy{ID: changedID, TenantID: owner.actor.TenantID, Name: "Native policy", Version: "2", Description: "Requirements", Rules: in.Rules, SchemaVersion: riskdomain.CustomPolicySchemaVersion, CreatedAt: at}
			case "evaluation":
				checks := []riskdomain.PolicyCheck{}
				for _, rule := range owner.policy.Rules {
					checks = append(checks, riskdomain.EvaluateCustomPolicyRule(riskdomain.PolicyRule(rule), false))
				}
				hash, err = application.NormalizedJSONHash(map[string]any{"policy": owner.policy, "release_id": owner.release.ID, "checks": domain.CustomPolicyChecksFromContext(checks)})
				if err != nil {
					t.Fatal(err)
				}
				value, callErr := server.customPolicyCommands.EvaluateCustomPolicy(t.Context(), owner.actor, owner.policy.ID, owner.release.ID)
				got, err = value, callErr
				changedID, auditKind, subjectType, subjectID = "cpe-native-1", "custom_policy.evaluated", "custom_policy_evaluation", "cpe-native-1"
				want = riskdomain.CustomPolicyEvaluation{ID: changedID, TenantID: owner.actor.TenantID, PolicyID: owner.policy.ID, ReleaseID: owner.release.ID, Result: "failed", Checks: checks, InputHash: hash, SchemaVersion: riskdomain.CustomPolicyEvalSchemaVersion, CreatedAt: at}
			case "workflow":
				value, callErr := server.vulnerabilityWorkflowCommands.RecordVulnerabilityWorkflow(t.Context(), owner.actor, riskapp.RecordVulnerabilityWorkflowInput{FindingID: owner.head.FindingID, Action: "reopened", Reason: " Review "})
				got, err = value, callErr
				changedID, auditKind, subjectType, subjectID = "vw-native-1", "vulnerability_workflow.reopened", "vulnerability_finding", owner.head.FindingID
				want = riskdomain.VulnerabilityWorkflowRecord{ID: changedID, TenantID: owner.actor.TenantID, FindingID: owner.head.FindingID, ReleaseID: owner.release.ID, Action: "reopened", Reason: "Review", ActorID: owner.actor.KeyID, SchemaVersion: riskdomain.VulnerabilityWorkflowSchemaVersion, CreatedAt: at}
			}
			if err != nil || !reflect.DeepEqual(got, want) || clock.calls != 1 || idCalls != 2 {
				t.Fatal("native Risk command lost complete DTO or resources", got, want, err)
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			entries := after.AuditEntries[owner.actor.TenantID]
			if len(entries) != len(before.AuditEntries[owner.actor.TenantID])+1 {
				t.Fatal("Risk command did not append exactly one audit")
			}
			entry := entries[len(entries)-1]
			if entry.ID != "ace-native-2" || entry.EntryType != auditKind || entry.SubjectType != subjectType || entry.SubjectID != subjectID || entry.ActorID != owner.actor.KeyID || entry.ActorType != "api_key" || entry.PayloadHash != hash || !entry.OccurredAt.Equal(at) {
				t.Fatal("Risk audit lost committed subject, actor, hash or time", entry)
			}
			var persisted any
			wantPersisted := want
			switch kind {
			case "creation":
				persisted = domain.CustomPolicyToContext(after.CustomPolicies[changedID])
				delete(after.CustomPolicies, changedID)
			case "evaluation":
				persisted = after.CustomPolicyEvaluations[changedID]
				wantPersisted = domain.CustomPolicyEvaluationFromContext(want.(riskdomain.CustomPolicyEvaluation))
				delete(after.CustomPolicyEvaluations, changedID)
			case "workflow":
				persisted = riskdomain.VulnerabilityWorkflowRecord(after.VulnerabilityWorkflow[changedID])
				delete(after.VulnerabilityWorkflow, changedID)
			}
			if !reflect.DeepEqual(persisted, wantPersisted) {
				t.Fatal("response and committed row diverged", persisted, wantPersisted)
			}
			after.AuditEntries[owner.actor.TenantID] = before.AuditEntries[owner.actor.TenantID]
			if !reflect.DeepEqual(before, after) {
				t.Fatal("native Risk command changed unrelated state or enqueued work")
			}
		})
	}
}

func TestRiskWorkflowNativeFixturesRejectMissingRepositoriesAndKeepExplicitPorts(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	custom := &policyHTTPFake{}
	workflow := &workflowHTTPFake{}
	server.customPolicyCommands, server.vulnerabilityWorkflowCommands = custom, workflow
	server.bindRiskWorkflowFixtureCommands(ledger)
	server.bindRiskWorkflowFixtureResources(application.ClockFunc(time.Now), application.IDGeneratorFunc(application.NewID))
	if server.customPolicyCommands != custom || server.vulnerabilityWorkflowCommands != workflow {
		t.Fatal("resource rebinding replaced explicit command ports")
	}
	transactions := riskWorkflowNativeFixtureTransactions{catalogFixtureCommands{ledger: ledger}}
	if err := transactions.ExecuteCustomPolicy(t.Context(), func(context.Context, riskapp.CustomPolicyTransaction) error {
		t.Fatal("missing repository callback executed")
		return nil
	}); err != app.ErrValidation {
		t.Fatal("missing repositories used aggregate fallback", err)
	}
}
