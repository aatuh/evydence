package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestPolicyEvaluationFixtureUsesCurrentRepositoryAndCommitsEvaluationWithAudit(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }})
	owner := seedRiskQueryFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	body := []byte(fmt.Sprintf(`{"release_id":%q}`, owner.release.ID))
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	response := postRaw(t, server, "fixture", "/v1/policies/evaluate", "evaluation-native", body, http.StatusCreated)
	var envelope struct {
		Data struct {
			ID        string `json:"id"`
			ReleaseID string `json:"release_id"`
			PolicySet string `json:"policy_set"`
			Checks    []any  `json:"checks"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil || envelope.Data.ID == "" || envelope.Data.ReleaseID != owner.release.ID || envelope.Data.PolicySet == "" || len(envelope.Data.Checks) == 0 {
		t.Fatal("policy evaluation lost current owned readiness result", response, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.PolicyEvaluations) != len(before.PolicyEvaluations)+1 || after.PolicyEvaluations[envelope.Data.ID].ReleaseID != owner.release.ID {
		t.Fatal("policy evaluation was not committed to the current repository")
	}
	audits := 0
	for _, entry := range after.AuditEntries[owner.actor.TenantID] {
		if entry.EntryType == "policy.evaluated" && entry.SubjectID == envelope.Data.ID && entry.TenantID == owner.actor.TenantID {
			audits++
		}
	}
	if audits != 1 {
		t.Fatal("policy evaluation lacks exactly one matching committed audit")
	}
	factory.fail = true
	response = postRaw(t, server, "fixture", "/v1/policies/evaluate", "evaluation-failure", body, http.StatusInternalServerError)
	for _, private := range []string{"private-query-commit-secret", "private triage", `"data"`, `"checks"`} {
		if strings.Contains(response, private) {
			t.Fatal("failed evaluation commit disclosed private diagnostics or partial result", response)
		}
	}
	factory.fail = false
	failed, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed policy evaluation published evaluation, audit or outbox state", err)
	}
}

func TestPolicyEvaluationFixtureCommandIgnoresAggregateClockAndReturnsNoResultOnCommitFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory})
	owner := seedRiskQueryFixtureScope(t, ledger, "Owner")
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("policy command consulted aggregate clock") }})
	commands := riskCommandFixture{catalogFixtureCommands{ledger: rebound}}
	if err := commands.AuthorizeEvaluateRelease(t.Context(), owner.actor, owner.release.ID); err != nil {
		t.Fatal("native policy guard could not use current repository", err)
	}
	value, err := commands.EvaluateRelease(t.Context(), owner.actor, owner.release.ID)
	if err != nil || value.ID == "" || value.ReleaseID != owner.release.ID || value.CreatedAt.IsZero() {
		t.Fatal("native policy command lost its own evaluation clock or current facts", err)
	}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	value, err = commands.EvaluateRelease(t.Context(), owner.actor, owner.release.ID)
	if err == nil || !reflect.DeepEqual(value, riskdomain.PolicyEvaluation{}) {
		t.Fatal("failed policy commit returned a partial evaluation", err)
	}
	factory.fail = false
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed direct policy command changed committed state", err)
	}
}
