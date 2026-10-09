package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type failingRiskCommandFixture struct {
	riskCommandFixture
	changedID string
	isolated  bool
}

func (f *failingRiskCommandFixture) failure(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private risk fixture failure after write")
}
func (f *failingRiskCommandFixture) CreateVulnerabilityDecision(ctx context.Context, a domain.Actor, id string, in riskapp.CreateVulnerabilityDecisionInput) (riskdomain.VulnerabilityDecision, error) {
	v, err := f.riskCommandFixture.CreateVulnerabilityDecision(ctx, a, id, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingRiskCommandFixture) EvaluateRelease(ctx context.Context, a domain.Actor, id string) (riskdomain.PolicyEvaluation, error) {
	v, err := f.riskCommandFixture.EvaluateRelease(ctx, a, id)
	return v, f.failure(ctx, v.ID, err)
}

func newRiskCommandRegressionLedger(t *testing.T) (*app.Ledger, *app.MemoryUnitOfWorkFactory) {
	t.Helper()
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }})
	return ledger, factory
}

func TestRiskCommandFixturesRollBackDecisionSupersessionEvaluationAndAudit(t *testing.T) {
	for _, action := range []string{"decision", "evaluation"} {
		t.Run(action, func(t *testing.T) {
			ledger, factory := newRiskCommandRegressionLedger(t)
			owner := seedRiskQueryFixtureScope(t, ledger, "Owner")
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingRiskCommandFixture{riskCommandFixture: riskCommandFixture{catalogFixtureCommands{ledger: ledger}}}
			server.vulnerabilityDecisionCommands, server.policyEvaluationCommands = commands, commands
			path, body := "/v1/vulnerability-findings/"+owner.head.FindingID+"/decisions", `{"status":"fixed","justification":"reviewed","impact_statement":"patched","action_statement":"ship patch","internal_notes":"private triage"}`
			if action == "evaluation" {
				path, body = "/v1/policies/evaluate", fmt.Sprintf(`{"release_id":%q}`, owner.release.ID)
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, owner.secret, path, "risk-failure", []byte(body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, `"data"`) || strings.Contains(out, commands.changedID) || strings.Contains(out, "private") {
				t.Fatal("failed Risk command disclosed or bypassed isolated effects")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed Risk command lost its failure record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil {
					t.Fatal("failed Risk command cached partial success")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed Risk command committed a decision, supersession, evaluation, audit or job")
			}
		})
	}
}

func TestRiskCommandFixturesRecheckCurrentAuthorityAndPreserveExactReplay(t *testing.T) {
	ledger, factory := newRiskCommandRegressionLedger(t)
	owner := seedRiskQueryFixtureScope(t, ledger, "Owner")
	foreign := seedRiskQueryFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceWrite, app.ScopeVerifyRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite, app.ScopeVerifyRead}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	server.durableCommandExecutor = riskFixtureReplayExecutor{catalogFixtureReplayExecutor{ledger: ledger}}
	for _, tc := range []struct{ path, body, key string }{
		{"/v1/vulnerability-findings/" + owner.head.FindingID + "/decisions", `{"status":"fixed","justification":"reviewed","impact_statement":"patched","action_statement":"ship patch","customer_visible":true,"internal_notes":"private triage"}`, "decision"},
		{"/v1/policies/evaluate", fmt.Sprintf(`{"release_id":%q}`, owner.release.ID), "evaluation"},
	} {
		original := postRaw(t, server, owner.secret, tc.path, tc.key, []byte(tc.body), 201)
		if strings.Contains(original, "private triage") || strings.Contains(original, "internal_notes") {
			t.Fatal("Risk command disclosed internal notes")
		}
		before, err := factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if replay := postRaw(t, server, owner.secret, tc.path, tc.key, []byte(tc.body), 201); replay != original {
			t.Fatal("Risk fixture did not replay the identical HTTP response")
		}
		for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
			auth.actor.ResourceGrants = grants
			postRaw(t, server, owner.secret, tc.path, tc.key, []byte(tc.body), 403)
		}
		auth.actor = human
		postRaw(t, server, owner.secret, tc.path, tc.key, []byte(tc.body+" "), 409)
		after, err := factory.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("completed/denied/conflicting Risk retries reapplied effects", err)
		}
	}
	guards := riskCommandFixture{catalogFixtureCommands{ledger: ledger}}
	pointGuard := vexDecisionPointFixture{riskCommandFixture: guards, scanID: owner.head.ScanID}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		run  func(context.Context, domain.Actor) error
	}{
		{"decision", func(ctx context.Context, a domain.Actor) error {
			return guards.AuthorizeVulnerabilityDecision(ctx, a, owner.head.FindingID)
		}},
		{"synchronous-vex-decision", func(ctx context.Context, a domain.Actor) error {
			return pointGuard.AuthorizeVulnerabilityDecision(ctx, a, owner.head.FindingID)
		}},
		{"evaluation", func(ctx context.Context, a domain.Actor) error {
			return guards.AuthorizeEvaluateRelease(ctx, a, owner.release.ID)
		}},
	} {
		if err := tc.run(t.Context(), human); err != nil {
			t.Fatal("owned Risk guard requires unrelated read scopes", tc.name, err)
		}
		if err := tc.run(t.Context(), foreign.actor); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("Risk guard accepted a foreign resource", tc.name, err)
		}
		for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
			denied := human
			denied.ResourceGrants = grants
			if err := tc.run(t.Context(), denied); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("Risk guard retained wrong or removed grants", tc.name, err)
			}
		}
		denied := human
		denied.Scopes = []string{"product:read"}
		if err := tc.run(t.Context(), denied); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("Risk guard omitted credential scope", tc.name, err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := tc.run(ctx, human); !errors.Is(err, context.Canceled) {
			t.Fatal("Risk guard ignored cancellation", tc.name, err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("Risk authority checks changed repository state", err)
	}
}

func TestRiskPolicyEvaluationFixtureMappingRetainsDetachedHistory(t *testing.T) {
	value := domain.PolicyEvaluation{ID: "evaluation", TenantID: "tenant", ReleaseID: "release", Result: "failed", PolicySet: "release-readiness.v1", Checks: []domain.PolicyCheck{{Name: "blocking_findings", Result: "failed", Severity: "error", Missing: []string{"finding"}, Explanation: "review needed", Remediation: "record decision"}}, CreatedAt: time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)}
	model := policyEvaluationFixtureModel(value)
	if !reflect.DeepEqual(domain.PolicyEvaluationFromContext(model), value) {
		t.Fatal("policy evaluation fixture lost recorded check metadata")
	}
	model.Checks[0].Missing[0], model.Checks[0].Explanation = "changed", "changed"
	if value.Checks[0].Missing[0] != "finding" || value.Checks[0].Explanation != "review needed" {
		t.Fatal("policy evaluation fixture shared mutable historical checks")
	}
}
