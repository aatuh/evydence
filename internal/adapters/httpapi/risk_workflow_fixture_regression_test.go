package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type failingRiskWorkflowFixture struct {
	riskWorkflowFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingRiskWorkflowFixture) failure(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private Risk workflow fixture failure after write")
}
func (f *failingRiskWorkflowFixture) CreateCustomPolicy(ctx context.Context, a domain.Actor, in riskapp.CreateCustomPolicyInput) (riskdomain.CustomPolicy, error) {
	v, err := f.riskWorkflowFixtureCommands.CreateCustomPolicy(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingRiskWorkflowFixture) EvaluateCustomPolicy(ctx context.Context, a domain.Actor, policy, release string) (riskdomain.CustomPolicyEvaluation, error) {
	v, err := f.riskWorkflowFixtureCommands.EvaluateCustomPolicy(ctx, a, policy, release)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingRiskWorkflowFixture) RecordVulnerabilityWorkflow(ctx context.Context, a domain.Actor, in riskapp.RecordVulnerabilityWorkflowInput) (riskdomain.VulnerabilityWorkflowRecord, error) {
	v, err := f.riskWorkflowFixtureCommands.RecordVulnerabilityWorkflow(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}

type riskWorkflowFixtureScope struct {
	riskQueryFixtureScope
	policy domain.CustomPolicy
}

func seedRiskWorkflowFixtureScope(t *testing.T, ledger *app.Ledger, name string) riskWorkflowFixtureScope {
	t.Helper()
	f := riskWorkflowFixtureScope{riskQueryFixtureScope: seedRiskQueryFixtureScope(t, ledger, name)}
	var err error
	f.policy, err = ledger.CreateCustomPolicy(t.Context(), f.actor, app.CreateCustomPolicyInput{Name: "Fixture policy", Version: "1", Description: "Recorded requirements", Rules: []domain.PolicyRule{{Name: "SBOM required", EvidenceType: "sbom", Severity: "high", Required: true}, {Name: "Build optional", EvidenceType: "build", Severity: "low", Required: false}}})
	if err != nil {
		t.Fatal("seed policy:", err)
	}
	return f
}

type riskWorkflowFixtureRequest struct{ name, path, body string }

func riskWorkflowFixtureRequests(f riskWorkflowFixtureScope) []riskWorkflowFixtureRequest {
	return []riskWorkflowFixtureRequest{
		{"creation", "/v1/custom-policies", `{"name":"New policy","version":"2","description":"Recorded guidance","rules":[{"name":"SBOM required","evidence_type":"sbom","severity":"high","required":true},{"name":"Build optional","evidence_type":"build","severity":"low","required":false}]}`},
		{"evaluation", "/v1/custom-policies/" + f.policy.ID + "/evaluate", fmt.Sprintf(`{"release_id":%q}`, f.release.ID)},
		{"workflow", "/v1/vulnerability-findings/" + f.head.FindingID + "/workflow", `{"action":"scanner_disagreement","reason":"Review with Security Team"}`},
	}
}
func TestRiskWorkflowFixturesRollbackPolicyEvaluationWorkflowAuditAndReplay(t *testing.T) {
	for index := 0; index < 3; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedRiskWorkflowFixtureScope(t, ledger, "Owner")
		request := riskWorkflowFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingRiskWorkflowFixture{riskWorkflowFixtureCommands: riskWorkflowFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.customPolicyCommands, server.vulnerabilityWorkflowCommands = commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, `"data"`) || strings.Contains(out, commands.changedID) || strings.Contains(out, "private Risk") {
				t.Fatal("partial or non-isolated Risk workflow effects")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("failed receipt missing", err)
			}
			for key, record := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil) {
					t.Fatal("Risk workflow partial response cached")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("Risk workflow failure committed policy/evaluation/workflow/audit/outbox effects")
			}
		})
	}
}
func TestRiskWorkflowFixturesReplayRechecksCurrentHumanGrantsAndForeignParents(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedRiskWorkflowFixtureScope(t, ledger, "Owner")
	foreign := seedRiskWorkflowFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "reviewer", Scopes: []string{"policy:write", "policy:read", "security:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"policy:write"}}, {ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"policy:read", "security:write"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, request := range riskWorkflowFixtureRequests(owner) {
		t.Run(request.name, func(t *testing.T) {
			original := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201)
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			entries := before.AuditEntries[owner.actor.TenantID]
			last := entries[len(entries)-1]
			if last.ActorType != "human_user" || last.ActorID != human.UserID {
				t.Fatal("Risk workflow lost human audit identity", last)
			}
			assertTrustHTTPReplay(t, original, postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201))
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
			}
			auth.actor = human
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body+" "), 409)
			if request.name != "creation" {
				auth.actor.TenantID = foreign.actor.TenantID
				auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"*"}}}
				postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 404)
				auth.actor = human
			}
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("Risk workflow replay/denial/conflict added effects", err)
			}
		})
	}
	guard := riskWorkflowFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, check := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"create", func(ctx context.Context) error {
			return guard.AuthorizeCreateCustomPolicy(ctx, human, riskapp.CreateCustomPolicyInput{Name: "Read only", Version: "1", Rules: []riskdomain.PolicyRule{{Name: "Rule", EvidenceType: "sbom", Severity: "high", Required: true}}})
		}},
		{"evaluate", func(ctx context.Context) error {
			return guard.AuthorizeEvaluateCustomPolicy(ctx, human, owner.policy.ID, owner.release.ID)
		}},
		{"workflow", func(ctx context.Context) error {
			return guard.AuthorizeVulnerabilityWorkflow(ctx, human, riskapp.RecordVulnerabilityWorkflowInput{FindingID: owner.head.FindingID, Action: "scanner_disagreement", Reason: "Review"})
		}},
	} {
		if err := check.run(t.Context()); err != nil {
			t.Fatal(check.name, err)
		}
		if err := check.run(cancelled); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled Risk guard accepted", check.name, err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("Risk workflow guard mutated state", err)
	}
	// A release-less annotation needs current tenant-wide security permission,
	// not an inferred release or a narrower product grant.
	// Current upload commands require a release, but existing release-less rows
	// are still supported by workflow authority. Seed the actual repository,
	// not an invalid current-upload request or fabricated successful read.
	source, err := ledger.CreateEvidence(t.Context(), owner.actor, app.CreateEvidenceInput{ProductID: owner.product.ID, Type: "vulnerability_scan", Title: "Legacy scan", SourceSystem: "fixture", PayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal("release-less source:", err)
	}
	scan := domain.VulnerabilityScan{ID: "legacy-release-less-scan", TenantID: human.TenantID, EvidenceID: source.ID, Scanner: "fixture", TargetRef: "pkg:oci/tenant", Findings: []domain.VulnerabilityFinding{{ID: "legacy-release-less-finding"}}, CreatedAt: owner.release.CreatedAt}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, repos app.Repositories) error {
		return repos.Evidence.InsertVulnerabilityScan(ctx, scan)
	}); err != nil {
		t.Fatal("release-less repository scan:", err)
	}
	before, err = factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	in := riskapp.RecordVulnerabilityWorkflowInput{FindingID: scan.Findings[0].ID, Action: "reopened", Reason: "Tenant-wide review"}
	if err := guard.AuthorizeVulnerabilityWorkflow(t.Context(), human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("product grant authorized release-less workflow", err)
	}
	tenantActor := human
	tenantActor.ResourceGrants = append(tenantActor.ResourceGrants, domain.ResourceGrant{ResourceType: "tenant", ResourceID: human.TenantID, Scopes: []string{"security:write"}})
	if err := guard.AuthorizeVulnerabilityWorkflow(t.Context(), tenantActor, in); err != nil {
		t.Fatal("tenant-wide release-less workflow rejected", err)
	}
	if err := guard.AuthorizeVulnerabilityWorkflow(t.Context(), human, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("release-less workflow retained revoked tenant authority", err)
	}
	after, err = factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("release-less authority checks added effects", err)
	}
}
