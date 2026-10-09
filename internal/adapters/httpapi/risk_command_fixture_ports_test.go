package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// These bridges exist only in the HTTP test binary. Actual Risk authorizers
// check current credentials/grants; writes use the isolated replay clone.
// They are not a runtime backend or a proof of PostgreSQL locking.
type riskCommandFixture struct{ catalogFixtureCommands }

// Only the synchronous repository-free characterization explicitly supplies
// immutable receipt readers. Ordinary readers use current repository rows.
type vexDecisionPointFixture struct {
	riskCommandFixture
	scanID         string
	scanReader     evidencequery.VulnerabilityScanPointReader
	evidenceReader evidencequery.EvidencePointReader
}

func (f vexDecisionPointFixture) AuthorizeVulnerabilityDecision(ctx context.Context, actor domain.Actor, id string) error {
	authorizer := riskapp.NewVulnerabilityDecisionWriteAuthorizer()
	if err := authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: app.ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if err := validateControlEvidencePathID(id); err != nil {
		return err
	}
	reader := domain.Actor{TenantID: actor.TenantID, KeyID: "fixture-owner-reader", Scopes: []string{"evidence:read", "release:read", "product:read"}}
	ledger := f.commandLedger(ctx)
	scanReader := f.scanReader
	if scanReader == nil {
		scanReader = evidenceReadFixture{f.catalogFixtureCommands}
	}
	scanQuery, err := evidencequery.NewVulnerabilityScanPoints(scanReader)
	if err != nil {
		return err
	}
	scan, err := scanQuery.GetVulnerabilityScan(ctx, reader, f.scanID)
	err = legacyParsedPointError(err)
	if err != nil {
		return err
	}
	count := 0
	for _, finding := range scan.Findings {
		if finding.ID == id {
			count++
		}
	}
	if count == 0 || scan.TenantID != actor.TenantID || scan.ReleaseID == "" {
		return app.ErrNotFound
	}
	if count != 1 {
		return app.ErrConflict
	}
	sourceReader := f.evidenceReader
	if sourceReader == nil {
		sourceReader = evidenceReadFixture{catalogFixtureCommands{ledger: ledger}}
	}
	sourceQuery, err := evidencequery.NewEvidencePoints(sourceReader)
	if err != nil {
		return err
	}
	evidence, err := sourceQuery.GetEvidence(ctx, reader, scan.EvidenceID)
	err = legacyParsedPointError(err)
	if err != nil {
		return err
	}
	release, err := ledger.GetRelease(ctx, reader, scan.ReleaseID)
	if err != nil {
		return err
	}
	if evidence.TenantID != actor.TenantID || evidence.Type != "vulnerability_scan" || evidence.ReleaseID != "" && evidence.ReleaseID != release.ID || evidence.ProductID != "" && evidence.ProductID != release.ProductID {
		return app.ErrNotFound
	}
	product, err := ledger.GetProduct(ctx, reader, release.ProductID)
	if err != nil {
		return err
	}
	if product.TenantID != actor.TenantID || release.TenantID != actor.TenantID {
		return app.ErrNotFound
	}
	return authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: app.ScopeEvidenceWrite, Resources: application.ResourceReferences{ProductID: product.ID, ReleaseID: release.ID}})
}

func riskCommandTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	server, secret := governanceTestServer(t)
	server.durableCommandExecutor = riskFixtureReplayExecutor{catalogFixtureReplayExecutor{ledger: legacyFixtureLedger(server)}}
	return server, secret
}

// These two response types are stored as JSON by the explicit repository
// fixture. Normalize the fresh result before storage too, so byte-for-byte HTTP
// replay assertions remain meaningful rather than depending on Go struct order.
type riskFixtureReplayExecutor struct{ catalogFixtureReplayExecutor }

func (e riskFixtureReplayExecutor) WithBody(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if run == nil {
		return 0, nil, app.ErrValidation
	}
	return e.catalogFixtureReplayExecutor.WithBody(ctx, actor, method, path, key, body, authorize, func(ctx context.Context) (int, any, error) {
		status, value, err := run(ctx)
		riskResponse := path == "/v1/policies/evaluate" || strings.HasPrefix(path, "/v1/vulnerability-findings/") && strings.HasSuffix(path, "/decisions")
		if err != nil || !riskResponse {
			return status, value, err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return 0, nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var normalized any
		if err := decoder.Decode(&normalized); err != nil {
			return 0, nil, err
		}
		return status, normalized, nil
	})
}

func (f riskCommandFixture) AuthorizeVulnerabilityDecision(ctx context.Context, actor domain.Actor, id string) error {
	command, err := f.manualDecision()
	if err != nil {
		return err
	}
	return policyEvaluationFixtureError(command.AuthorizeVulnerabilityDecision(ctx, actor, id))
}

func (f riskCommandFixture) CreateVulnerabilityDecision(ctx context.Context, actor domain.Actor, id string, input riskapp.CreateVulnerabilityDecisionInput) (riskdomain.VulnerabilityDecision, error) {
	command, err := f.manualDecision()
	if err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	value, err := command.CreateVulnerabilityDecision(ctx, actor, id, input)
	return value, policyEvaluationFixtureError(err)
}

func (f riskCommandFixture) AuthorizeEvaluateRelease(ctx context.Context, actor domain.Actor, id string) error {
	command, err := f.policyEvaluation()
	if err != nil {
		return err
	}
	return policyEvaluationFixtureError(command.AuthorizeEvaluateRelease(ctx, actor, id))
}

func policyEvaluationFixtureModel(value domain.PolicyEvaluation) riskdomain.PolicyEvaluation {
	checks := make([]riskdomain.PolicyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, riskdomain.PolicyCheck{Name: check.Name, Result: check.Result, Severity: check.Severity, Missing: slices.Clone(check.Missing), Explanation: check.Explanation, Remediation: check.Remediation})
	}
	return riskdomain.PolicyEvaluation{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, Result: value.Result, PolicySet: value.PolicySet, Checks: checks, CreatedAt: value.CreatedAt}
}

func (f riskCommandFixture) EvaluateRelease(ctx context.Context, actor domain.Actor, id string) (riskdomain.PolicyEvaluation, error) {
	command, err := f.policyEvaluation()
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	value, err := command.EvaluateRelease(ctx, actor, id)
	return value, policyEvaluationFixtureError(err)
}

func (s *Server) bindRiskCommandFixturePorts(ledger *app.Ledger) {
	commands := riskCommandFixture{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.vulnerabilityDecisionCommands.(riskCommandFixture); s.vulnerabilityDecisionCommands == nil || fixture {
		s.vulnerabilityDecisionCommands = commands
	}
	if _, fixture := s.policyEvaluationCommands.(riskCommandFixture); s.policyEvaluationCommands == nil || fixture {
		s.policyEvaluationCommands = commands
	}
}

var (
	_ VulnerabilityDecisionCommands = riskCommandFixture{}
	_ PolicyEvaluationCommands      = riskCommandFixture{}
)
