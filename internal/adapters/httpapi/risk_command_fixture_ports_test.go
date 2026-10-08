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
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// These bridges exist only in the HTTP test binary. Actual Risk authorizers
// check current credentials/grants; writes use the isolated replay clone.
// They are not a runtime backend or a proof of PostgreSQL locking.
type riskCommandFixture struct{ catalogFixtureCommands }

// The known scan ID is only a locator. The native query uses a current repository
// reader, or an explicitly supplied immutable receipt in the synchronous
// characterization. Actual source/parent authority is always rechecked.
type vexDecisionPointFixture struct {
	riskCommandFixture
	scanID     string
	scanReader evidencequery.VulnerabilityScanPointReader
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
	var scan evidencedomain.VulnerabilityScan
	var err error
	if f.scanReader != nil {
		query, buildErr := evidencequery.NewVulnerabilityScanPoints(f.scanReader)
		if buildErr != nil {
			return buildErr
		}
		scan, err = query.GetVulnerabilityScan(ctx, reader, f.scanID)
		err = legacyParsedPointError(err)
	} else {
		scan, err = (evidenceReadFixture{f.catalogFixtureCommands}).GetVulnerabilityScan(ctx, reader, f.scanID)
	}
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
	evidence, err := ledger.GetEvidence(ctx, reader, scan.EvidenceID)
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
	authorizer := riskapp.NewVulnerabilityDecisionWriteAuthorizer()
	if err := authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: app.ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if err := validateControlEvidencePathID(id); err != nil {
		return err
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Governance.(riskapp.WaiverCommandReader)
		if !ok {
			return app.ErrValidation
		}
		// This authority-only finding read validates current typed scan/evidence/
		// product/release parents and ambiguity without reading decision history.
		owner, err := reader.ReadWaiverSubject(ctx, actor.TenantID, "finding", id)
		if err != nil {
			return err
		}
		if owner.TenantID != actor.TenantID || owner.ID != id || owner.Type != "finding" || owner.ProductID == "" || owner.ReleaseID == "" {
			return app.ErrNotFound
		}
		return authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: app.ScopeEvidenceWrite, Resources: application.ResourceReferences{ProductID: owner.ProductID, ReleaseID: owner.ReleaseID}})
	})
}

func (f riskCommandFixture) CreateVulnerabilityDecision(ctx context.Context, actor domain.Actor, id string, input riskapp.CreateVulnerabilityDecisionInput) (riskdomain.VulnerabilityDecision, error) {
	refs := make([]domain.SubjectRef, 0, len(input.SupportingRefs))
	for _, ref := range input.SupportingRefs {
		refs = append(refs, domain.SubjectRef{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
	}
	value, err := f.commandLedger(ctx).CreateVulnerabilityDecision(ctx, actor, id, app.CreateVulnerabilityDecisionInput{Status: input.Status, Justification: input.Justification, ImpactStatement: input.ImpactStatement, ActionStatement: input.ActionStatement, CustomerVisible: input.CustomerVisible, InternalNotes: input.InternalNotes, EvidenceIDs: slices.Clone(input.EvidenceIDs), SupportingRefs: refs, VEXDocumentID: input.VEXDocumentID, ReviewedAt: copyDecisionSummaryTime(input.ReviewedAt), ReviewDueAt: copyDecisionSummaryTime(input.ReviewDueAt)})
	if err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	return domain.VulnerabilityDecisionToContextModel(value)
}

func (f riskCommandFixture) AuthorizeEvaluateRelease(ctx context.Context, actor domain.Actor, id string) error {
	authorizer := riskapp.NewPolicyEvaluationAuthorizer()
	if err := authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: app.ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if err := validateControlEvidencePathID(id); err != nil {
		return err
	}
	// Use the actual tenant-bound point reads as the fixture's internal owner
	// lookup, not the request actor's read grants: evaluating is verify:read.
	// No result is exposed until the actual Risk write authorizer has checked
	// the request actor's current grant against the resolved coordinates.
	reader := domain.Actor{TenantID: actor.TenantID, KeyID: "fixture-owner-reader", Scopes: []string{"product:read", "release:read"}}
	query := catalogQueryFixture(f)
	release, err := query.GetRelease(ctx, reader, id)
	if err != nil {
		return mapCatalogPointQueryError(err)
	}
	if release.TenantID != actor.TenantID || release.ID != id || release.ProductID == "" {
		return app.ErrNotFound
	}
	product, err := query.GetProduct(ctx, reader, release.ProductID)
	if err != nil {
		return mapCatalogPointQueryError(err)
	}
	if product.ID != release.ProductID || product.TenantID != actor.TenantID {
		return app.ErrNotFound
	}
	return authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: app.ScopeVerifyRead, Resources: application.ResourceReferences{ProductID: product.ID, ReleaseID: id}})
}

func policyEvaluationFixtureModel(value domain.PolicyEvaluation) riskdomain.PolicyEvaluation {
	checks := make([]riskdomain.PolicyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, riskdomain.PolicyCheck{Name: check.Name, Result: check.Result, Severity: check.Severity, Missing: slices.Clone(check.Missing), Explanation: check.Explanation, Remediation: check.Remediation})
	}
	return riskdomain.PolicyEvaluation{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, Result: value.Result, PolicySet: value.PolicySet, Checks: checks, CreatedAt: value.CreatedAt}
}

func (f riskCommandFixture) EvaluateRelease(ctx context.Context, actor domain.Actor, id string) (riskdomain.PolicyEvaluation, error) {
	value, err := f.commandLedger(ctx).EvaluateRelease(ctx, actor, id)
	return policyEvaluationFixtureModel(value), err
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
