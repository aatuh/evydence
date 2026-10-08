package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

type riskReportFixtureScope struct {
	riskQueryFixtureScope
	scan domain.VulnerabilityScan
}

func seedRiskReportFixtureScope(t *testing.T, ledger *app.Ledger, name string) riskReportFixtureScope {
	t.Helper()
	f := riskReportFixtureScope{riskQueryFixtureScope: riskQueryFixtureScope{evidenceFixtureScope: seedEvidenceFixtureScope(t, ledger, name)}}
	var err error
	f.release, err = ledger.CreateRelease(t.Context(), f.actor, f.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ledger.UploadVulnerabilityScan(t.Context(), f.actor, []byte(fmt.Sprintf(`{"scanner":"grype","target_ref":"pkg:oci/reports","release_id":%q,"findings":[{"vulnerability":"CVE-2026-0001","component":"reviewed","severity":"high","state":"open"},{"vulnerability":"CVE-2026-0002","component":"unreviewed","severity":"high","state":"open"},{"vulnerability":"CVE-2026-0003","component":"critical","severity":"critical","state":"open"}]}`, f.release.ID)))
	if err != nil || len(scan.Findings) != 3 {
		t.Fatal("seed report scan:", err)
	}
	f.scan = scan
	f.head, err = ledger.CreateVulnerabilityDecision(t.Context(), f.actor, scan.Findings[0].ID, app.CreateVulnerabilityDecisionInput{Status: "affected", Justification: "Reviewed", ImpactStatement: "Under review", ActionStatement: "Patch planned", CustomerVisible: true, InternalNotes: "private triage " + name})
	if err != nil {
		t.Fatal("seed report decision:", err)
	}
	return f
}

// Independent expected DTO: no aggregate or native summary query supplies it.
func expectedRiskReportFixtureSummary(f riskReportFixtureScope) domain.ReleaseSecuritySummary {
	missing := make([]domain.ReleaseSecurityMissingDecision, 0, len(f.scan.Findings))
	for _, finding := range f.scan.Findings {
		missing = append(missing, domain.ReleaseSecurityMissingDecision{FindingID: finding.ID, ScanID: f.scan.ID, Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity, State: finding.State})
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].FindingID == missing[j].FindingID {
			return missing[i].ScanID < missing[j].ScanID
		}
		return missing[i].FindingID < missing[j].FindingID
	})
	return domain.ReleaseSecuritySummary{
		Product:    domain.ReleaseSecurityProductSummary{ID: f.product.ID, Name: f.product.Name, Slug: f.product.Slug},
		Release:    domain.ReleaseSecurityReleaseSummary{ID: f.release.ID, Version: f.release.Version, State: f.release.State},
		SBOMStatus: "missing", VulnerabilityScanStatus: "present",
		OpenFindingsBySeverity: map[string]int{"high": 2, "critical": 1}, DecisionsByStatus: map[string]int{"affected": 1},
		MissingRequiredDecisions: missing, ReadinessStatus: "failed", PackageStatus: "not_generated",
		Counts: map[string]int{"artifact_refs": 0, "passed_builds": 0, "build_attestations": 0, "sboms": 0, "vulnerability_scans": 1, "vex_documents": 0, "vulnerability_decisions": 1, "release_bundles": 0, "customer_packages": 0},
		Assumptions: []string{
			"Summary values are derived only from evidence, decisions, exceptions, approvals, bundles, packages, and build records in this Evydence tenant.",
			"Open finding counts reflect uploaded scanner evidence and recorded decisions or exceptions; scanner results are not treated as complete or authoritative coverage.",
		},
		Limitations: []string{
			"This summary supports technical review and compliance readiness, not legal compliance conclusions, certification, or release security guarantees.",
			"Raw SBOM, scanner, VEX, build, and package payload bytes are intentionally excluded from the summary.",
		},
		SchemaVersion: domain.ReleaseSecuritySummaryVersion, GeneratedAt: f.release.CreatedAt.UTC(),
	}
}

func TestRiskReportFixturesKeepCurrentGrantsCompleteDTOsPrivacyAndDetachedMetadata(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedRiskReportFixtureScope(t, ledger, "Owner")
	foreign := seedRiskReportFixtureScope(t, ledger, "Foreign")
	// Commit directly through repositories, without publishing aggregate maps.
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.Governance.InsertApprovalRecord(ctx, domain.ApprovalRecord{ID: "repository-approval", TenantID: owner.actor.TenantID, SubjectType: "release", SubjectID: owner.release.ID, Decision: "approved", Reason: "private approval reason", ApproverID: owner.actor.KeyID, SchemaVersion: domain.ApprovalRecordSchemaVersion, CreatedAt: owner.release.CreatedAt}); err != nil {
			return err
		}
		return r.Decisions.InsertException(ctx, domain.Exception{ID: "repository-exception", TenantID: owner.actor.TenantID, ReleaseID: owner.release.ID, Owner: "security", Reason: "private exception reason", ExpiresAt: owner.release.CreatedAt.Add(time.Hour), CreatedAt: owner.release.CreatedAt})
	}); err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "reader", Scopes: []string{"report:read", "security:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"report:read", "security:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	clock := &evidenceFlowFixtureClock{at: owner.release.CreatedAt}
	server.bindReleaseSummaryFixtureClock(clock.Now)
	server.bindVulnerabilityPostureFixtureClock(clock.Now)
	reader := server.vulnerabilityPostureQuery.(riskReportFixture)
	summaryReader := server.releaseSecuritySummaryQuery.(releaseSummaryNativeFixture)
	wantSummary := expectedRiskReportFixtureSummary(owner)
	wantSummary.ApprovalSummary = domain.ReleaseSecurityApprovalSummary{Total: 1, Approved: 1}
	wantSummary.ExceptionSummary = domain.ReleaseSecurityExceptionSummary{Total: 1, Unapproved: 1}
	if len(wantSummary.MissingRequiredDecisions) != 3 {
		t.Fatal("summary lacks meaningful missing-decision data")
	}
	wantPosture := domain.VulnerabilityPostureReport{ReportType: "vulnerability_posture", TemplateVersion: "vulnerability-posture.v1.0.0", ReleaseID: owner.release.ID, Summary: map[string]int{"high": 2, "critical": 1}, OpenCritical: 1, Assumptions: []string{"Posture reflects scans uploaded to this tenant only."}, Limitations: []string{"Scanner coverage and vulnerability databases are not independently verified by Evydence."}, GeneratedAt: owner.release.CreatedAt}
	postureCounts, err := reader.Report(t.Context(), human, owner.release.ID)
	if err != nil || postureCounts.OpenCritical != 1 || postureCounts.Summary["high"] != 2 || postureCounts.Summary["critical"] != 1 {
		t.Fatal("fixture lacks expected owned posture counts", err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	summaryPath := "/v1/releases/" + owner.release.ID + "/security-summary"
	posturePath := "/v1/reports/vulnerability-posture?release_id=" + owner.release.ID
	for _, tc := range []struct {
		path string
		want any
	}{{summaryPath, wantSummary}, {posturePath, wantPosture}} {
		out := getRaw(t, server, "fixture-auth", tc.path, 200)
		want, err := json.Marshal(map[string]any{"data": tc.want, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), out.Body.String())
		for _, private := range []string{"private triage", "internal_notes", "private approval reason", "private exception reason", foreign.product.ID, foreign.release.ID} {
			if strings.Contains(out.Body.String(), private) {
				t.Fatal("Risk report exposed private or foreign metadata", private)
			}
		}
	}
	getRaw(t, server, "fixture-auth", "/v1/releases/"+foreign.release.ID+"/security-summary", 404)
	getRaw(t, server, "fixture-auth", "/v1/reports/vulnerability-posture?release_id="+foreign.release.ID, 404)
	getRaw(t, server, "fixture-auth", posturePath+"&release_id="+foreign.release.ID, 400)
	getRaw(t, server, "fixture-auth", "/v1/reports/vulnerability-posture", 403)
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
		auth.actor.ResourceGrants = grants
		getRaw(t, server, "fixture-auth", summaryPath, 403)
		getRaw(t, server, "fixture-auth", posturePath, 403)
	}
	auth.actor = human
	auth.actor.ResourceGrants = append(auth.actor.ResourceGrants, domain.ResourceGrant{ResourceType: "tenant", ResourceID: human.TenantID, Scopes: []string{"security:read"}})
	out := getRaw(t, server, "fixture-auth", "/v1/reports/vulnerability-posture", 200)
	var all struct {
		Data domain.VulnerabilityPostureReport `json:"data"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &all); err != nil || all.Data.ReleaseID != "" || all.Data.OpenCritical != 1 || all.Data.Summary["high"] != 2 || all.Data.Summary["critical"] != 1 {
		t.Fatal("tenant-wide posture included foreign findings or lost filters", err)
	}
	projectedSummary, err := summaryReader.Summary(t.Context(), human, owner.release.ID)
	if err != nil || !reflect.DeepEqual(releaseSecuritySummaryFromQuery(projectedSummary), wantSummary) {
		t.Fatal("summary fixture mapper lost public fields", err)
	}
	for _, values := range []map[string]int{projectedSummary.OpenFindingsBySeverity, projectedSummary.DecisionsByStatus, projectedSummary.Counts} {
		for key := range values {
			values[key] = -1
		}
	}
	projectedSummary.MissingRequiredDecisions[0].Vulnerability = "modified"
	projectedSummary.Assumptions[0], projectedSummary.Limitations[0] = "modified", "modified"
	projectedPosture, err := reader.Report(t.Context(), human, owner.release.ID)
	if err != nil || !reflect.DeepEqual(vulnerabilityPostureFromQuery(projectedPosture), wantPosture) {
		t.Fatal("posture fixture mapper lost public fields", err)
	}
	projectedPosture.Summary["critical"] = -1
	projectedPosture.Assumptions[0], projectedPosture.Limitations[0] = "modified", "modified"
	againSummary, err := summaryReader.Summary(t.Context(), human, owner.release.ID)
	if err != nil || !reflect.DeepEqual(releaseSecuritySummaryFromQuery(againSummary), wantSummary) {
		t.Fatal("summary fixture exposed stored aliases", err)
	}
	againPosture, err := reader.Report(t.Context(), human, owner.release.ID)
	if err != nil || !reflect.DeepEqual(vulnerabilityPostureFromQuery(againPosture), wantPosture) {
		t.Fatal("posture fixture exposed stored aliases", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := summaryReader.Summary(cancelled, human, owner.release.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled summary accepted", err)
	}
	if _, err := reader.Report(cancelled, human, owner.release.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled posture accepted", err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { panic("summary consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = auth
	clock.at = owner.release.CreatedAt.Add(2 * time.Hour)
	calls := clock.calls
	result, err := server.releaseSecuritySummaryQuery.Summary(t.Context(), human, owner.release.ID)
	wantSummary.ExceptionSummary = domain.ReleaseSecurityExceptionSummary{Total: 1, Expired: 1}
	wantSummary.GeneratedAt = clock.at.UTC()
	if err != nil || !reflect.DeepEqual(releaseSecuritySummaryFromQuery(result), wantSummary) || clock.calls != calls+2 {
		t.Fatal("rebind lost live explicit snapshot/evaluation clock or current rows", result, err)
	}
	wantPosture.GeneratedAt = clock.at
	posture, err := server.vulnerabilityPostureQuery.Report(t.Context(), human, owner.release.ID)
	if err != nil || !reflect.DeepEqual(vulnerabilityPostureFromQuery(posture), wantPosture) || clock.calls != calls+3 {
		t.Fatal("posture rebind lost complete DTO or explicit clock", posture, err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("Risk report reads, denials or metadata mutations changed state", err)
	}
}
