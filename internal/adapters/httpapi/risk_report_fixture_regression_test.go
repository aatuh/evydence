package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func seedRiskReportFixtureScope(t *testing.T, ledger *app.Ledger, name string) riskQueryFixtureScope {
	t.Helper()
	f := riskQueryFixtureScope{evidenceFixtureScope: seedEvidenceFixtureScope(t, ledger, name)}
	var err error
	f.release, err = ledger.CreateRelease(t.Context(), f.actor, f.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ledger.UploadVulnerabilityScan(t.Context(), f.actor, []byte(fmt.Sprintf(`{"scanner":"grype","target_ref":"pkg:oci/reports","release_id":%q,"findings":[{"vulnerability":"CVE-2026-0001","component":"reviewed","severity":"high","state":"open"},{"vulnerability":"CVE-2026-0002","component":"unreviewed","severity":"high","state":"open"},{"vulnerability":"CVE-2026-0003","component":"critical","severity":"critical","state":"open"}]}`, f.release.ID)))
	if err != nil || len(scan.Findings) != 3 {
		t.Fatal("seed report scan:", err)
	}
	f.head, err = ledger.CreateVulnerabilityDecision(t.Context(), f.actor, scan.Findings[0].ID, app.CreateVulnerabilityDecisionInput{Status: "affected", Justification: "Reviewed", ImpactStatement: "Under review", ActionStatement: "Patch planned", CustomerVisible: true, InternalNotes: "private triage " + name})
	if err != nil {
		t.Fatal("seed report decision:", err)
	}
	return f
}

func TestRiskReportFixturesKeepCurrentGrantsCompleteDTOsPrivacyAndDetachedMetadata(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedRiskReportFixtureScope(t, ledger, "Owner")
	foreign := seedRiskReportFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "reader", Scopes: []string{"report:read", "security:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"report:read", "security:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	reader := riskReportFixture{catalogFixtureCommands{ledger: ledger}}
	wantSummary, err := ledger.ReleaseSecuritySummary(t.Context(), human, owner.release.ID)
	if err != nil || len(wantSummary.MissingRequiredDecisions) == 0 {
		t.Fatal("summary lacks meaningful missing-decision data", err)
	}
	wantPosture, err := ledger.VulnerabilityPostureReport(t.Context(), human, owner.release.ID)
	if err != nil || wantPosture.OpenCritical != 1 || wantPosture.Summary["high"] != 2 || wantPosture.Summary["critical"] != 1 {
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
		for _, private := range []string{"private triage", "internal_notes", foreign.product.ID, foreign.release.ID} {
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
	projectedSummary, err := reader.Summary(t.Context(), human, owner.release.ID)
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
	againSummary, err := ledger.ReleaseSecuritySummary(t.Context(), human, owner.release.ID)
	if err != nil || !reflect.DeepEqual(againSummary, wantSummary) {
		t.Fatal("summary fixture exposed stored aliases", err)
	}
	againPosture, err := ledger.VulnerabilityPostureReport(t.Context(), human, owner.release.ID)
	if err != nil || !reflect.DeepEqual(againPosture, wantPosture) {
		t.Fatal("posture fixture exposed stored aliases", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.Summary(cancelled, human, owner.release.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled summary accepted", err)
	}
	if _, err := reader.Report(cancelled, human, owner.release.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled posture accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("Risk report reads, denials or metadata mutations changed state", err)
	}
}
